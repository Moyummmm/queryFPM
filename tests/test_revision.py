import copy
import unittest
from fpm_benchmark.authorization import (authorization, establish_facts, canonical_hash,
                                         resolve_property_algorithm, classify_algorithm)
from fpm_benchmark.revision_prompts import messages, normalize
from fpm_benchmark.revision_runner import triage_record, replay_action, select_action

def evidence(cwe="CWE-089"):
    return {"alert_id": "case-1", "alert_contract": {"cwe": cwe,
        "primary_location": {"file": "Case.java", "start_line": 10, "start_column": 5}},
        "evidence_slots": {"source_user_controlled": "yes", "sink_dangerous": "yes",
                           "path_exists": "yes", "sink_identified": "yes"},
        "ground_truth": {"alert_expected_vulnerable": True}, "query_history": []}

def result(cwe="CWE-089", kind="sql_parameterized", value="SELECT * FROM t WHERE x=?"):
    template = "find-sql-parameterization" if kind == "sql_parameterized" else "find-crypto-algorithm"
    rule = "constant-sql-same-receiver-v1" if kind == "sql_parameterized" else "constant-actual-algorithm-v1"
    params = {"file": "Case.java", "line": 10, "column": 5}
    return {"template_id": template, "parameters": params, "status": "ok", "producer": "codeql-v2",
            "provenance": {"database_hash": "db-hash", "template_hash": "template-hash",
                           "parameters_hash": canonical_hash(params)},
            "result": {"#select": {"tuples": [["fpm-bound-v1", kind, cwe, "Case.java", 10, 5,
                                                 "statement", value, rule]]}},
            "summary": {"tuple_count": 1}}

def attach(e, r):
    e["query_history"].append(r)
    establish_facts(e, r)

class FakeClient:
    def __init__(self, raw): self.raw = raw; self.prompts = []
    def chat_json(self, prompt, **kw):
        self.prompts.append(prompt)
        return copy.deepcopy(self.raw), {"prompt_tokens": 20, "completion_tokens": 5}

def candidate(verdict="FP"):
    return {"verdict": verdict, "sufficient": True, "missing_evidence": [],
            "next_query": {"template_id": None, "parameters": {}}, "reason_summary": "test"}

class RevisionTests(unittest.TestCase):
    def test_success_or_zero_rows_never_authorize(self):
        for count in (0, 1, 10):
            e = evidence(); e["query_history"] = [{"status": "ok", "template_id": "find-sql-parameterization",
                                                     "summary": {"tuple_count": count}}]
            for confidence in ("high", "medium", "low"):
                e["confidence"] = confidence
                self.assertFalse(authorization(e, "FP")["authorized"])

    def test_model_slots_and_trace_do_not_authorize(self):
        e = evidence(); e["evidence_slots"].update({"safe_api_usage": "yes", "sanitizer_present": "yes",
                                                    "constant_overwrite": "yes", "validator_present": "yes"})
        self.assertFalse(authorization(e, "FP")["authorized"])
        self.assertFalse(authorization(e, "TP")["authorized"])

    def test_bound_safety_authorizes_and_has_one_route(self):
        e = evidence(); attach(e, result())
        self.assertTrue(authorization(e, "FP")["authorized"])
        self.assertEqual(authorization(e, "FP")["route"], "sql_parameterized")

    def test_unrelated_receiver_option_column_or_cwe_rejected(self):
        for index, replacement in [(1, "nearby_constant_option"), (2, "CWE-079"),
                                   (3, "Other.java"), (4, 11), (5, 9), (8, "nearby-setString")]:
            r = result(); r["result"]["#select"]["tuples"][0][index] = replacement
            e = evidence(); attach(e, r)
            self.assertFalse(authorization(e, "FP")["authorized"])

    def test_query_provenance_and_history_required(self):
        for key in ("database_hash", "template_hash", "parameters_hash"):
            e = evidence(); r = result(); r["provenance"][key] = ""; attach(e, r)
            self.assertFalse(authorization(e, "FP")["authorized"])
        e = evidence(); establish_facts(e, result())
        self.assertFalse(authorization(e, "FP")["authorized"])

    def test_certificate_from_wrong_database_snapshot_is_rejected(self):
        e=evidence();e['analysis_provenance']={'database_hash':'different-project-database'}
        attach(e,result())
        self.assertFalse(authorization(e,'FP')['authorized'])

    def test_checked_none_failures_and_unknown_cwe_keep(self):
        for state in ("checked_none", "error", "unknown"):
            e = evidence(); e["evidence_slots"]["safe_api_usage"] = state
            self.assertFalse(authorization(e, "FP")["authorized"])
        self.assertFalse(authorization(evidence("CWE-999"), "TP")["authorized"])

    def test_crypto_effective_only_and_configuration_precedence(self):
        self.assertEqual(resolve_property_algorithm(key="cipher", configured={"cipher":"DES"},
                         default="DESede", resource_verified=True), "DES")
        self.assertIsNone(resolve_property_algorithm(key="cipher", configured=None,
                         default="DESede", resource_verified=False))
        self.assertIsNone(classify_algorithm('property_default=DESede; effective=AES/GCM/NoPadding'))
        self.assertIsNone(classify_algorithm("AES/ECB/PKCS5Padding"))
        e = evidence("CWE-327"); attach(e, result("CWE-327", "crypto_effective", "AES/GCM/NoPadding"))
        e["annotated_trace"] = [{"code": 'getProperty("cipher", "DESede")'}]
        self.assertTrue(authorization(e, "FP")["authorized"])
        attach(e, result("CWE-327", "crypto_effective", "DES"))
        self.assertFalse(authorization(e, "FP")["authorized"])

    def test_full_prompt_match_and_no_confidence_or_labels(self):
        e = evidence(); e["decision"] = {"confidence": "high"}
        a = messages(e, [], method="queryfpm"); b = messages(e, [], method="matched_one_shot")
        self.assertEqual(a, b)
        self.assertNotIn("ground_truth", a[1]["content"])
        self.assertNotIn('"confidence"', a[1]["content"])

    def test_common_budget_keeps_valid_json_and_matches_one_shot(self):
        import json
        e=evidence();e['code_context']={'related_source_no_comments':'x'*100000}
        a=messages(e,[],method='queryfpm',max_chars=8000)
        b=messages(e,[],method='matched_one_shot',max_chars=8000)
        self.assertEqual(a,b)
        self.assertLessEqual(sum(len(m['content']) for m in a),8000)
        json.loads(a[1]['content'])

    def test_missing_column_does_not_run_falsely_successful_check(self):
        e=evidence();e['alert_contract']['primary_location']['start_column']=None
        actions=[{'template_id':'find-sql-parameterization','parameters':['file','line','column']}]
        self.assertIsNone(select_action(e,{},actions))

    def test_malformed_bool_and_model_fact_forgery(self):
        self.assertEqual(normalize({**candidate(), "sufficient": "false"})["verdict"], "UNKNOWN")
        raw = {**candidate(), "backend_facts": [{"kind":"sql_parameterized"}], "confidence":"high"}
        out = triage_record(evidence(), client=FakeClient(raw), manifest={"templates": []}, cfg={}, budget=0)
        self.assertEqual(out["operation"], "KEEP")
        self.assertNotIn("confidence", out["candidate_decision"])

    def test_tp_structure_does_not_early_stop(self):
        manifest = {"templates":[{"id":"find-sql-parameterization","parameters":["file","line","column"],
                                  "cwe_categories":["CWE-089"], "language":"java"}]}
        def executor(e, request):
            r=result(); r.update(request); r["provenance"]["parameters_hash"] = canonical_hash(request["parameters"])
            return r
        client=FakeClient(candidate("TP"))
        out=triage_record(evidence(), client=client, manifest=manifest, cfg={}, budget=1, query_executor=executor)
        self.assertEqual(len(client.prompts),2)
        self.assertEqual(out["decision"]["verdict"],"UNKNOWN")

    def test_replay_no_database_does_not_fabricate_absence(self):
        e=evidence(); req={"template_id":"find-sql-parameterization", "parameters":result()["parameters"]}
        self.assertEqual(replay_action(e,req,[])["status"],"unavailable")
        r=result(); r["alert_id"]=e["alert_id"]
        self.assertEqual(replay_action(e,req,[r])["producer"],"verified-replay-v2")
        req["parameters"]["line"] = 11
        self.assertEqual(replay_action(e,req,[r])["status"],"unavailable")

    def test_python_never_selects_java_template(self):
        e=evidence(); e["alert_contract"]["primary_location"]["file"]="case.py"
        client=FakeClient(candidate())
        out=triage_record(e,client=client,manifest={"templates":[{"id":"find-sql-parameterization",
             "language":"java","parameters":["file","line"]}]},cfg={"language":"python"},budget=2)
        self.assertEqual(out["query_history"],[])

    def test_nullable_no_action_is_valid_and_controller_still_selects_python_action(self):
        raw = {**candidate('TP'), 'next_query': None}
        self.assertIsNone(normalize(raw)['next_query']['template_id'])
        e = evidence('CWE-078')
        actions = [{'template_id': 'find-python-bound-literal', 'parameters': ['file','line','column','cwe']}]
        selected = select_action(e, normalize(raw), actions)
        self.assertEqual(selected['template_id'], 'find-python-bound-literal')
        self.assertFalse(authorization(e, 'FP')['authorized'])

if __name__ == "__main__": unittest.main()
