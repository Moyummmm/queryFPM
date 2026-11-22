"""Optional TP v2.1 behavior with synthetic source and in-memory clients only."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fpm_benchmark.authorization import authorization, canonical_hash, establish_facts
from fpm_benchmark.codeql import summarize_bqrs_json
from fpm_benchmark.fp_policy import build_fp_policy
from fpm_benchmark.llm import LLMInfrastructureError
from fpm_benchmark.revision_runner import triage_record
from fpm_benchmark.tp_policy import build_tp_policy
from fpm_benchmark.java_source_lexer import mask_java_comments


def proposal(verdict="TP", **changes):
    return {"verdict": verdict, "sufficient": True, "missing_evidence": [],
            "next_query": None, "reason_summary": "synthetic candidate", **changes}


class Client:
    def __init__(self, candidates):
        self.candidates, self.calls = candidates, 0

    def chat_json(self, messages, **kwargs):
        value = self.candidates[min(self.calls, len(self.candidates) - 1)]
        self.calls += 1
        if value == "error":
            raise LLMInfrastructureError("synthetic", error_type="network", attempts=1, retryable=True)
        return copy.deepcopy(value), {}


class SemanticTPTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fpm-tp-policy-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.source_file = self.source / "T.java"
        self.source_manifest = self.root / "source_hashes.json"
        self.template_file = self.root / "probe.ql"
        self.template_file.write_text('select "synthetic observation"\n')
        self.manifest_file = self.root / "templates.json"
        self.lines = ['class T {', '  String value = request.getParameter("x");',
                      '  writer.println(value);', '}']
        self.record = self.make_record("CWE-079", "java/xss", 3)
        self.record["annotated_trace"] = [
            {"file": "T.java", "start_line": line, "start_column": 3,
             "code": self.lines[line - 1].strip(), "step": index,
             "role": role, "provenance": "sarif.codeFlows"}
            for index, line, role in [(1, 2, "SOURCE_CANDIDATE"), (2, 3, "SINK_CANDIDATE")]]
        self.write_fixture(["find-bound-fixed-sink", "find-bound-constant-value"])
        self.policy = self.build()

    def make_record(self, cwe, rule, line):
        return {"alert_id": "opaque-test", "analysis_provenance": {"language": "java",
            "database_hash": "d" * 64, "sarif_sha256": "e" * 64},
            "alert_contract": {"tool": "CodeQL", "cwe": cwe, "rule_id": rule,
                "sarif_indices": {"run": 0, "result": 0}, "primary_location": {
                    "file": "T.java", "start_line": line, "start_column": 3,
                    "end_line": line, "end_column": len(self.lines[line - 1]) + 1,
                    "code": self.lines[line - 1].strip()}}, "annotated_trace": [],
            "code_context": {"primary_snippet": self.lines[line - 1].strip()},
            "evidence_slots": {}, "ground_truth": {"alert_expected_vulnerable": True},
            "query_history": [], "backend_facts": []}

    def write_fixture(self, templates):
        self.source_file.write_text("\n".join(self.lines) + "\n")
        self.source_manifest.write_text(json.dumps({"files": {
            "T.java": hashlib.sha256(self.source_file.read_bytes()).hexdigest()}}))
        self.manifest = {"templates": [{"id": tid, "file": "probe.ql", "language": "java",
            "parameters": ["file", "line", "column", "cwe"],
            "cwe_categories": [self.record["alert_contract"]["cwe"]]} for tid in templates]}
        self.manifest_file.write_text(json.dumps(self.manifest))

    def config(self, minimum=2, variant="flow_or_api"):
        return {"mode": "semantic_tp_v2_1", "source_root": str(self.source),
            "source_manifest": str(self.source_manifest), "variant": variant,
            "minimum_successful_queries_before_tp": minimum}

    def build(self, minimum=2, variant="flow_or_api"):
        return build_tp_policy(self.config(minimum, variant), [self.record],
                               template_manifest=self.manifest_file, method="queryfpm")

    def evidence(self):
        return copy.deepcopy(self.record)

    def gate(self, evidence=None, candidate=None, *, budget=2, policy=None, exhausted=False, errors=None):
        return (policy or self.policy).evaluate(evidence or self.evidence(), candidate or proposal(),
            infrastructure_errors=errors or [], query_budget=budget,
            confirmed_action_exhaustion=exhausted)

    def executor(self, status="ok", certificate=None):
        calls = []
        def execute(evidence, request):
            calls.append(request)
            if status != "ok":
                return {**request, "status": status}
            p = request["parameters"]
            rows = []
            if certificate:
                kind, detail, rule = certificate
                rows = [["fpm-bound-v1", kind, p["cwe"], p["file"], p["line"], p["column"],
                         "subject", detail, rule]]
            result = {"#select": {"columns": [{"kind": "String"}] * 9, "tuples": rows}}
            return {**request, "status": "ok", "producer": "codeql-v2",
                "provenance": {"database_hash": "d" * 64, "parameters_hash": canonical_hash(p),
                    "template_hash": self.policy.context.template_hashes[request["template_id"]]},
                "result": result, "summary": summarize_bqrs_json(request["template_id"], result)}
        return execute, calls

    def run_case(self, *, budget=2, status="ok", certificate=None, client=None, fp_policy=None):
        executor, calls = self.executor(status, certificate)
        client = client or Client([proposal()])
        result = triage_record(self.record, client=client, manifest=self.manifest, cfg={"language": "java"},
            budget=budget, query_executor=executor, tp_policy=self.policy, fp_policy=fp_policy)
        return result, client, calls

    def crypto(self, expression):
        self.lines = ['class T {', f'  Cipher.getInstance({expression});', '}']
        self.record = self.make_record("CWE-327", "java/weak-cryptographic-algorithm", 2)
        self.write_fixture(["find-crypto-algorithm"])
        self.policy = self.build()

    def test_default_and_invalid_configuration(self):
        self.assertIsNone(build_tp_policy(None, [], template_manifest=self.manifest_file, method="queryfpm"))
        for config in ({}, self.config(minimum=True), self.config(minimum=3), self.config(variant="other")):
            with self.assertRaises(ValueError):
                build_tp_policy(config, [self.record], template_manifest=self.manifest_file, method="queryfpm")
        with self.assertRaises(ValueError):
            build_tp_policy(self.config(), [self.record], template_manifest=self.manifest_file, method="direct_llm")

    def test_zero_budget_preserves_budget_exhaustion_semantics(self):
        result, client, calls = self.run_case(budget=0)
        self.assertEqual((client.calls, len(calls)), (1, 0))
        self.assertEqual(result["decision"]["verdict"], "TP")
        self.assertEqual(result["decision"]["verification"], "model_classified_unverified")
        self.assertEqual(result["operation"], "KEEP")
        self.assertEqual(result["authorization"]["minimum_successful_queries_before_tp"], 2)
        self.assertEqual(result["authorization"]["query_budget"], 0)

    def test_threshold_budget_matrix(self):
        for minimum in (0, 1, 2):
            policy = self.build(minimum)
            for budget in (0, 1, 2, 3):
                for completed in range(budget + 1):
                    evidence = self.evidence()
                    evidence["query_history"] = [{"status": "ok"}] * completed
                    result = self.gate(evidence, budget=budget, policy=policy)
                    expected = completed >= minimum or completed >= budget
                    self.assertEqual(result["authorized"], expected, (minimum, budget, completed))

    def test_two_query_threshold_observes_three_judgments(self):
        result, client, calls = self.run_case()
        self.assertEqual((client.calls, len(calls)), (3, 2))
        self.assertEqual(result["decision"]["verdict"], "TP")
        self.assertEqual(result["llm_trace"][0]["gate"]["reason"], "tp_wait_for_evidence")
        self.assertEqual(result["authorization"]["successful_queries"], 2)

    def test_one_query_threshold_is_respected(self):
        self.policy = self.build(minimum=1)
        result, client, calls = self.run_case()
        self.assertEqual((client.calls, len(calls)), (2, 1))
        self.assertEqual(result["decision"]["verdict"], "TP")

    def test_controller_confirmed_exhaustion_after_one_success(self):
        self.crypto('"DES"')
        result, client, calls = self.run_case()
        self.assertEqual((client.calls, len(calls)), (2, 1))
        self.assertEqual(result["stop_reason"], "tp_evidence_actions_exhausted")
        self.assertTrue(result["llm_trace"][-1]["tp_actions_exhausted"])
        self.assertEqual(result["llm_trace"][-1]["gate_before_action_exhaustion"]["reason"], "tp_wait_for_evidence")
        self.assertTrue(result["authorization"]["evidence_actions_exhausted"])
        self.assertEqual(result["decision"]["verdict"], "TP")

    def test_no_executable_action_without_success_does_not_bypass_threshold(self):
        self.write_fixture([])
        self.policy = self.build()
        result, client, calls = self.run_case()
        self.assertEqual((client.calls, len(calls)), (1, 0))
        self.assertEqual(result["decision"]["verdict"], "UNKNOWN")
        self.assertEqual(result["authorization"]["reason"], "tp_wait_for_evidence")

    def test_model_cannot_set_controller_exhaustion(self):
        evidence = self.evidence()
        evidence["query_history"] = [{"status": "ok"}]
        result = self.gate(evidence, proposal(confirmed_action_exhaustion=True))
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason"], "tp_wait_for_evidence")

    def test_failures_and_unavailable_queries_never_authorize_tp(self):
        for status, verdict in (("failed", "INFRA_ERROR"), ("unavailable", "UNKNOWN")):
            result, _, _ = self.run_case(status=status)
            self.assertEqual(result["decision"]["verdict"], verdict)
            self.assertEqual(result["operation"], "KEEP")
            self.assertNotIn("tp_actions_exhausted", result["llm_trace"][-1])
        result, _, _ = self.run_case(client=Client(["error"]))
        self.assertEqual(result["decision"]["verdict"], "INFRA_ERROR")

    def test_incomplete_candidate_and_infrastructure_are_not_tp(self):
        for candidate in (proposal(sufficient=False), proposal(missing_evidence=["unresolved"])):
            self.assertFalse(self.gate(candidate=candidate, budget=0)["authorized"])
        self.assertFalse(self.gate(budget=0, errors=["network"])["authorized"])

    def test_strict_fp_certificate_conflicts_without_automatic_suppression(self):
        certificate = ("compile_time_sink_argument", "fixed", "compile-time-actual-argument-v1")
        result, _, _ = self.run_case(certificate=certificate)
        self.assertEqual(result["decision"]["verdict"], "UNKNOWN")
        self.assertEqual(result["authorization"]["reason"], "tp_conflicts_with_bound_safety_certificate")
        self.assertEqual(result["operation"], "KEEP")

    def test_source_fp_permission_is_never_a_tp_safety_conflict(self):
        fp_config = {"mode": "source_location_unverified", "source_root": str(self.source),
                     "source_manifest": str(self.source_manifest)}
        fp = build_fp_policy(fp_config, [self.record], template_manifest=self.manifest_file, method="queryfpm")
        self.assertTrue(fp.evaluate(self.evidence(), proposal("FP"), infrastructure_errors=[])["authorized"])
        with patch.object(fp, "evaluate", side_effect=AssertionError("TP must not use the FP permission strategy")):
            result, _, _ = self.run_case(budget=0, fp_policy=fp)
        self.assertEqual(result["decision"]["verdict"], "TP")
        self.assertFalse(result["authorization"]["original_fp_gate"]["authorized"])

    def test_snapshot_mismatch_rejected_before_any_judgment(self):
        self.record["code_context"]["primary_snippet"] = "changed"
        client = Client([proposal()])
        with self.assertRaisesRegex(ValueError, "frozen static snapshot"):
            self.run_case(client=client)
        self.assertEqual(client.calls, 0)

    def test_source_change_after_cached_view_is_rejected(self):
        self.assertTrue(self.gate(budget=0)["authorized"])
        self.source_file.write_text(self.source_file.read_text() + "changed\n")
        self.assertFalse(self.gate(budget=0)["authorized"])

    def test_label_changes_do_not_change_tp_gate(self):
        first = self.gate(budget=0)
        evidence = self.evidence()
        evidence["ground_truth"] = {"alert_expected_vulnerable": False}
        self.assertEqual(first, self.gate(evidence, budget=0))

    def test_non_tp_authority_is_unchanged_when_only_tp_mode_selected(self):
        for verdict in ("FP", "UNKNOWN"):
            self.assertEqual(self.gate(candidate=proposal(verdict)), authorization(self.record, verdict))
            result, _, _ = self.run_case(budget=0, client=Client([proposal(verdict)]))
            self.assertEqual(result["operation"], "KEEP")
            self.assertEqual(result["authorization"], authorization(self.record, verdict))

    def test_dynamic_crypto_configuration_remains_unknown(self):
        self.crypto('props.getProperty("algorithm", "DES")')
        result, client, calls = self.run_case()
        self.assertEqual((client.calls, len(calls)), (2, 1))
        self.assertEqual(result["decision"]["verdict"], "UNKNOWN")
        self.assertEqual(result["authorization"]["reason"], "crypto_effective_algorithm_unbound")

    def test_crypto_strong_unknown_expression_and_ambiguous_region_refused(self):
        for expression in ('"AES/GCM/NoPadding"', '"AES/ECB/PKCS5Padding"', '"DES" + suffix', '"D\\105S"'):
            self.crypto(expression)
            self.assertFalse(self.gate(budget=0)["authorized"])
        self.crypto('"DES"')
        self.record["alert_contract"]["primary_location"]["end_column"] = 5
        self.policy = self.build()
        self.assertFalse(self.gate(budget=0)["authorized"])

    def test_bound_weak_fact_is_distinct_and_bypasses_semantic_wait(self):
        self.crypto("algorithm")
        executor, _ = self.executor(certificate=("crypto_effective", "DES", "constant-actual-algorithm-v1"))
        evidence = self.evidence()
        request = {"template_id": "find-crypto-algorithm", "parameters": {
            "file": "T.java", "line": 2, "column": 3, "cwe": "CWE-327"}}
        query = executor(evidence, request)
        evidence["query_history"] = [query]
        establish_facts(evidence, query)
        gate = self.gate(evidence)
        self.assertTrue(gate["authorized"])
        self.assertEqual(gate["verification"], "bound_weak_algorithm_fact_not_vulnerability_proof")
        self.assertEqual(gate["route"], "weak_crypto")

    def test_java_lexer_preserves_literals_and_offsets(self):
        text = 'String url = "http://example"; /* ordinary comment */\nint n = 1; // note\n'
        masked = mask_java_comments(text)
        self.assertEqual(len(masked), len(text))
        self.assertEqual(masked.count("\n"), text.count("\n"))
        self.assertIn('"http://example"', masked)
        self.assertNotIn("ordinary comment", masked)
        self.assertNotIn("note", masked)


if __name__ == "__main__":
    unittest.main()
