"""Offline integrity and branch-separation tests for the optional FP strategy."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fpm_benchmark.authorization import authorization, canonical_hash, establish_facts
from fpm_benchmark.codeql import summarize_bqrs_json
from fpm_benchmark.fp_policy import (FrozenSourceContext, SourceLocationUnverifiedPolicy,
    STATIC_FIELDS, build_fp_policy, strict_fp_reference)
from fpm_benchmark.revision_runner import triage_record


FP = {"verdict": "FP", "sufficient": True, "missing_evidence": [], "next_query": None,
      "reason_summary": "synthetic model proposal"}


class FakeClient:
    def __init__(self, candidate):
        self.candidate, self.calls = candidate, 0

    def chat_json(self, messages, **kwargs):
        self.calls += 1
        return copy.deepcopy(self.candidate), {"prompt_tokens": 12, "completion_tokens": 4}


class SourcePolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fpm-source-policy-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.file = self.source / "Example.java"
        self.file.write_text('class Example {\nvoid run(String input) { writer.printf("%s", input); }\n}\n')
        self.source_manifest = self.root / "source_hashes.json"
        self.source_manifest.write_text(json.dumps({"files": {
            "Example.java": hashlib.sha256(self.file.read_bytes()).hexdigest()}}))
        self.template_root = self.root / "templates"
        self.template_root.mkdir()
        self.template_file = self.template_root / "probe.ql"
        self.template_file.write_text('select "synthetic observation"\n')
        self.manifest = self.template_root / "templates.json"
        self.manifest.write_text(json.dumps({"templates": [{"id": tid, "file": "probe.ql",
            "parameters": ["file", "line", "column", "cwe"], "language": "java"}
            for tid in ("find-bound-constant-value", "find-crypto-algorithm", "find-sql-parameterization")]}))
        self.record = {"alert_id": "opaque-one", "analysis_provenance": {
            "language": "java", "database_hash": "d" * 64, "sarif_sha256": "e" * 64},
            "alert_contract": {"cwe": "CWE-079", "rule_id": "java/xss", "primary_location": {
                "file": "Example.java", "start_line": 2, "start_column": 1}},
            "annotated_trace": [{"file": "Example.java", "start_line": 2, "start_column": 1}],
            "query_history": [], "backend_facts": [], "evidence_slots": {},
            "ground_truth": {"alert_label": "TP", "alert_expected_vulnerable": True}}
        self.config = {"mode": "source_location_unverified", "source_root": str(self.source),
                       "source_manifest": str(self.source_manifest)}
        self.policy = self.build()

    def build(self, records=None):
        return build_fp_policy(self.config, records or [self.record],
                               template_manifest=self.manifest, method="queryfpm")

    def gate(self, record=None, candidate=None, policy=None, errors=None):
        return (policy or self.policy).evaluate(record or self.record, candidate or FP,
                                              infrastructure_errors=errors or [])

    def query(self, *, rows=None, template="find-bound-constant-value"):
        params = {"file": "Example.java", "line": 2, "column": 1,
                  "cwe": self.record["alert_contract"]["cwe"]}
        if rows is None:
            rows = [["fpm-bound-v1", "constant_branch_value", params["cwe"],
                     "Example.java", 2, 1, "format", "%s", "constant-selector-branch-v1"]]
        result = {"#select": {"columns": [{"kind": "String"}] * 9, "tuples": rows}}
        return {"template_id": template, "parameters": params, "status": "ok", "producer": "codeql-v2",
            "provenance": {"database_hash": "d" * 64, "parameters_hash": canonical_hash(params),
                "template_hash": self.policy.context.template_hashes[template]},
            "result": result, "summary": summarize_bqrs_json(template, result)}

    def test_default_selection_is_unchanged_and_config_is_explicit(self):
        for config in (None, {"mode": "default"}):
            self.assertIsNone(build_fp_policy(config, [], template_manifest=self.manifest, method="queryfpm"))
        for config in ({}, {"mode": "source-location"}, {**self.config, "confidence": "high"}):
            with self.assertRaises(ValueError):
                build_fp_policy(config, [self.record], template_manifest=self.manifest, method="queryfpm")
        with self.assertRaises(ValueError):
            build_fp_policy(self.config, [self.record], template_manifest=self.manifest, method="direct_llm")

    def test_explicit_permission_is_unverified_even_for_wrong_model_fp(self):
        result = self.gate()
        self.assertTrue(result["authorized"])
        self.assertFalse(result["safety_proven"])
        self.assertEqual(result["verification"], "unverified_high_recall")
        self.assertEqual(result["route"], "unverified_model_fp_plus_located_source")
        self.assertEqual(result["fact_ids"], [])
        self.assertFalse(authorization(self.record, "FP")["authorized"])
        self.assertFalse(strict_fp_reference(self.record, "FP")["authorized"])

    def test_labels_confidence_and_model_prose_do_not_change_permission(self):
        expected = self.gate()
        other = copy.deepcopy(self.record)
        other["ground_truth"] = {"alert_label": "FP", "alert_expected_vulnerable": False}
        other["confidence"] = "high"
        self.assertEqual(expected, self.gate(other, FP | {"reason_summary": "different", "confidence": "low"}))
        other.pop("ground_truth")
        self.assertEqual(expected, self.gate(other))

    def test_contract_is_deep_frozen_and_id_is_only_integrity_lookup(self):
        metadata = self.policy.metadata()
        self.record["alert_contract"]["cwe"] = "CWE-089"
        self.assertFalse(self.gate()["authorized"])
        self.assertEqual(metadata, self.policy.metadata())
        self.record["alert_contract"]["cwe"] = "CWE-079"
        self.record["alert_id"] = "unknown-id"
        self.assertFalse(self.gate()["authorized"])

    def test_cross_alert_static_contract_swap_rejected(self):
        other = copy.deepcopy(self.record)
        other["alert_id"] = "opaque-two"
        other["alert_contract"]["primary_location"]["start_column"] = 2
        policy = self.build([self.record, other])
        changed = copy.deepcopy(self.record)
        changed.update({k: copy.deepcopy(other[k]) for k in STATIC_FIELDS})
        self.assertFalse(self.gate(changed, policy=policy)["authorized"])
        changed["alert_id"] = "opaque-two"
        self.assertTrue(self.gate(changed, policy=policy)["authorized"])

    def test_every_static_contract_field_and_trace_order_are_bound(self):
        original = copy.deepcopy(self.record)
        for key, value in (("file", "Other.java"), ("start_line", 3), ("start_column", 2),
                           ("end_line", 2), ("end_column", 20)):
            changed = copy.deepcopy(original)
            changed["alert_contract"]["primary_location"][key] = value
            self.assertFalse(self.gate(changed)["authorized"])
        for field in ("cwe", "rule_id"):
            changed = copy.deepcopy(original)
            changed["alert_contract"][field] = "changed"
            self.assertFalse(self.gate(changed)["authorized"])
        changed = copy.deepcopy(original)
        changed["annotated_trace"][0]["start_column"] = 2
        self.assertFalse(self.gate(changed)["authorized"])
        for field in ("database_hash", "sarif_sha256"):
            changed = copy.deepcopy(original)
            changed["analysis_provenance"][field] = "f" * 64
            self.assertFalse(self.gate(changed)["authorized"])

    def test_invalid_original_ranges_fail_preflight(self):
        for updates in ({"end_line": 0}, {"end_column": 1000}, {"end_column": 0},
                        {"start_column": 4, "end_column": 2}, {"start_column": True},
                        {"file": "../Example.java"}, {"start_line": 1000}):
            changed = copy.deepcopy(self.record)
            changed["alert_contract"]["primary_location"].update(updates)
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                self.build([changed])

    def test_source_change_and_missing_manifest_fail_closed(self):
        self.file.write_text(self.file.read_text() + "changed\n")
        self.assertFalse(self.gate()["authorized"])
        self.source_manifest.unlink()
        self.assertFalse(self.gate()["authorized"])

    def test_empty_and_verified_zero_row_queries_remain_unverified(self):
        self.assertTrue(self.gate()["authorized"])
        self.record["query_history"] = [self.query(rows=[])]
        result = self.gate()
        self.assertTrue(result["authorized"])
        self.assertFalse(result["safety_proven"])
        self.assertEqual(result["query_checks"][0]["row_count"], 0)

    def test_any_bad_query_vetoes_even_after_a_valid_one(self):
        good = self.query()
        variants = []
        for field, value in (("producer", "untrusted"), ("status", "failed"), ("summary", {}),
                             ("truncated", True), ("error_type", "unexpected")):
            bad = copy.deepcopy(good)
            bad[field] = value
            variants.append(bad)
        for field in ("database_hash", "template_hash", "parameters_hash"):
            bad = copy.deepcopy(good)
            bad["provenance"][field] = "wrong"
            variants.append(bad)
        for bad in variants:
            self.record["query_history"] = [copy.deepcopy(good), bad]
            self.assertFalse(self.gate()["authorized"])

    def test_query_request_target_and_typed_row_target_are_checked(self):
        for field, value in (("file", "Other.java"), ("line", 3), ("column", 2), ("cwe", "CWE-089")):
            query = self.query()
            query["parameters"][field] = value
            query["provenance"]["parameters_hash"] = canonical_hash(query["parameters"])
            self.record["query_history"] = [query]
            self.assertFalse(self.gate()["authorized"])
        for index, value in ((2, "CWE-089"), (3, "Other.java"), (4, 3), (5, 2)):
            row = self.query()["result"]["#select"]["tuples"][0]
            row[index] = value
            self.record["query_history"] = [self.query(rows=[row])]
            self.assertFalse(self.gate()["authorized"])

    def test_truncated_consistent_summary_is_still_rejected(self):
        row = self.query()["result"]["#select"]["tuples"][0]
        query = self.query(rows=[row] * 21)
        self.assertTrue(query["summary"]["truncated"])
        self.record["query_history"] = [query]
        self.assertFalse(self.gate()["authorized"])

    def test_template_change_and_malformed_history_fail_closed(self):
        self.record["query_history"] = [self.query()]
        self.template_file.write_text("changed")
        self.assertFalse(self.gate()["authorized"])
        for history in (None, {}, [None], [{"status": "ok", "producer": "codeql-v2", "template_id": []}]):
            self.record["query_history"] = history
            self.assertFalse(self.gate()["authorized"])

    def test_strict_reference_does_not_accept_disabled_constant_certificate(self):
        query = self.query()
        self.record["query_history"] = [query]
        establish_facts(self.record, query)
        self.assertTrue(authorization(self.record, "FP")["authorized"])
        self.assertFalse(strict_fp_reference(self.record, "FP")["authorized"])
        result = self.gate()
        self.assertTrue(result["authorized"])
        self.assertFalse(result["safety_proven"])
        self.assertEqual(result["fact_ids"], [])

    def test_strict_true_cannot_bypass_integrity_or_infrastructure_checks(self):
        strict = {"authorized": True, "route": "synthetic_strict_fact", "fact_ids": ["one"]}
        with patch("fpm_benchmark.fp_policy.strict_fp_reference", return_value=strict) as reference:
            self.assertEqual(self.gate(), strict)
            self.record["query_history"] = [self.query()]
            self.record["query_history"][0]["producer"] = "wrong"
            reference.reset_mock()
            result = self.gate()
            self.assertFalse(result["authorized"])
            self.assertIsNone(result["route"])
            reference.assert_not_called()
            self.assertFalse(self.gate(errors=["synthetic infrastructure failure"])["authorized"])

    def test_verified_weak_crypto_veto(self):
        self.record["alert_contract"]["cwe"] = "CWE-327"
        self.policy = self.build()
        row = ["fpm-bound-v1", "crypto_effective", "CWE-327", "Example.java", 2, 1,
               "algorithm", "DES", "constant-actual-algorithm-v1"]
        query = self.query(rows=[row], template="find-crypto-algorithm")
        self.record["query_history"] = [query]
        establish_facts(self.record, query)
        result = self.gate()
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason"], "known_weak_crypto_veto")

    def test_incomplete_candidate_errors_and_shared_context_never_authorize(self):
        for candidate in (FP | {"sufficient": False}, FP | {"missing_evidence": ["unknown"]}):
            self.assertFalse(self.gate(candidate=candidate)["authorized"])
        for slots in ({"x": "error"}, {"x": "checked_error"}, {"call_context_required": "yes"}):
            self.record["evidence_slots"] = slots
            self.assertFalse(self.gate()["authorized"])

    def test_non_fp_calls_are_exact_original_authorization(self):
        for verdict in ("TP", "UNKNOWN"):
            self.assertEqual(self.gate(candidate=FP | {"verdict": verdict}), authorization(self.record, verdict))
        self.assertFalse(authorization(self.record, "FP")["authorized"])

    def test_runner_explicit_fp_mode_and_default_have_separate_results(self):
        default = triage_record(self.record, client=FakeClient(FP), manifest={"templates": []}, cfg={}, budget=0)
        optional = triage_record(self.record, client=FakeClient(FP), manifest={"templates": []}, cfg={}, budget=0,
                                 fp_policy=self.policy)
        self.assertEqual(default["decision"]["verdict"], "UNKNOWN")
        self.assertEqual(default["operation"], "KEEP")
        self.assertNotIn("fp_policy", default)
        self.assertEqual(optional["decision"]["verdict"], "FP")
        self.assertEqual(optional["operation"], "SUPPRESS")
        self.assertFalse(optional["decision"]["safety_proven"])
        self.assertEqual(optional["fp_policy"], self.policy.metadata())

    def test_runner_tp_unknown_and_strict_authority_stay_unchanged(self):
        for verdict in ("TP", "UNKNOWN"):
            candidate = FP | {"verdict": verdict}
            default = triage_record(self.record, client=FakeClient(candidate), manifest={"templates": []}, cfg={}, budget=0)
            optional = triage_record(self.record, client=FakeClient(candidate), manifest={"templates": []}, cfg={}, budget=0,
                                     fp_policy=self.policy)
            for field in ("authorization", "decision", "operation", "backend_facts"):
                self.assertEqual(default[field], optional[field])

    def test_runner_rejects_unbound_opt_in_before_client_use(self):
        client = FakeClient(FP)
        with self.assertRaises(ValueError):
            triage_record(self.record, client=client, manifest={"templates": []}, cfg={"fp_policy": self.config}, budget=0)
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
