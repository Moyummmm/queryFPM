from __future__ import annotations

import unittest

from fpm_benchmark.evidence import (
    build_evidence_slots,
    compact_for_llm,
    detect_cross_context_field_ambiguity,
    enrich_core_evidence_slots,
    strip_java_comments,
)


class EvidenceTest(unittest.TestCase):
    def test_detects_cross_file_static_field_trace(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-089"},
            "annotated_trace": [
                {"file": "Source.java", "step": 1, "code": "request.getParameter(\"x\")"},
                {"file": "Source.java", "step": 2, "code": "public static String data;"},
                {"file": "Sink.java", "step": 3, "code": "executeQuery(data)"},
            ],
        }

        ambiguity = detect_cross_context_field_ambiguity(evidence)

        self.assertIsNotNone(ambiguity)
        self.assertEqual(ambiguity["field_name"], "data")
        self.assertEqual(ambiguity["trace_file_count"], 2)

    def test_does_not_trigger_on_static_method_or_single_file_field(self) -> None:
        static_method = {
            "alert_contract": {"cwe": "CWE-089"},
            "annotated_trace": [
                {"file": "A.java", "code": "public static String load() {"},
                {"file": "B.java", "code": "executeQuery(data)"},
            ],
        }
        single_file_field = {
            "alert_contract": {"cwe": "CWE-089"},
            "annotated_trace": [
                {"file": "A.java", "code": "private static String data;"},
                {"file": "A.java", "code": "executeQuery(data)"},
            ],
        }
        immutable_cross_file_field = {
            "alert_contract": {"cwe": "CWE-089"},
            "annotated_trace": [
                {"file": "A.java", "code": "private static final String data = \"safe\";"},
                {"file": "B.java", "code": "executeQuery(data)"},
            ],
        }

        self.assertIsNone(detect_cross_context_field_ambiguity(static_method))
        self.assertIsNone(detect_cross_context_field_ambiguity(single_file_field))
        self.assertIsNone(detect_cross_context_field_ambiguity(immutable_cross_file_field))

    def test_enrichment_marks_call_context_as_required(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-022"},
            "annotated_trace": [
                {"file": "A.java", "step": 1, "role": "SOURCE_CANDIDATE", "code": "source()"},
                {"file": "A.java", "step": 2, "role": "PROPAGATION", "code": "static String path;"},
                {"file": "B.java", "step": 3, "role": "SINK_CANDIDATE", "code": "new File(path)"},
            ],
            "evidence_slots": {},
        }

        enrich_core_evidence_slots(evidence)

        self.assertEqual(evidence["evidence_slots"]["call_context_required"], "yes")
        self.assertEqual(evidence["evidence_slots"]["call_context_resolved"], "unknown")
        self.assertIn("MISSING_CALL_CONTEXT_ALIGNMENT", evidence["missing_evidence"])

    def test_source_sink_trace_backfills_user_control_and_path(self) -> None:
        trace = [
            {"role": "SOURCE_CANDIDATE", "semantic_tag": "user_input_candidate"},
            {"role": "SINK_CANDIDATE", "semantic_tag": "response_sink_candidate"},
        ]

        slots = build_evidence_slots("CWE-079", trace)

        self.assertEqual(slots["source_user_controlled"], "yes")
        self.assertEqual(slots["sink_dangerous"], "yes")
        self.assertEqual(slots["path_exists"], "yes")

    def test_enrichment_updates_legacy_slots_and_missing_evidence(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-022"},
            "annotated_trace": [
                {"role": "SOURCE_CANDIDATE"},
                {"role": "SINK_CANDIDATE"},
            ],
            "evidence_slots": {"source_user_controlled": "unknown"},
            "missing_evidence": ["MISSING_SOURCE_TRUST_LEVEL"],
        }

        enrich_core_evidence_slots(evidence)

        self.assertEqual(evidence["evidence_slots"]["source_user_controlled"], "yes")
        self.assertNotIn("MISSING_SOURCE_TRUST_LEVEL", evidence["missing_evidence"])

    def test_strip_java_comments_preserves_literals_and_lines(self) -> None:
        source = (
            'String url = "https://example.test/a/*b*/"; // label-like comment\n'
            "char slash = '/'; /* block\ncomment */\n"
        )

        cleaned = strip_java_comments(source)

        self.assertIn('"https://example.test/a/*b*/"', cleaned)
        self.assertIn("char slash = '/';", cleaned)
        self.assertNotIn("label-like", cleaned)
        self.assertNotIn("block", cleaned)
        self.assertEqual(cleaned.count("\n"), source.count("\n"))

    def test_source_chain_view_excludes_ground_truth_and_query_results(self) -> None:
        evidence = {
            "alert_id": "a1",
            "alert_contract": {
                "cwe": "CWE-079",
                "primary_location": {"code": "sink(value); // safe"},
            },
            "annotated_trace": [{"code": "source(); /* safe */"}],
            "cwe_profile": {},
            "evidence_slots": {},
            "missing_evidence": [],
            "code_context": {
                "primary_snippet": "sink(value);",
                "related_source_no_comments": "class Example {}",
            },
            "query_history": [{"template_id": "must-not-leak"}],
            "supplemental_evidence": [{"summary": "must-not-leak"}],
            "ground_truth": {"expected_vulnerable": False},
        }

        compact = compact_for_llm(evidence, view="source-chain")

        self.assertNotIn("ground_truth", compact)
        self.assertNotIn("query_history", compact)
        self.assertNotIn("supplemental_evidence", compact)
        self.assertNotIn("evidence_slots", compact)
        self.assertNotIn("missing_evidence", compact)
        self.assertNotIn("safe", compact["alert_contract"]["primary_location"]["code"])
        self.assertNotIn("safe", compact["annotated_trace"][0]["code"])
        self.assertEqual(
            compact["code_context"]["related_source_no_comments"],
            "class Example {}",
        )

    def test_query_centered_view_includes_only_compact_query_evidence(self) -> None:
        evidence = {
            "alert_id": "a1",
            "alert_contract": {"cwe": "CWE-079", "primary_location": {}},
            "annotated_trace": [],
            "cwe_profile": {},
            "code_context": {"related_source_no_comments": "class Example {}"},
            "query_history": [{"template_id": "find-x", "status": "ok"}],
            "supplemental_evidence": [
                {"template_id": "find-x", "status": "ok", "summary": {"tuple_count": 1}}
            ],
            "ground_truth": {"expected_vulnerable": False},
        }

        compact = compact_for_llm(evidence, view="query-centered")

        self.assertNotIn("ground_truth", compact)
        self.assertEqual(compact["query_history"][0]["template_id"], "find-x")
        self.assertEqual(compact["supplemental_evidence"][0]["summary"]["tuple_count"], 1)


if __name__ == "__main__":
    unittest.main()
