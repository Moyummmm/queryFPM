from __future__ import annotations

import json
import re
import unittest

from fpm_benchmark.evidence import compact_for_llm
from fpm_benchmark.juliet import audit_label_blind_views, prepare_juliet_records


def _record(rule_id: str, file: str, line: int, cwe: str = "CWE-078") -> dict:
    return {
        "alert_id": f"{rule_id}:{file}:{line}",
        "alert_contract": {
            "rule_id": rule_id,
            "cwe": cwe,
            "primary_location": {
                "file": file,
                "uri": file,
                "start_line": line,
                "code": "Runtime.getRuntime().exec(value);",
            },
        },
        "annotated_trace": [],
        "code_context": {"related_source_no_comments": ""},
    }


class JulietAdapterTest(unittest.TestCase):
    def test_labels_alerts_by_exact_enclosing_callable(self) -> None:
        base = "src/testcases/CWE78_OS_Command_Injection/Case.java"
        records = [
            _record("java/command-line-injection", base, 20),
            _record("java/command-line-injection", base, 60),
        ]
        rows = [
            [base, 10, 30, "testcases.Case", "badSink"],
            [base, 50, 70, "testcases.Case", "goodG2BSink"],
        ]

        prepared, summary = prepare_juliet_records(records, rows)

        self.assertEqual(
            [record["ground_truth"]["alert_label"] for record in prepared], ["TP", "FP"]
        )
        self.assertEqual(summary["labels"], {"FP": 1, "TP": 1})
        self.assertEqual(summary["raw_codeql_precision"], 0.5)

    def test_helper_action_uses_bad_or_good_class_variant(self) -> None:
        bad_file = "src/testcases/CWE89_SQL_Injection/Case_81_bad.java"
        good_file = "src/testcases/CWE89_SQL_Injection/Case_81_goodG2B.java"
        records = [
            _record("java/sql-injection", bad_file, 20, "CWE-089"),
            _record("java/sql-injection", good_file, 20, "CWE-089"),
        ]
        rows = [
            [bad_file, 10, 30, "testcases.Case_81_bad", "action"],
            [good_file, 10, 30, "testcases.Case_81_goodG2B", "action"],
        ]

        prepared, _ = prepare_juliet_records(records, rows)

        self.assertEqual(
            [record["ground_truth"]["alert_label"] for record in prepared], ["TP", "FP"]
        )

    def test_predictable_seed_is_mapped_to_research_cwe_330(self) -> None:
        file = "src/testcases/CWE336_Same_Seed_in_PRNG/Case.java"
        records = [_record("java/predictable-seed", file, 20, "CWE-335")]
        rows = [[file, 10, 30, "testcases.Case", "bad"]]

        prepared, _ = prepare_juliet_records(records, rows)

        self.assertEqual(prepared[0]["alert_contract"]["cwe"], "CWE-330")

    def test_label_blind_projection_removes_juliet_name_signals(self) -> None:
        evidence = _record(
            "java/command-line-injection",
            "src/testcases/CWE78_OS_Command_Injection/Case_81_bad.java",
            20,
        )
        evidence["dataset"] = {"label_blind": True}
        evidence["code_context"]["related_source_no_comments"] = (
            "void bad() { helper.goodG2BSink(); }"
        )
        evidence["query_history"] = [
            {
                "template_id": "find-static-field-call-context",
                "status": "ok",
                "summary": {
                    "tuple_count": 1,
                    "facts": [
                        {
                            "message": (
                                "caller=testcases.Example.bad, "
                                "sink_callable=testcases.Example.goodG2BSink"
                            )
                        }
                    ],
                },
            }
        ]
        evidence["supplemental_evidence"] = list(evidence["query_history"])
        evidence["ground_truth"] = {"alert_label": "TP"}

        prompt_view = json.dumps(compact_for_llm(evidence, view="query-centered"))

        self.assertIsNone(re.search(r"(?i)\b(?:bad|goodG2B(?:Sink)?)\b", prompt_view))
        self.assertIn("caseSymbol_", prompt_view)
        self.assertNotIn("ground_truth", prompt_view)

        audit = audit_label_blind_views([evidence])
        self.assertEqual(
            audit["leak_counts"],
            {"ground_truth": 0, "juliet_label": 0, "comment_marker": 0},
        )


if __name__ == "__main__":
    unittest.main()
