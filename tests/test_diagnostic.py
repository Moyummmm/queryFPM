from __future__ import annotations

import unittest

from fpm_benchmark.diagnostic import (
    compare_diagnostic_decisions,
    select_diagnostic_cohort,
)


def record(
    alert_id: str,
    *,
    cwe: str,
    truth: bool,
    verdict: str,
    query_count: int = 0,
) -> dict:
    return {
        "alert_id": alert_id,
        "alert_contract": {
            "cwe": cwe,
            "primary_location": {"file": f"{alert_id}.java", "start_line": 10},
        },
        "ground_truth": {"alert_expected_vulnerable": truth},
        "decision": {"verdict": verdict, "sufficient": True},
        "query_history": [{"template_id": "old"}] * query_count,
        "supplemental_evidence": [{"status": "old"}] * query_count,
        "llm_trace": [{"old": True}],
    }


class DiagnosticCohortTests(unittest.TestCase):
    def test_selects_exact_control_then_records_same_cwe_fallback(self) -> None:
        records = [
            record("error-fp-1", cwe="CWE-327", truth=False, verdict="TP", query_count=1),
            record("error-fp-2", cwe="CWE-327", truth=False, verdict="TP"),
            record("control-fp", cwe="CWE-327", truth=False, verdict="FP"),
            record("control-tp", cwe="CWE-327", truth=True, verdict="TP"),
        ]

        cohort, report = select_diagnostic_cohort(records)

        self.assertEqual(len(cohort), 4)
        self.assertEqual(report["match_quality"]["exact_cwe_and_truth"], 1)
        self.assertEqual(report["match_quality"]["fallback_same_cwe"], 1)
        self.assertEqual({r["diagnostic"]["cohort_role"] for r in cohort}, {"error", "control"})
        for selected in cohort:
            self.assertNotIn("decision", selected)
            self.assertNotIn("llm_trace", selected)
            self.assertEqual(selected["query_history"], [])
            self.assertEqual(selected["supplemental_evidence"], [])
            self.assertIn("baseline_decision", selected["diagnostic"])

    def test_compare_counts_error_corrections_and_control_regressions(self) -> None:
        source = [
            record("error", cwe="CWE-089", truth=False, verdict="TP"),
            record("control", cwe="CWE-089", truth=False, verdict="FP"),
        ]
        cohort, _ = select_diagnostic_cohort(source)
        for selected in cohort:
            if selected["diagnostic"]["cohort_role"] == "error":
                selected["decision"] = {"verdict": "FP", "sufficient": True}
            else:
                selected["decision"] = {"verdict": "TP", "sufficient": True}

        report = compare_diagnostic_decisions(cohort)

        self.assertEqual(report["errors"]["corrected"], 1)
        self.assertEqual(report["controls"]["regressed"], 1)
        self.assertEqual(report["net_corrected"], 0)
        self.assertEqual(report["transitions"], {"FP->TP": 1, "TP->FP": 1})

    def test_compare_can_use_a_matched_no_evidence_arm(self) -> None:
        source = [
            record("error", cwe="CWE-089", truth=False, verdict="TP"),
            record("control", cwe="CWE-089", truth=False, verdict="FP"),
        ]
        forced, _ = select_diagnostic_cohort(source)
        no_evidence = []
        for selected in forced:
            control = dict(selected)
            control["decision"] = {"verdict": "TP", "sufficient": True}
            no_evidence.append(control)
            selected["decision"] = {"verdict": "FP", "sufficient": True}

        report = compare_diagnostic_decisions(forced, no_evidence)

        self.assertEqual(report["comparison_baseline"], "matched_control_arm")
        self.assertEqual(report["missing_control_alert_ids"], [])
        self.assertEqual(report["transitions"], {"TP->FP": 2})
        self.assertEqual(report["paired_correctness"]["improved"], 2)
        self.assertEqual(report["paired_correctness"]["regressed"], 0)
        self.assertEqual(report["paired_correctness"]["exact_mcnemar_p"], 0.5)


if __name__ == "__main__":
    unittest.main()
