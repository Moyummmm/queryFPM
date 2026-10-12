from __future__ import annotations

import unittest

from fpm_benchmark.ground_truth import attach_ground_truth
from fpm_benchmark.metrics import compute_metrics


class GroundTruthTest(unittest.TestCase):
    def test_exact_cwe_uses_testcase_vulnerability(self) -> None:
        evidence = self._evidence("CWE-079")
        expected = self._expected("CWE-079", True)

        result = attach_ground_truth(evidence, expected)

        self.assertEqual(result["ground_truth"]["alert_label"], "TP")
        self.assertTrue(result["ground_truth"]["alert_expected_vulnerable"])

    def test_cross_cwe_alert_is_unresolved(self) -> None:
        evidence = self._evidence("CWE-079")
        expected = self._expected("CWE-089", True)

        result = attach_ground_truth(evidence, expected)

        self.assertEqual(result["ground_truth"]["match_quality"], "test_only")
        self.assertTrue(result["ground_truth"]["test_expected_vulnerable"])
        self.assertIsNone(result["ground_truth"]["alert_expected_vulnerable"])
        self.assertEqual(result["ground_truth"]["alert_label"], "UNRESOLVED")

    def test_metrics_prefer_alert_level_label(self) -> None:
        record = attach_ground_truth(
            self._evidence("CWE-079"), self._expected("CWE-089", True)
        )
        record["decision"] = {"verdict": "FP"}

        metrics = compute_metrics([record])

        self.assertEqual(metrics["overall"]["original_tp"], 0)
        self.assertEqual(metrics["overall"]["original_fp"], 0)
        self.assertEqual(metrics["overall"]["operational"]["removed_fp"], 0)

    @staticmethod
    def _evidence(cwe: str) -> dict:
        return {
            "alert_contract": {
                "cwe": cwe,
                "message": "BenchmarkTest00001",
                "primary_location": {},
            }
        }

    @staticmethod
    def _expected(cwe: str, vulnerable: bool) -> dict:
        return {
            "BenchmarkTest00001": {
                "benchmark_test": "BenchmarkTest00001",
                "expected_cwe": cwe,
                "expected_vulnerable": vulnerable,
            }
        }


if __name__ == "__main__":
    unittest.main()
