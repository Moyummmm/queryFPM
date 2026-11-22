from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


def summarize_labeled_evidence(
    records: list[dict[str, Any]],
    target_cwes: set[str],
    expected: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    per_cwe: dict[str, Counter[str]] = defaultdict(Counter)
    unique_tests: dict[str, set[str]] = defaultdict(set)

    for record in records:
        cwe = record.get("alert_contract", {}).get("cwe") or "UNKNOWN"
        ground_truth = record.get("ground_truth", {})
        match_quality = ground_truth.get("match_quality", "none")
        label = ground_truth.get("alert_label", "UNMATCHED")
        test_name = ground_truth.get("benchmark_test")

        per_cwe[cwe]["alerts"] += 1
        per_cwe[cwe][label.lower()] += 1
        per_cwe[cwe][match_quality] += 1
        if label in {"TP", "FP"}:
            per_cwe[cwe]["labeled"] += 1
        if test_name:
            unique_tests[cwe].add(test_name)

    expected_counts: dict[str, Counter[str]] = defaultdict(Counter)
    if expected:
        for testcase in expected.values():
            cwe = testcase.get("expected_cwe")
            if cwe not in target_cwes:
                continue
            label = "tp" if testcase.get("expected_vulnerable") else "fp"
            expected_counts[cwe][label] += 1

    by_cwe: dict[str, Any] = {}
    for cwe in sorted(target_cwes | set(per_cwe)):
        counts = per_cwe[cwe]
        universe = expected_counts[cwe]
        by_cwe[cwe] = {
            "alerts": counts["alerts"],
            "labeled_alerts": counts["labeled"],
            "tp_alerts": counts["tp"],
            "fp_alerts": counts["fp"],
            "unmatched_alerts": counts["unmatched"],
            "exact_cwe_alerts": counts["exact_cwe"],
            "cross_cwe_alerts": counts["test_only"],
            "unique_benchmark_tests": len(unique_tests[cwe]),
            "expected_testcases": {
                "total": universe["tp"] + universe["fp"],
                "vulnerable": universe["tp"],
                "non_vulnerable": universe["fp"],
            },
        }

    labeled = sum(1 for r in records if _alert_truth(r) is not None)
    return {
        "total_target_alerts": len(records),
        "final_labeled_alerts": labeled,
        "unmatched_alerts": len(records) - labeled,
        "tp_alerts": sum(1 for r in records if _alert_truth(r) is True),
        "fp_alerts": sum(1 for r in records if _alert_truth(r) is False),
        "unique_benchmark_tests": len(
            {
                r.get("ground_truth", {}).get("benchmark_test")
                for r in records
                if r.get("ground_truth", {}).get("benchmark_test")
            }
        ),
        "by_cwe": by_cwe,
    }


def matched_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [record for record in records if _alert_truth(record) is not None]


def _alert_truth(record: dict[str, Any]) -> bool | None:
    return record.get("ground_truth", {}).get("alert_expected_vulnerable")
