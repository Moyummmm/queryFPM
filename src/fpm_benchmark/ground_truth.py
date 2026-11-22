from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from .utils import canonical_cwe, truthy

BENCHMARK_TEST_RE = re.compile(r"\bBenchmarkTest\d{5}\b")


def extract_benchmark_test_name(*values: object) -> str | None:
    for value in values:
        if value is None:
            continue
        m = BENCHMARK_TEST_RE.search(str(value))
        if m:
            return m.group(0)
    return None


def _normalize_key(key: str) -> str:
    key = key.strip().lstrip("\ufeff").lstrip("#").strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", key).strip("_")


def load_expected_results(path: str | Path) -> dict[str, dict[str, Any]]:
    """Load OWASP Benchmark expected results keyed by BenchmarkTestNNNNN."""

    path = Path(path)
    records: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for raw_row in reader:
            row = {_normalize_key(k): (v.strip() if isinstance(v, str) else v) for k, v in raw_row.items()}
            test_name = (
                row.get("test_name")
                or row.get("test")
                or row.get("name")
                or extract_benchmark_test_name(*row.values())
            )
            if not test_name:
                continue
            cwe = canonical_cwe(row.get("cwe"))
            vulnerable = truthy(
                row.get("real_vulnerability")
                or row.get("real")
                or row.get("vulnerable")
                or row.get("expected")
            )
            records[test_name] = {
                "benchmark_test": test_name,
                "category": row.get("category"),
                "expected_vulnerable": vulnerable,
                "expected_cwe": cwe,
                "raw": row,
            }
    return records


def attach_ground_truth(
    evidence: dict[str, Any], expected: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    contract = evidence.get("alert_contract", {})
    primary = contract.get("primary_location", {})
    path_name = extract_benchmark_test_name(primary.get("file"), primary.get("uri"))
    message_names = set(BENCHMARK_TEST_RE.findall(str(contract.get("message") or "")))
    test_name = path_name or (next(iter(message_names)) if len(message_names) == 1 else None)
    if path_name and message_names and message_names != {path_name}:
        evidence["ground_truth"] = {"benchmark_test": path_name,
            "expected_vulnerable": None, "alert_expected_vulnerable": None,
            "alert_label": "UNRESOLVED", "match_quality": "conflicting_test_ids"}
        return evidence
    gt = expected.get(test_name or "")
    if not gt:
        evidence["ground_truth"] = {
            "benchmark_test": test_name,
            "expected_vulnerable": None,
            "test_expected_vulnerable": None,
            "alert_expected_vulnerable": None,
            "alert_label": "UNMATCHED",
            "expected_cwe": None,
            "match_quality": "none",
        }
        return evidence

    alert_cwe = contract.get("cwe")
    expected_cwe = gt.get("expected_cwe")
    match_quality = "exact_cwe" if alert_cwe == expected_cwe else "test_only"
    test_expected_vulnerable = gt.get("expected_vulnerable")
    alert_expected_vulnerable = (
        test_expected_vulnerable if match_quality == "exact_cwe" else None
    )
    evidence["ground_truth"] = {
        "benchmark_test": gt["benchmark_test"],
        # Keep the historical field as the raw OWASP testcase label.
        "expected_vulnerable": test_expected_vulnerable,
        "test_expected_vulnerable": test_expected_vulnerable,
        "alert_expected_vulnerable": alert_expected_vulnerable,
        "alert_label": ("TP" if alert_expected_vulnerable is True else
                        "FP" if alert_expected_vulnerable is False else "UNRESOLVED"),
        "expected_cwe": expected_cwe,
        "match_quality": match_quality,
    }
    return evidence
