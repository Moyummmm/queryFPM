from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any, Iterable
import re

from .cwe_profiles import profile_for
from .evidence import build_evidence_slots, compact_for_llm, infer_missing_evidence
from .sarif import sarif_to_evidence
from .utils import read_json


JULIET_RULES: dict[str, dict[str, Any]] = {
    "java/path-injection": {
        "cwe": "CWE-022",
        "directories": {"CWE23_Relative_Path_Traversal", "CWE36_Absolute_Path_Traversal"},
    },
    "java/command-line-injection": {
        "cwe": "CWE-078",
        "directories": {"CWE78_OS_Command_Injection"},
    },
    "java/xss": {
        "cwe": "CWE-079",
        "directories": {"CWE80_XSS", "CWE81_XSS_Error_Message", "CWE83_XSS_Attribute"},
    },
    "java/sql-injection": {
        "cwe": "CWE-089",
        "directories": {"CWE89_SQL_Injection"},
    },
    "java/ldap-injection": {
        "cwe": "CWE-090",
        "directories": {"CWE90_LDAP_Injection"},
    },
    "java/weak-cryptographic-algorithm": {
        "cwe": "CWE-327",
        "directories": {"CWE327_Use_Broken_Crypto"},
    },
    "java/predictable-seed": {
        "cwe": "CWE-330",
        "directories": {"CWE336_Same_Seed_in_PRNG", "CWE338_Weak_PRNG"},
    },
    "java/insecure-cookie": {
        "cwe": "CWE-614",
        "directories": {"CWE614_Sensitive_Cookie_Without_Secure"},
    },
    "java/xml/xpath-injection": {
        "cwe": "CWE-643",
        "directories": {"CWE643_Xpath_Injection"},
    },
}


def prepare_juliet_evidence(
    *,
    sarif_path: str | Path,
    callable_locations_path: str | Path,
    source_root: str | Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = sarif_to_evidence(sarif_path, source_root=source_root)
    callable_rows = load_callable_locations(callable_locations_path)
    return prepare_juliet_records(records, callable_rows)


def load_callable_locations(path: str | Path) -> list[list[Any]]:
    data = read_json(path)
    rows = data.get("#select", {}).get("tuples", []) if isinstance(data, dict) else []
    return [row for row in rows if isinstance(row, list) and len(row) >= 5]


def prepare_juliet_records(
    records: Iterable[dict[str, Any]], callable_rows: Iterable[list[Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    callables_by_file: dict[str, list[list[Any]]] = defaultdict(list)
    for row in callable_rows:
        callables_by_file[str(row[0])].append(row)

    prepared: list[dict[str, Any]] = []
    labels: Counter[str] = Counter()
    per_cwe: dict[str, Counter[str]] = defaultdict(Counter)

    for record in records:
        contract = record.get("alert_contract", {})
        rule_id = str(contract.get("rule_id") or "")
        spec = JULIET_RULES.get(rule_id)
        if not spec:
            continue

        primary = contract.get("primary_location", {})
        file = str(primary.get("file") or primary.get("uri") or "")
        juliet_directory = _juliet_directory(file)
        if juliet_directory not in spec["directories"]:
            continue

        cwe = str(spec["cwe"])
        contract["cwe"] = cwe
        record["cwe_profile"] = profile_for(cwe)
        record["evidence_slots"] = build_evidence_slots(
            cwe, record.get("annotated_trace", [])
        )
        record["missing_evidence"] = infer_missing_evidence(cwe, record["evidence_slots"])
        record["dataset"] = {
            "name": "Juliet Test Suite for Java",
            "version": "1.3",
            "label_blind": True,
            "juliet_cwe_directory": juliet_directory,
        }

        line = _to_int(primary.get("start_line"))
        matches = [
            row
            for row in callables_by_file.get(file, [])
            if line is not None and _to_int(row[1]) <= line <= _to_int(row[2])
        ]
        label, label_reason = _label_from_callable(matches)
        benchmark_test = _benchmark_test_name(file)
        expected = label == "TP" if label in {"TP", "FP"} else None
        record["ground_truth"] = {
            "dataset": "juliet-java-1.3",
            "benchmark_test": benchmark_test,
            "alert_expected_vulnerable": expected,
            "alert_label": label,
            "match_quality": "exact_callable" if len(matches) == 1 else "ambiguous",
            "label_source": label_reason,
        }
        prepared.append(record)
        labels[label] += 1
        per_cwe[cwe][label] += 1

    summary = {
        "dataset": "juliet-java-1.3",
        "target_alerts": len(prepared),
        "labels": dict(sorted(labels.items())),
        "raw_codeql_precision": _raw_precision(labels),
        "per_cwe": {
            cwe: {"total": sum(counts.values()), **dict(sorted(counts.items()))}
            for cwe, counts in sorted(per_cwe.items())
        },
    }
    summary["label_leakage_audit"] = audit_label_blind_views(prepared)
    if any(summary["label_leakage_audit"]["leak_counts"].values()):
        raise ValueError(f"Juliet label leakage detected: {summary['label_leakage_audit']}")
    return prepared, summary


def audit_label_blind_views(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    patterns = {
        "ground_truth": re.compile(r"ground_truth", flags=re.IGNORECASE),
        "juliet_label": re.compile(
            r"(?:\b(?:good|bad)(?=\s*\()|_(?:good|bad)(?:\.java|\b)|"
            r"\b(?:goodG2B|goodB2G|badSink|goodSink)\b)",
            flags=re.IGNORECASE,
        ),
        "comment_marker": re.compile(r"POTENTIAL FLAW|\bFIX\b", flags=re.IGNORECASE),
    }
    counts: Counter[str] = Counter()
    scanned = 0
    for record in records:
        view = compact_for_llm(record, view="query-centered")
        text = json.dumps(view, ensure_ascii=False, sort_keys=True)
        scanned += 1
        for name, pattern in patterns.items():
            if pattern.search(text):
                counts[name] += 1
    return {
        "records_scanned": scanned,
        "view": "query-centered",
        "leak_counts": {name: counts.get(name, 0) for name in patterns},
    }


def _label_from_callable(matches: list[list[Any]]) -> tuple[str, str]:
    if len(matches) != 1:
        return "UNKNOWN", f"enclosing_callable_matches={len(matches)}"

    row = matches[0]
    declaring_type = str(row[3]).rsplit(".", 1)[-1]
    callable_name = str(row[4])
    signals: set[str] = set()

    if callable_name.lower().startswith("bad"):
        signals.add("TP")
    if callable_name.lower().startswith("good"):
        signals.add("FP")
    if re.search(r"_bad$", declaring_type, flags=re.IGNORECASE):
        signals.add("TP")
    if re.search(r"_good(?:g2b|b2g)?$", declaring_type, flags=re.IGNORECASE):
        signals.add("FP")

    if len(signals) != 1:
        return "UNKNOWN", f"callable={callable_name};class={declaring_type};signals={signals}"
    label = next(iter(signals))
    return label, f"callable={callable_name};class={declaring_type}"


def _juliet_directory(file: str) -> str | None:
    parts = Path(file).parts
    try:
        index = parts.index("testcases")
    except ValueError:
        return None
    return parts[index + 1] if index + 1 < len(parts) else None


def _benchmark_test_name(file: str) -> str:
    stem = Path(file).stem
    stem = re.sub(r"_(?:bad|goodG2B|goodB2G|base)$", "", stem, flags=re.IGNORECASE)
    return re.sub(r"(?<=\d)[a-e]$", "", stem, flags=re.IGNORECASE)


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _raw_precision(labels: Counter[str]) -> float | None:
    tp = labels.get("TP", 0)
    fp = labels.get("FP", 0)
    return tp / (tp + fp) if tp + fp else None
