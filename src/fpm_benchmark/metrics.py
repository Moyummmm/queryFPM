from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


def compute_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    infrastructure_errors = sum(1 for r in records if _verdict(r) == "INFRA_ERROR")
    labeled = [r for r in records if _truth(r) is not None and _verdict(r) in {"TP", "FP", "UNKNOWN"}]
    overall = _compute_group(labeled)
    by_cwe: dict[str, Any] = {}
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in labeled:
        cwe = record.get("alert_contract", {}).get("cwe") or "UNKNOWN"
        groups[cwe].append(record)
    for cwe, group in sorted(groups.items()):
        by_cwe[cwe] = _compute_group(group)
    return {
        "overall": overall,
        "by_cwe": by_cwe,
        "labeled_alerts": len(labeled),
        "excluded_infrastructure_errors": infrastructure_errors,
        "experiment_complete": infrastructure_errors == 0,
    }


def _compute_group(records: list[dict[str, Any]]) -> dict[str, Any]:
    original_tp = sum(1 for r in records if _truth(r) is True)
    original_fp = sum(1 for r in records if _truth(r) is False)

    kept_tp = sum(1 for r in records if _truth(r) is True and _kept_operational(r))
    removed_tp = sum(1 for r in records if _truth(r) is True and _verdict(r) == "FP")
    kept_fp = sum(1 for r in records if _truth(r) is False and _kept_operational(r))
    removed_fp = sum(1 for r in records if _truth(r) is False and _verdict(r) == "FP")
    unknown = sum(1 for r in records if _verdict(r) == "UNKNOWN")

    precision = _safe_div(kept_tp, kept_tp + kept_fp)
    tp_retention = _safe_div(kept_tp, original_tp)
    fp_reduction = _safe_div(removed_fp, original_fp)
    f1 = _f1(precision, tp_retention)
    mcc = _mcc(kept_tp, kept_fp, removed_fp, removed_tp)

    non_unknown = [r for r in records if _verdict(r) != "UNKNOWN"]
    selective = _selective(non_unknown)

    return {
        "count": len(records),
        "original_tp": original_tp,
        "original_fp": original_fp,
        "operational": {
            "kept_tp": kept_tp,
            "kept_fp": kept_fp,
            "removed_tp": removed_tp,
            "removed_fp": removed_fp,
            "precision": precision,
            "tp_retention": tp_retention,
            "fp_reduction": fp_reduction,
            "f1": f1,
            "mcc": mcc,
        },
        "unknown": {
            "count": unknown,
            "rate": _safe_div(unknown, len(records)),
            "coverage": _safe_div(len(records) - unknown, len(records)),
        },
        "selective": selective,
    }


def _selective(records: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(1 for r in records if _truth(r) is True and _verdict(r) == "TP")
    fp = sum(1 for r in records if _truth(r) is False and _verdict(r) == "TP")
    tn = sum(1 for r in records if _truth(r) is False and _verdict(r) == "FP")
    fn = sum(1 for r in records if _truth(r) is True and _verdict(r) == "FP")
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    return {
        "count": len(records),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": _safe_div(tp + tn, len(records)),
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
        "mcc": _mcc(tp, fp, tn, fn),
    }


def _truth(record: dict[str, Any]) -> bool | None:
    ground_truth = record.get("ground_truth", {})
    if "alert_expected_vulnerable" in ground_truth:
        return ground_truth.get("alert_expected_vulnerable")
    return ground_truth.get("expected_vulnerable")


def _verdict(record: dict[str, Any]) -> str:
    return str(record.get("decision", {}).get("verdict", "UNKNOWN")).upper()


def _kept_operational(record: dict[str, Any]) -> bool:
    return _verdict(record) in {"TP", "UNKNOWN"}


def _safe_div(a: float, b: float) -> float | None:
    if b == 0:
        return None
    return a / b


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def _mcc(tp: int, fp: int, tn: int, fn: int) -> float | None:
    denom = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    if denom == 0:
        return None
    return (tp * tn - fp * fn) / math.sqrt(denom)
