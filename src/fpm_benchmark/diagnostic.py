from __future__ import annotations

import copy
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .batch_codeql import execute_batched_template_queries
from .metrics import compute_metrics
from .utils import stable_id


FORCED_TEMPLATES_BY_CWE: dict[str, tuple[str, ...]] = {
    "CWE-022": (
        "find-path-canonical-guard",
        "find-sink-argument-origin",
        "find-constant-assignment-nearby",
    ),
    "CWE-078": (
        "find-command-execution-arguments",
        "find-sink-argument-origin",
        "find-constant-assignment-nearby",
    ),
    "CWE-079": (
        "find-xss-encoder-nearby",
        "find-sink-argument-origin",
        "find-constant-assignment-nearby",
    ),
    "CWE-089": (
        "find-sql-parameterization",
        "find-sink-argument-origin",
        "find-constant-assignment-nearby",
    ),
    "CWE-090": (
        "find-sanitizer-on-path",
        "find-validator-or-guard",
        "find-sink-argument-origin",
    ),
    "CWE-327": ("find-crypto-algorithm",),
    "CWE-330": ("find-randomness-source",),
    "CWE-501": ("find-trust-boundary-transfer", "find-validator-or-guard"),
    "CWE-614": ("find-cookie-secure-flag",),
    "CWE-643": (
        "find-sanitizer-on-path",
        "find-validator-or-guard",
        "find-sink-argument-origin",
    ),
}


def select_diagnostic_cohort(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    labeled = [record for record in records if _truth(record) is not None]
    errors = sorted(
        (record for record in labeled if not _is_correct(record)),
        key=_record_sort_key,
    )
    controls = sorted(
        (record for record in labeled if _is_correct(record)),
        key=_record_sort_key,
    )
    available = {id(record): record for record in controls}
    cohort: list[dict[str, Any]] = []
    match_counts: Counter[str] = Counter()
    unmatched: list[str] = []

    for pair_index, error in enumerate(errors, start=1):
        control, quality = _take_control(error, available)
        if control is None:
            unmatched.append(str(error.get("alert_id", "")))
            continue
        pair_id = f"pair-{pair_index:04d}"
        cohort.append(_diagnostic_copy(error, role="error", pair_id=pair_id, match_quality=quality))
        cohort.append(
            _diagnostic_copy(control, role="control", pair_id=pair_id, match_quality=quality)
        )
        match_counts[quality] += 1

    report = {
        "source_records": len(records),
        "labeled_records": len(labeled),
        "source_errors": len(errors),
        "paired_errors": len(cohort) // 2,
        "cohort_records": len(cohort),
        "match_quality": dict(sorted(match_counts.items())),
        "unmatched_error_alert_ids": unmatched,
        "errors_by_cwe": _counts_by(errors, _cwe),
        "errors_by_truth": _counts_by(errors, _truth_label),
        "cohort_by_cwe": _counts_by(cohort, _cwe),
        "cohort_by_role": _counts_by(
            cohort, lambda record: record.get("diagnostic", {}).get("cohort_role", "unknown")
        ),
    }
    return cohort, report


def force_diagnostic_evidence(
    records: list[dict[str, Any]],
    *,
    codeql_bin: str,
    database: str | Path,
    manifest: dict[str, Any],
    template_root: str | Path,
    cache_dir: str | Path,
    additional_packs_root: str | Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    request_targets: dict[str, tuple[int, str, dict[str, Any]]] = {}

    for index, record in enumerate(records):
        cwe = _cwe(record)
        location = _location_params(record)
        templates = FORCED_TEMPLATES_BY_CWE.get(cwe, ())
        if location is None:
            record.setdefault("diagnostic", {})["query_preparation_error"] = "missing location"
            continue
        for template_id in templates:
            parameters = dict(location)
            if template_id == "find-sanitizer-on-path":
                parameters["cwe"] = cwe
            request_id = f"diagnostic:{index}:{template_id}"
            request = {
                "request_id": request_id,
                "template_id": template_id,
                "parameters": parameters,
            }
            requests.append(request)
            request_targets[request_id] = (index, template_id, parameters)

    results, query_stats = execute_batched_template_queries(
        requests=requests,
        codeql_bin=codeql_bin,
        database=database,
        manifest=manifest,
        template_root=template_root,
        cache_dir=cache_dir,
        additional_packs_root=additional_packs_root,
    )

    status_counts: Counter[str] = Counter()
    for request_id, (index, template_id, parameters) in request_targets.items():
        result = results[request_id]
        status_counts[str(result.get("status", "unknown"))] += 1
        query_record = {
            "iteration": "diagnostic-forced",
            "template_id": template_id,
            "parameters": parameters,
            "reason": "forced evidence for paired gate diagnostic",
            **result,
        }
        records[index].setdefault("query_history", []).append(query_record)
        records[index].setdefault("supplemental_evidence", []).append(result)

    report = {
        "forced_query_requests": len(requests),
        "query_status": dict(sorted(status_counts.items())),
        "query_engine": query_stats,
        "templates_by_cwe": {
            cwe: list(templates) for cwe, templates in FORCED_TEMPLATES_BY_CWE.items()
        },
    }
    return records, report


def compare_diagnostic_decisions(
    records: list[dict[str, Any]],
    baseline_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    before_records: list[dict[str, Any]] = []
    transitions: Counter[str] = Counter()
    by_role: dict[str, Counter[str]] = defaultdict(Counter)
    by_cwe: dict[str, Counter[str]] = defaultdict(Counter)

    controls_by_alert = {
        str(record.get("alert_id")): record for record in (baseline_records or [])
    }
    missing_control_alert_ids: list[str] = []
    paired_rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for record in records:
        diagnostic = record.get("diagnostic", {})
        alert_id = str(record.get("alert_id"))
        control = controls_by_alert.get(alert_id)
        baseline = (
            control.get("decision") if control is not None else diagnostic.get("baseline_decision")
        )
        if baseline_records is not None and control is None:
            missing_control_alert_ids.append(alert_id)
        if not isinstance(baseline, dict):
            continue
        before = str(baseline.get("verdict", "UNKNOWN")).upper()
        after = str(record.get("decision", {}).get("verdict", "UNKNOWN")).upper()
        transition = f"{before}->{after}"
        role = str(diagnostic.get("cohort_role", "unknown"))
        transitions[transition] += 1
        by_role[role][transition] += 1
        by_cwe[_cwe(record)][transition] += 1

        before_record = copy.deepcopy(record)
        before_record["decision"] = copy.deepcopy(baseline)
        before_records.append(before_record)
        paired_rows.append((before_record, record))

    error_records = [
        record
        for record in records
        if record.get("diagnostic", {}).get("cohort_role") == "error"
    ]
    cohort_controls = [
        record
        for record in records
        if record.get("diagnostic", {}).get("cohort_role") == "control"
    ]
    errors_corrected = sum(1 for record in error_records if _is_correct(record))
    controls_regressed = sum(1 for record in cohort_controls if not _is_correct(record))

    outcome_by_cwe: dict[str, Any] = {}
    for cwe in sorted({_cwe(record) for record in records}):
        cwe_errors = [record for record in error_records if _cwe(record) == cwe]
        cwe_controls = [record for record in cohort_controls if _cwe(record) == cwe]
        outcome_by_cwe[cwe] = {
            "errors": len(cwe_errors),
            "errors_corrected": sum(1 for record in cwe_errors if _is_correct(record)),
            "controls": len(cwe_controls),
            "controls_regressed": sum(1 for record in cwe_controls if not _is_correct(record)),
        }

    return {
        "comparison_baseline": "matched_control_arm" if baseline_records is not None else "saved_original",
        "records": len(records),
        "comparable_records": len(before_records),
        "missing_control_alert_ids": missing_control_alert_ids,
        "errors": {
            "count": len(error_records),
            "corrected": errors_corrected,
            "correction_rate": _safe_div(errors_corrected, len(error_records)),
        },
        "controls": {
            "count": len(cohort_controls),
            "regressed": controls_regressed,
            "regression_rate": _safe_div(controls_regressed, len(cohort_controls)),
        },
        "net_corrected": errors_corrected - controls_regressed,
        "transitions": dict(sorted(transitions.items())),
        "transitions_by_role": {
            role: dict(sorted(counts.items())) for role, counts in sorted(by_role.items())
        },
        "transitions_by_cwe": {
            cwe: dict(sorted(counts.items())) for cwe, counts in sorted(by_cwe.items())
        },
        "outcomes_by_cwe": outcome_by_cwe,
        "paired_correctness": _paired_correctness(paired_rows),
        "paired_correctness_by_role": {
            role: _paired_correctness(
                [
                    pair
                    for pair in paired_rows
                    if pair[1].get("diagnostic", {}).get("cohort_role") == role
                ]
            )
            for role in ("error", "control")
        },
        "paired_correctness_by_cwe": {
            cwe: _paired_correctness(
                [pair for pair in paired_rows if _cwe(pair[1]) == cwe]
            )
            for cwe in sorted({_cwe(record) for record in records})
        },
        "metrics_before_forced_evidence": compute_metrics(before_records),
        "metrics_after_forced_evidence": compute_metrics(records),
    }


def _take_control(
    error: dict[str, Any], available: dict[int, dict[str, Any]]
) -> tuple[dict[str, Any] | None, str]:
    candidates = list(available.values())
    cwe = _cwe(error)
    truth = _truth(error)
    strategies = (
        ("exact_cwe_and_truth", lambda record: _cwe(record) == cwe and _truth(record) is truth),
        ("fallback_same_cwe", lambda record: _cwe(record) == cwe),
        ("fallback_same_truth", lambda record: _truth(record) is truth),
        ("fallback_any_correct", lambda record: True),
    )
    for quality, predicate in strategies:
        match = next((record for record in candidates if predicate(record)), None)
        if match is not None:
            available.pop(id(match))
            return match, quality
    return None, "unmatched"


def _diagnostic_copy(
    record: dict[str, Any], *, role: str, pair_id: str, match_quality: str
) -> dict[str, Any]:
    copied = copy.deepcopy(record)
    baseline_decision = copy.deepcopy(copied.get("decision", {}))
    copied["diagnostic"] = {
        "study": "forced-cwe-evidence-v1",
        "cohort_role": role,
        "pair_id": pair_id,
        "match_quality": match_quality,
        "baseline_decision": baseline_decision,
        "baseline_verdict": baseline_decision.get("verdict", "UNKNOWN"),
        "truth_label": _truth_label(copied),
        "prior_query_count": len(copied.get("query_history", [])),
    }
    copied["query_history"] = []
    copied["supplemental_evidence"] = []
    for key in (
        "decision",
        "llm_trace",
        "llm_usage_total",
        "llm_error",
        "runtime_seconds",
        "runtime_breakdown",
    ):
        copied.pop(key, None)
    return copied


def _location_params(record: dict[str, Any]) -> dict[str, Any] | None:
    primary = record.get("alert_contract", {}).get("primary_location", {})
    file = primary.get("file") or primary.get("uri")
    line = primary.get("start_line")
    if not file or line in {None, ""}:
        return None
    return {"file": file, "line": line}


def _is_correct(record: dict[str, Any]) -> bool:
    truth = _truth(record)
    verdict = str(record.get("decision", {}).get("verdict", "UNKNOWN")).upper()
    return (truth is True and verdict == "TP") or (truth is False and verdict == "FP")


def _truth(record: dict[str, Any]) -> bool | None:
    ground_truth = record.get("ground_truth", {})
    if "alert_expected_vulnerable" in ground_truth:
        return ground_truth.get("alert_expected_vulnerable")
    return ground_truth.get("expected_vulnerable")


def _truth_label(record: dict[str, Any]) -> str:
    truth = _truth(record)
    if truth is True:
        return "TP"
    if truth is False:
        return "FP"
    return "UNKNOWN"


def _cwe(record: dict[str, Any]) -> str:
    return str(record.get("alert_contract", {}).get("cwe") or "UNKNOWN")


def _record_sort_key(record: dict[str, Any]) -> tuple[str, str]:
    return (_cwe(record), str(record.get("alert_id") or stable_id(record)))


def _counts_by(records: list[dict[str, Any]], key) -> dict[str, int]:
    counts = Counter(str(key(record)) for record in records)
    return dict(sorted(counts.items()))


def _safe_div(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _paired_correctness(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for before, after in pairs:
        before_correct = _is_correct(before)
        after_correct = _is_correct(after)
        if before_correct and after_correct:
            counts["both_correct"] += 1
        elif not before_correct and not after_correct:
            counts["both_wrong"] += 1
        elif not before_correct and after_correct:
            counts["improved"] += 1
        else:
            counts["regressed"] += 1
    improved = counts["improved"]
    regressed = counts["regressed"]
    return {
        "count": len(pairs),
        "both_correct": counts["both_correct"],
        "both_wrong": counts["both_wrong"],
        "improved": improved,
        "regressed": regressed,
        "net_improvement": improved - regressed,
        "exact_mcnemar_p": _exact_mcnemar_p(improved, regressed),
    }


def _exact_mcnemar_p(improved: int, regressed: int) -> float | None:
    discordant = improved + regressed
    if discordant == 0:
        return None
    tail = sum(math.comb(discordant, k) for k in range(min(improved, regressed) + 1))
    return min(1.0, 2.0 * tail / (2**discordant))
