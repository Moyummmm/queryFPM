#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


def read_jsonl(path: Path) -> dict[str, dict[str, Any]]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return {record["alert_id"]: record for record in records}


def truth(record: dict[str, Any]) -> str:
    return str(record.get("ground_truth", {}).get("alert_label", "UNKNOWN"))


def verdict(record: dict[str, Any]) -> str:
    return str(record.get("decision", {}).get("verdict", "UNKNOWN"))


def cwe(record: dict[str, Any]) -> str:
    return str(record.get("alert_contract", {}).get("cwe", "UNKNOWN"))


def metrics(records: Iterable[dict[str, Any]], verdicts: dict[str, str] | None = None) -> dict[str, Any]:
    rows = list(records)
    outcomes = {record["alert_id"]: verdict(record) for record in rows}
    if verdicts is not None:
        outcomes.update(verdicts)

    original_tp = sum(truth(record) == "TP" for record in rows)
    original_fp = sum(truth(record) == "FP" for record in rows)
    removed_tp = sum(
        truth(record) == "TP" and outcomes[record["alert_id"]] == "FP" for record in rows
    )
    removed_fp = sum(
        truth(record) == "FP" and outcomes[record["alert_id"]] == "FP" for record in rows
    )
    kept_tp = original_tp - removed_tp
    kept_fp = original_fp - removed_fp
    unknown = sum(outcomes[record["alert_id"]] == "UNKNOWN" for record in rows)
    return {
        "count": len(rows),
        "original_tp": original_tp,
        "original_fp": original_fp,
        "final_verdicts": dict(sorted(Counter(outcomes.values()).items())),
        "tp_retention": kept_tp / original_tp if original_tp else None,
        "fp_reduction": removed_fp / original_fp if original_fp else None,
        "post_filter_precision": kept_tp / (kept_tp + kept_fp) if kept_tp + kept_fp else None,
        "unknown_rate": unknown / len(rows) if rows else None,
        "removed_tp": removed_tp,
        "removed_fp": removed_fp,
    }


def candidate_round_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    traces: dict[str, dict[int, str]] = {}
    max_round = 0
    for record in records:
        by_round = {
            int(item.get("iteration", 1)): str(item.get("decision", {}).get("verdict", "UNKNOWN"))
            for item in record.get("llm_trace", [])
        }
        if not by_round:
            by_round[1] = verdict(record)
        traces[record["alert_id"]] = by_round
        max_round = max(max_round, max(by_round))

    snapshots: dict[str, Any] = {}
    latest: dict[str, str] = {}
    previous: dict[str, Any] | None = None
    for iteration in range(1, max_round + 1):
        for record in records:
            alert_id = record["alert_id"]
            if iteration in traces[alert_id]:
                latest[alert_id] = traces[alert_id][iteration]
        current = metrics(records, latest)
        current["alerts_evaluated_this_round"] = sum(
            iteration in trace for trace in traces.values()
        )
        if previous is not None:
            current["fp_reduction_gain"] = current["fp_reduction"] - previous["fp_reduction"]
            current["unknown_rate_change"] = current["unknown_rate"] - previous["unknown_rate"]
        snapshots[str(iteration)] = current
        previous = current
    return snapshots


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare a fixed error-audit cohort across runs.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--previous", required=True)
    parser.add_argument("--current", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--runtime")
    parser.add_argument("--previous-provider", default="unspecified")
    parser.add_argument("--current-provider", default="unspecified")
    parser.add_argument("--method-revision", default="unspecified")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    cohort = manifest["records"]
    cohort_ids = {record["alert_id"] for record in cohort}
    previous_all = read_jsonl(Path(args.previous))
    current_all = read_jsonl(Path(args.current))
    for name, records in (("previous", previous_all), ("current", current_all)):
        missing = sorted(cohort_ids - set(records))
        if missing:
            raise SystemExit(f"{name} run is missing {len(missing)} cohort alerts: {missing[:5]}")

    previous = [previous_all[record["alert_id"]] for record in cohort]
    current = [current_all[record["alert_id"]] for record in cohort]
    previous_by_id = {record["alert_id"]: record for record in previous}
    current_by_id = {record["alert_id"]: record for record in current}

    transitions: Counter[str] = Counter()
    for alert_id in sorted(cohort_ids):
        record = current_by_id[alert_id]
        transitions[
            f"{truth(record)}:{verdict(previous_by_id[alert_id])}->{verdict(record)}"
        ] += 1

    by_cwe: dict[str, Any] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in current:
        grouped[cwe(record)].append(record)
    for name, rows in sorted(grouped.items()):
        old_verdicts = {
            record["alert_id"]: verdict(previous_by_id[record["alert_id"]]) for record in rows
        }
        by_cwe[name] = {
            "previous": metrics(rows, old_verdicts),
            "current": metrics(rows),
        }

    manifest_by_id = {record["alert_id"]: record for record in cohort}
    controls = [
        record for record in current if manifest_by_id[record["alert_id"]]["reason"].startswith("correct_")
    ]
    control_regressions = [
        {
            "alert_id": record["alert_id"],
            "ground_truth": truth(record),
            "previous_verdict": verdict(previous_by_id[record["alert_id"]]),
            "current_verdict": verdict(record),
        }
        for record in controls
        if verdict(record) != truth(record)
    ]

    provider_changed = args.previous_provider != args.current_provider
    previous_metrics = metrics(previous)
    current_metrics = metrics(current)
    runtime_rounds: list[dict[str, Any]] = []
    if args.runtime:
        runtime = json.loads(Path(args.runtime).read_text(encoding="utf-8"))
        runtime_rounds = runtime.get("llm_rounds", [])

    report = {
        "scope": "fixed 150-alert error-audit cohort",
        "method_revision": args.method_revision,
        "manifest": args.manifest,
        "previous_run": args.previous,
        "current_run": args.current,
        "providers": {
            "previous": args.previous_provider,
            "current": args.current_provider,
            "changed": provider_changed,
        },
        "causal_interpretation": (
            "Provider changed between runs; observed deltas combine method and provider effects and "
            "must not be reported as a method-only causal gain."
            if provider_changed
            else "Provider is held constant; remaining configuration differences must still be audited."
        ),
        "previous": previous_metrics,
        "current": current_metrics,
        "deltas": {
            "tp_retention": current_metrics["tp_retention"] - previous_metrics["tp_retention"],
            "fp_reduction": current_metrics["fp_reduction"] - previous_metrics["fp_reduction"],
            "post_filter_precision": current_metrics["post_filter_precision"]
            - previous_metrics["post_filter_precision"],
            "unknown_rate": current_metrics["unknown_rate"] - previous_metrics["unknown_rate"],
        },
        "runtime_rounds": runtime_rounds,
        "candidate_round_metrics": candidate_round_metrics(current),
        "candidate_round_metrics_warning": (
            "These snapshots use raw LLM candidates from llm_trace before the conservative gate. "
            "They diagnose candidate evolution and are not deployable final metrics."
        ),
        "transitions": dict(sorted(transitions.items())),
        "controls": {
            "count": len(controls),
            "regression_count": len(control_regressions),
            "regressions": control_regressions,
        },
        "by_cwe": by_cwe,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("previous", "current", "deltas", "controls")}, indent=2))
    print(f"wrote comparison report to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
