#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from fpm_benchmark.metrics import compute_metrics
from fpm_benchmark.utils import read_jsonl, write_json


def _verdict(decision: dict[str, Any]) -> str:
    return str(decision.get("verdict", "UNKNOWN")).upper()


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = compute_metrics(records)
    final_verdicts = Counter(_verdict(r.get("decision", {})) for r in records)
    llm_failures = 0
    infrastructure_error_types: Counter[str] = Counter()
    query_statuses: Counter[str] = Counter()
    query_templates: Counter[str] = Counter()
    round_verdicts: dict[int, Counter[str]] = {}

    for record in records:
        if record.get("llm_error") or record.get("last_failed_decision"):
            llm_failures += 1
        if _verdict(record.get("decision", {})) == "INFRA_ERROR":
            infrastructure_error_types[
                str(record.get("infrastructure_error", {}).get("type", "unknown"))
            ] += 1
        for item in record.get("query_history", []):
            query_statuses[str(item.get("status", "unknown"))] += 1
            query_templates[str(item.get("template_id", "unknown"))] += 1
        for item in record.get("llm_trace", []):
            iteration = int(item.get("iteration", 1))
            round_verdicts.setdefault(iteration, Counter())[_verdict(item.get("decision", {}))] += 1

    return {
        "metrics": metrics,
        "diagnostics": {
            "records": len(records),
            "final_verdicts": dict(final_verdicts),
            "records_with_llm_failure": llm_failures,
            "final_infrastructure_errors": dict(infrastructure_error_types),
            "query_statuses": dict(query_statuses),
            "query_templates": dict(query_templates),
            "round_verdicts": {
                str(round_number): dict(counts)
                for round_number, counts in sorted(round_verdicts.items())
            },
        },
    }


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize FPM decision JSONL results.")
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    records = read_jsonl(args.decisions)
    report = summarize(records)
    write_json(args.out, report)

    overall = report["metrics"]["overall"]
    operational = overall["operational"]
    unknown = overall["unknown"]
    diagnostics = report["diagnostics"]
    print(f"records: {diagnostics['records']}")
    print(f"final verdicts: {diagnostics['final_verdicts']}")
    print(f"TP Retention: {_percent(operational['tp_retention'])}")
    print(f"FP Reduction: {_percent(operational['fp_reduction'])}")
    print(f"Precision: {_percent(operational['precision'])}")
    print(f"Unknown Rate: {_percent(unknown['rate'])}")
    print(f"MCC: {operational['mcc']}")
    print(f"records with LLM failure: {diagnostics['records_with_llm_failure']}")
    print(f"wrote summary to {Path(args.out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
