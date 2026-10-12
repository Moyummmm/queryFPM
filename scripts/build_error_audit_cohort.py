#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def truth(record: dict[str, Any]) -> str:
    return str(record.get("ground_truth", {}).get("alert_label", "UNKNOWN"))


def verdict(record: dict[str, Any]) -> str:
    return str(record.get("decision", {}).get("verdict", "UNKNOWN"))


def cwe(record: dict[str, Any]) -> str:
    return str(record.get("alert_contract", {}).get("cwe", "UNKNOWN"))


def choose_controls(
    records: list[dict[str, Any]], selected: set[str], label: str, count: int
) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if (
            record["alert_id"] not in selected
            and truth(record) == label
            and verdict(record) == label
            and not record.get("llm_error")
        ):
            groups[cwe(record)].append(record)
    for group in groups.values():
        group.sort(key=lambda item: item["alert_id"])

    chosen: list[dict[str, Any]] = []
    cwes = sorted(groups)
    offset = 0
    while len(chosen) < count:
        progressed = False
        for name in cwes:
            if offset < len(groups[name]):
                chosen.append(groups[name][offset])
                progressed = True
                if len(chosen) == count:
                    break
        if not progressed:
            raise SystemExit(f"not enough correct {label} controls")
        offset += 1
    return chosen


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the fixed 150-alert error audit cohort.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    inputs = {record["alert_id"]: record for record in read_jsonl(Path(args.input))}
    decisions = read_jsonl(Path(args.decisions))
    reasons: dict[str, str] = {}
    for record in decisions:
        if verdict(record) == "UNKNOWN":
            reasons[record["alert_id"]] = "final_unknown"
        elif truth(record) == "FP" and verdict(record) == "TP":
            reasons[record["alert_id"]] = "false_positive_retained_as_tp"

    if len(reasons) != 128:
        raise SystemExit(f"expected 128 error/abstention records, got {len(reasons)}")

    selected = set(reasons)
    for record in choose_controls(decisions, selected, "TP", 11):
        reasons[record["alert_id"]] = "correct_tp_control"
        selected.add(record["alert_id"])
    for record in choose_controls(decisions, selected, "FP", 11):
        reasons[record["alert_id"]] = "correct_fp_control"
        selected.add(record["alert_id"])

    if len(reasons) != 150:
        raise SystemExit(f"expected 150 records, got {len(reasons)}")
    missing = sorted(selected - set(inputs))
    if missing:
        raise SystemExit(f"selected alerts missing from input: {missing}")

    ordered_ids = sorted(selected)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "".join(json.dumps(inputs[alert_id], ensure_ascii=False) + "\n" for alert_id in ordered_ids),
        encoding="utf-8",
    )
    decision_by_id = {record["alert_id"]: record for record in decisions}
    manifest = {
        "count": len(ordered_ids),
        "source_input": args.input,
        "source_decisions": args.decisions,
        "records": [
            {
                "alert_id": alert_id,
                "reason": reasons[alert_id],
                "cwe": cwe(decision_by_id[alert_id]),
                "ground_truth": truth(decision_by_id[alert_id]),
                "previous_verdict": verdict(decision_by_id[alert_id]),
            }
            for alert_id in ordered_ids
        ],
    }
    manifest_path = Path(args.manifest)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(f"wrote {len(ordered_ids)} records to {out}")
    print(f"wrote cohort manifest to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
