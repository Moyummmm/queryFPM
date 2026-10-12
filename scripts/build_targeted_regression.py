#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REGRESSION_IDS = {
    "e7b80f287ce524be": "known_false_negative_cwe327",
    "bd1d3490219b7611": "known_false_negative_cwe501",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the fixed 50-alert regression cohort.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--previous-decisions", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    inputs = {r["alert_id"]: r for r in read_jsonl(Path(args.input))}
    previous = read_jsonl(Path(args.previous_decisions))
    selected: dict[str, str] = dict(REGRESSION_IDS)

    for record in previous:
        missing = record.get("decision", {}).get("missing_evidence", [])
        if (
            record.get("decision", {}).get("verdict") == "UNKNOWN"
            and "MAX_ITERATIONS_WITHOUT_SUFFICIENT_EVIDENCE" in missing
        ):
            selected.setdefault(record["alert_id"], "previous_gate_unknown")

    def add_stratum(cwe: str, label: str, count: int, reason: str) -> None:
        candidates = sorted(
            (
                record
                for record in previous
                if record.get("alert_contract", {}).get("cwe") == cwe
                and record.get("ground_truth", {}).get("alert_label") == label
                and record["alert_id"] not in selected
            ),
            key=lambda record: record["alert_id"],
        )
        if len(candidates) < count:
            raise SystemExit(f"not enough candidates for {cwe} {label}: {len(candidates)}")
        for record in candidates[:count]:
            selected[record["alert_id"]] = reason

    add_stratum("CWE-327", "TP", 9, "cwe327_tp_guard")
    add_stratum("CWE-327", "FP", 5, "cwe327_fp_guard")
    add_stratum("CWE-501", "TP", 4, "cwe501_tp_guard")
    add_stratum("CWE-501", "FP", 5, "cwe501_fp_guard")

    for cwe in ("CWE-022", "CWE-078", "CWE-079", "CWE-089", "CWE-643"):
        add_stratum(cwe, "FP", 1, "cross_cwe_fp_regression")

    if len(selected) != 50:
        raise SystemExit(f"expected 50 selected alerts, got {len(selected)}")
    missing_inputs = sorted(set(selected) - set(inputs))
    if missing_inputs:
        raise SystemExit(f"selected alerts missing from input: {missing_inputs}")

    ordered_ids = sorted(selected)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "".join(json.dumps(inputs[alert_id], ensure_ascii=False) + "\n" for alert_id in ordered_ids),
        encoding="utf-8",
    )
    manifest = {
        "count": len(ordered_ids),
        "source_input": args.input,
        "previous_decisions": args.previous_decisions,
        "records": [
            {
                "alert_id": alert_id,
                "reason": selected[alert_id],
                "cwe": inputs[alert_id].get("alert_contract", {}).get("cwe"),
                "ground_truth": inputs[alert_id].get("ground_truth", {}).get("alert_label"),
            }
            for alert_id in ordered_ids
        ],
    }
    Path(args.manifest).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(f"wrote {len(ordered_ids)} records to {out}")
    print(f"wrote cohort manifest to {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
