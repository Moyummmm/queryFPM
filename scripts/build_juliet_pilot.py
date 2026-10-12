#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

from fpm_benchmark.utils import read_jsonl, write_json, write_jsonl


def build_pilot(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    false_positives = [record for record in records if _label(record) == "FP"]
    true_positives = [record for record in records if _label(record) == "TP"]
    tp_by_family: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)
    tp_by_cwe: dict[str, deque[dict[str, Any]]] = defaultdict(deque)

    for record in sorted(true_positives, key=_sort_key):
        key = (_cwe(record), _family(record))
        tp_by_family[key].append(record)
        tp_by_cwe[_cwe(record)].append(record)

    selected_tp: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    match_quality: Counter[str] = Counter()
    for fp in sorted(false_positives, key=_sort_key):
        key = (_cwe(fp), _family(fp))
        match = _take_unused(tp_by_family[key], selected_ids)
        quality = "same_cwe_family"
        if match is None:
            match = _take_unused(tp_by_cwe[_cwe(fp)], selected_ids)
            quality = "same_cwe"
        if match is None:
            raise ValueError(f"No TP match available for FP alert {fp.get('alert_id')}")
        selected_tp.append(match)
        selected_ids.add(str(match.get("alert_id")))
        match_quality[quality] += 1

    selected = sorted(false_positives + selected_tp, key=_sort_key)
    ids = [str(record.get("alert_id")) for record in selected]
    if len(ids) != len(set(ids)):
        raise ValueError("Pilot contains duplicate alert IDs")

    manifest = {
        "design": "all_fp_plus_one_matched_tp_per_fp",
        "records": len(selected),
        "labels": dict(Counter(_label(record) for record in selected)),
        "per_cwe": {
            cwe: dict(
                Counter(_label(record) for record in selected if _cwe(record) == cwe)
            )
            for cwe in sorted({_cwe(record) for record in selected})
        },
        "tp_match_quality": dict(match_quality),
        "population_records": len(records),
        "population_fp": len(false_positives),
        "note": (
            "Balanced pilot metrics are diagnostic. Population precision and final external "
            "validation metrics must be computed on the full Juliet alert set."
        ),
    }
    return selected, manifest


def _take_unused(
    candidates: deque[dict[str, Any]], selected_ids: set[str]
) -> dict[str, Any] | None:
    while candidates:
        candidate = candidates.popleft()
        if str(candidate.get("alert_id")) not in selected_ids:
            return candidate
    return None


def _label(record: dict[str, Any]) -> str:
    return str(record.get("ground_truth", {}).get("alert_label", "UNKNOWN"))


def _cwe(record: dict[str, Any]) -> str:
    return str(record.get("alert_contract", {}).get("cwe", "UNKNOWN"))


def _family(record: dict[str, Any]) -> str:
    return str(record.get("ground_truth", {}).get("benchmark_test", "UNKNOWN"))


def _sort_key(record: dict[str, Any]) -> tuple[str, str, str, int, int]:
    location = record.get("alert_contract", {}).get("primary_location", {})
    return (
        _cwe(record),
        _family(record),
        str(location.get("file") or ""),
        int(location.get("start_line") or 0),
        int(location.get("start_column") or 0),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the balanced Juliet FPM pilot.")
    parser.add_argument(
        "--input", default="data/interim/juliet-target-evidence.labeled.jsonl"
    )
    parser.add_argument("--out", default="data/interim/juliet-pilot-204.jsonl")
    parser.add_argument("--manifest", default="data/interim/juliet-pilot-204.manifest.json")
    args = parser.parse_args()

    selected, manifest = build_pilot(read_jsonl(args.input))
    write_jsonl(args.out, selected)
    write_json(args.manifest, manifest)
    print(f"wrote {len(selected)} pilot records to {Path(args.out)}")
    print(f"wrote pilot manifest to {Path(args.manifest)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
