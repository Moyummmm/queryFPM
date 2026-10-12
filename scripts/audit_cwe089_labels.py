#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def classify(record: dict[str, Any]) -> tuple[str, list[str]]:
    source = str(record.get("code_context", {}).get("related_source_no_comments", ""))
    query_messages = "\n".join(
        str(fact.get("message", ""))
        for query in record.get("query_history", [])
        for fact in query.get("summary", {}).get("facts", [])
    )
    candidate = record.get("decision", {}).get("candidate_decision", record.get("decision", {}))
    reasons: list[str] = []

    if re.search(
        r"branch=then[^\n]*value_compile_time_constant=no[^\n]*result=true",
        query_messages,
    ) or re.search(
        r"branch=else[^\n]*value_compile_time_constant=no[^\n]*result=false",
        query_messages,
    ):
        reasons.append("query reports a feasible non-constant assignment reaching the sink variable")
        return "suspected_benchmark_semantic_conflict", reasons
    if candidate.get("verdict") == "FP":
        reasons.append("LLM produced a high-confidence FP candidate but the conservative gate rejected it")
        return "gate_lacks_path_bound_fp_proof", reasons
    if re.search(r"ThingFactory|createThing\s*\(", source):
        reasons.append("value origin depends on reflection/factory-selected implementation")
        return "missing_reflection_or_factory_semantics", reasons
    if re.search(r"\.(?:add|remove|get|put)\s*\(", source):
        reasons.append("value origin depends on ordered collection mutations")
        return "missing_collection_semantics", reasons
    if re.search(r"\bdoSomething\s*\(", source):
        reasons.append("sink value is returned through a helper or inner method")
        return "missing_interprocedural_return_origin", reasons
    reasons.append("current templates do not bind the reported assignment to the final SQL sink argument")
    return "missing_sink_bound_origin", reasons


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit disputed CWE-089 benchmark labels.")
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    records = [
        record
        for record in read_jsonl(Path(args.decisions))
        if record.get("alert_contract", {}).get("cwe") == "CWE-089"
        and record.get("ground_truth", {}).get("alert_label") == "FP"
        and record.get("decision", {}).get("verdict") != "FP"
    ]
    audited: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for record in sorted(records, key=lambda item: item["alert_id"]):
        category, reasons = classify(record)
        counts[category] += 1
        candidate = record.get("decision", {}).get("candidate_decision", record.get("decision", {}))
        audited.append(
            {
                "alert_id": record["alert_id"],
                "benchmark_test": record.get("ground_truth", {}).get("benchmark_test"),
                "benchmark_label": "FP",
                "pipeline_verdict": record.get("decision", {}).get("verdict"),
                "candidate_verdict": candidate.get("verdict"),
                "audit_category": category,
                "audit_status": "needs_manual_review",
                "reasons": reasons,
                "file": record.get("alert_contract", {}).get("primary_location", {}).get("file"),
                "line": record.get("alert_contract", {}).get("primary_location", {}).get("start_line"),
            }
        )

    report = {
        "scope": "CWE-089 benchmark-FP alerts not filtered by experiment-v1.3",
        "count": len(audited),
        "method": "heuristic triage only; categories require manual semantic adjudication",
        "category_counts": dict(sorted(counts.items())),
        "records": audited,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["category_counts"], ensure_ascii=False, indent=2))
    print(f"wrote {len(audited)} audit records to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
