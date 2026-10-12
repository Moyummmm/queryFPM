from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

from .codeql import _additional_packs, summarize_bqrs_json
from .authorization import canonical_hash
from .query_templates import find_template
from .utils import read_json, write_json

BATCH_ENGINE_VERSION = "explicit-bound-v3-db3"


def execute_batched_template_queries(
    *,
    requests: list[dict[str, Any]],
    codeql_bin: str,
    database: str | Path,
    manifest: dict[str, Any],
    template_root: str | Path,
    cache_dir: str | Path,
    additional_packs_root: str | Path | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    started = time.perf_counter()
    cache_dir = Path(cache_dir)
    results_dir = cache_dir / "results"
    batches_dir = cache_dir / "batches"
    results_dir.mkdir(parents=True, exist_ok=True)
    batches_dir.mkdir(parents=True, exist_ok=True)

    hash_started = time.perf_counter()
    database_hash = hash_codeql_database(database)
    database_hash_seconds = time.perf_counter() - hash_started

    results: dict[str, dict[str, Any]] = {}
    misses: list[dict[str, Any]] = []
    cache_hits = 0
    unique_requests = _deduplicate_requests(requests)
    for request in unique_requests:
        template = find_template(manifest, request["template_id"])
        if not template:
            results[request["request_id"]] = {
                "status": "failed",
                "template_id": request["template_id"],
                "parameters": request.get("parameters", {}),
                "error": "Unknown template",
                "cache_hit": False,
            }
            continue
        template_hash = hash_template(template, template_root)
        cache_key = query_cache_key(
            database_hash=database_hash,
            template_hash=template_hash,
            parameters=request.get("parameters", {}),
        )
        cache_path = results_dir / f"{cache_key}.json"
        request = dict(request)
        request["cache_key"] = cache_key
        request["cache_path"] = str(cache_path)
        request["template_hash"] = template_hash
        if cache_path.exists():
            cached = read_json(cache_path)
            cached["cache_hit"] = True
            results[request["request_id"]] = cached
            cache_hits += 1
        else:
            misses.append(request)

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for request in misses:
        params = request.get("parameters", {})
        spec = find_template(manifest, request["template_id"])
        typed = '"fpm-bound-v1"' in (Path(template_root)/spec["file"]).read_text(encoding="utf-8")
        excluded = {"file", "line", "column"} if typed else {"file", "line"}
        extra = {key: value for key, value in params.items() if key not in excluded}
        groups[(request["template_id"], _canonical_json(extra))].append(request)

    batch_reports: list[dict[str, Any]] = []
    for (template_id, _), group in groups.items():
        batch_started = time.perf_counter()
        batch_results, report = _execute_batch_group(
            requests=group,
            codeql_bin=codeql_bin,
            database=database,
            manifest=manifest,
            template_id=template_id,
            template_root=template_root,
            batches_dir=batches_dir,
            additional_packs_root=additional_packs_root,
        )
        report["wall_seconds"] = time.perf_counter() - batch_started
        batch_reports.append(report)
        for request in group:
            result = batch_results[request["request_id"]]
            result["cache_key"] = request["cache_key"]
            result["cache_hit"] = False
            results[request["request_id"]] = result
            if result.get("status") == "ok":
                write_json(request["cache_path"], result)

    expanded_results: dict[str, dict[str, Any]] = {}
    for request in requests:
        dedupe_id = _dedupe_id(request)
        source = results.get(dedupe_id) or results.get(request["request_id"])
        if source is None:
            source = {
                "status": "failed",
                "template_id": request["template_id"],
                "parameters": request.get("parameters", {}),
                "error": "Batch executor did not produce a result",
                "cache_hit": False,
            }
        expanded_results[request["request_id"]] = dict(source)

    stats = {
        "database_hash": database_hash,
        "database_hash_seconds": database_hash_seconds,
        "requests": len(requests),
        "unique_requests": len(unique_requests),
        "cache_hits": cache_hits,
        "cache_misses": len(misses),
        "cache_hit_rate": cache_hits / len(unique_requests) if unique_requests else None,
        "batch_count": len(batch_reports),
        "batches": batch_reports,
        "wall_seconds": time.perf_counter() - started,
    }
    return expanded_results, stats


@lru_cache(maxsize=8)
def hash_codeql_database(database: str | Path) -> str:
    root = Path(database).resolve()
    digest = hashlib.sha256()
    digest.update(b"finalized-extraction-v3\0")
    included_roots = [
        root / "codeql-database.yml",
        root / "baseline-info.json",
        root / "src.zip",
        root / "db-java" / "semmlecode.dbscheme",
        root / "db-java" / "semmlecode.dbscheme.stats",
        root / "db-python" / "semmlecode.python.dbscheme",
        root / "db-python" / "semmlecode.python.dbscheme.stats",
    ]
    for path in included_roots:
        if path.is_file():
            _hash_file(digest, path, root)
    for default in [root / "db-java" / "default", root / "db-python" / "default"]:
        if default.exists():
            # Query evaluation creates default/strings pools and cache relations.
            # They are not extraction inputs and must not alter DB identity.
            paths=[p for p in default.iterdir() if p.is_file() and p.suffix in {".rel", ".meta"}]
            pools=default/"pools"
            if pools.exists():paths.extend(p for p in pools.rglob("*") if p.is_file())
            for path in sorted(paths):
                _hash_file(digest, path, root)
    return digest.hexdigest()


def hash_template(template: dict[str, Any], template_root: str | Path) -> str:
    path = Path(template_root) / template["file"]
    digest = hashlib.sha256()
    digest.update(BATCH_ENGINE_VERSION.encode("ascii"))
    digest.update(_canonical_json(template).encode("utf-8"))
    digest.update(path.read_bytes())
    return digest.hexdigest()


def query_cache_key(
    *,
    database_hash: str,
    template_hash: str,
    parameters: dict[str, Any],
) -> str:
    digest = hashlib.sha256()
    digest.update(database_hash.encode("ascii"))
    digest.update(template_hash.encode("ascii"))
    digest.update(_canonical_json(parameters).encode("utf-8"))
    return digest.hexdigest()


def render_batched_template(
    template: dict[str, Any],
    requests: list[dict[str, Any]],
    template_root: str | Path,
) -> tuple[str, tuple[int, int]]:
    path = Path(template_root) / template["file"]
    raw = path.read_text(encoding="utf-8")
    typed = '"fpm-bound-v1"' in raw
    if "{{file}}" not in raw or "{{line}}" not in raw:
        raise ValueError(f"Template {template['id']} is not a file/line batch template")

    before, after = _line_window(raw)
    extra = {
        key: value
        for key, value in requests[0].get("parameters", {}).items()
        if key not in ({"file", "line", "column"} if typed else {"file", "line"})
    }

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        if key == "file":
            return "targetFile"
        if key == "line":
            return "targetLine"
        if typed and key == "column":
            return "targetColumn"
        return json.dumps(extra.get(key, ""), ensure_ascii=False)

    text = re.sub(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", replace, raw)
    if typed:
        clauses = ["(targetFile = " + json.dumps(str(r["parameters"]["file"])) +
                   " and targetLine = " + str(int(r["parameters"]["line"])) +
                   " and targetColumn = " + str(int(r["parameters"]["column"])) + ")"
                   for r in requests]
        target_predicate = ("predicate batchTarget(string targetFile, int targetLine, int targetColumn) {\n"
                            + "\n or ".join(clauses) + "\n}\n")
    else:
        target_predicate = _target_predicate(requests)
    text = _insert_after_imports(text, target_predicate)

    marker = "predicate inWindow(Element e) {"
    if marker in text:
        start = text.index(marker)
        open_brace = text.index("{", start)
        close_brace = _matching_brace(text, open_brace)
        body = text[open_brace + 1 : close_brace].strip()
        replacement = (
            "predicate inWindow(Element e) {\n"
            "  exists(string targetFile, int targetLine |\n"
            "    batchTarget(targetFile, targetLine) and\n"
            f"    ({body})\n"
            "  )\n"
            "}"
        )
        text = text[:start] + replacement + text[close_brace + 1 :]
    elif typed:
        pos = text.rfind("\nfrom ") + len("\nfrom ")
        text = text[:pos] + "string targetFile, int targetLine, int targetColumn, " + text[pos:]
        pos = text.find("\nwhere ", pos) + len("\nwhere ")
        text = text[:pos] + "batchTarget(targetFile, targetLine, targetColumn) and\n  " + text[pos:]
    else:
        text = _wrap_top_level_where(text)

    if typed:
        text = text.replace('\nselect "fpm-bound-v1"', '\nselect targetFile, targetLine, "fpm-bound-v1"')
    else:
        text = _prepend_result_location(text)
    return text, (before, after)


def _execute_batch_group(
    *,
    requests: list[dict[str, Any]],
    codeql_bin: str,
    database: str | Path,
    manifest: dict[str, Any],
    template_id: str,
    template_root: str | Path,
    batches_dir: Path,
    additional_packs_root: str | Path | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    template = find_template(manifest, template_id)
    if not template:
        raise ValueError(f"Unknown template: {template_id}")
    try:
        rendered, (before, after) = render_batched_template(template, requests, template_root)
    except ValueError as exc:
        failed = {
            request["request_id"]: {
                "status": "failed",
                "template_id": template_id,
                "parameters": request.get("parameters", {}),
                "error": str(exc),
            }
            for request in requests
        }
        return failed, {
            "template_id": template_id,
            "request_count": len(requests),
            "status": "failed",
        }

    batch_hash = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    batch_dir = batches_dir / batch_hash
    batch_dir.mkdir(parents=True, exist_ok=True)
    (batch_dir / "qlpack.yml").write_text(
        'name: fpm/evidence-batch-query\n'
        'version: 0.0.0\n'
        'dependencies:\n'
        f'  codeql/{template.get("language", "java")}-all: "*"\n',
        encoding="utf-8",
    )
    query_path = batch_dir / f"{template_id}.ql"
    bqrs_path = batch_dir / f"{template_id}.bqrs"
    json_path = batch_dir / f"{template_id}.json"
    query_path.write_text(rendered, encoding="utf-8")

    command = [
        codeql_bin,
        "query",
        "run",
        str(query_path),
        "--database",
        str(database),
        "--output",
        str(bqrs_path),
        "--common-caches", str(batches_dir.parent / "codeql-common-cache"),
        "--threads", "4", "--ram", "4096",
        "--timeout", "600", "--evaluator-log", str(batch_dir / "evaluation.json"),
    ]
    additional_packs = _additional_packs(additional_packs_root)
    if additional_packs:
        command.extend(["--additional-packs", additional_packs])
    run = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if run.returncode != 0:
        return _failed_group(requests, template_id, run.stderr), {
            "template_id": template_id,
            "request_count": len(requests),
            "status": "failed",
            "error": run.stderr[-2000:],
        }

    decode = subprocess.run(
        [
            codeql_bin,
            "bqrs",
            "decode",
            str(bqrs_path),
            "--format",
            "json",
            "--output",
            str(json_path),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if decode.returncode != 0:
        return _failed_group(requests, template_id, decode.stderr), {
            "template_id": template_id,
            "request_count": len(requests),
            "status": "failed",
            "error": decode.stderr[-2000:],
        }

    data = json.loads(json_path.read_text(encoding="utf-8"))
    tuples = data.get("#select", {}).get("tuples", [])
    per_request_rows: dict[str, list[list[Any]]] = defaultdict(list)
    for row in tuples:
        if not isinstance(row, list) or len(row) < 3:
            continue
        evidence_file = str(row[0])
        try:
            evidence_line = int(row[1])
        except (TypeError, ValueError):
            continue
        original_row = row[2:]
        for request in requests:
            params = request.get("parameters", {})
            try:
                target_line = int(params.get("line"))
            except (TypeError, ValueError):
                continue
            if params.get("file") != evidence_file:
                continue
            if original_row and original_row[0] == "fpm-bound-v1" and original_row[5] != params.get("column"):
                continue
            if target_line - before <= evidence_line <= target_line + after:
                per_request_rows[request["request_id"]].append(original_row)

    results: dict[str, dict[str, Any]] = {}
    for request in requests:
        request_data = {"#select": {"tuples": per_request_rows[request["request_id"]],
                                   "columns": data.get("#select", {}).get("columns", [])[2:]}}
        results[request["request_id"]] = {
            "status": "ok",
            "producer": "codeql-v2",
            "provenance": {"database_hash": hash_codeql_database(database),
                           "template_hash": hash_template(template, template_root),
                           "parameters_hash": canonical_hash(request.get("parameters", {}))},
            "template_id": template_id,
            "parameters": request.get("parameters", {}),
            "batch_id": batch_hash,
            "batch_request_count": len(requests),
            "summary": summarize_bqrs_json(template_id, request_data),
            "result": request_data,
        }
    report = {
        "template_id": template_id,
        "request_count": len(requests),
        "status": "ok",
        "batch_id": batch_hash,
        "tuple_count": len(tuples),
        "window_before": before,
        "window_after": after,
    }
    return results, report


def _target_predicate(requests: list[dict[str, Any]]) -> str:
    clauses = []
    for request in requests:
        params = request.get("parameters", {})
        clauses.append(
            "(targetFile = "
            + json.dumps(str(params["file"]), ensure_ascii=False)
            + " and targetLine = "
            + str(int(params["line"]))
            + ")"
        )
    return (
        "predicate batchTarget(string targetFile, int targetLine) {\n  "
        + "\n  or ".join(clauses)
        + "\n}\n"
    )


def _insert_after_imports(text: str, declaration: str) -> str:
    matches = list(re.finditer(r"(?m)^import\s+[^\n]+\n", text))
    if not matches:
        return declaration + "\n" + text
    position = matches[-1].end()
    return text[:position] + "\n" + declaration + text[position:]


def _wrap_top_level_where(text: str) -> str:
    from_pos = text.rfind("\nfrom ")
    where_pos = text.find("\nwhere ", from_pos)
    select_pos = text.find("\nselect ", where_pos)
    if min(from_pos, where_pos, select_pos) < 0:
        raise ValueError("Could not locate top-level from/where/select query")
    body = text[where_pos + len("\nwhere ") : select_pos].strip()
    wrapped = (
        "\nwhere exists(string targetFile, int targetLine |\n"
        "  batchTarget(targetFile, targetLine) and\n"
        f"  ({body})\n"
        ")"
    )
    return text[:where_pos] + wrapped + text[select_pos:]


def _prepend_result_location(text: str) -> str:
    select_pos = text.rfind("\nselect ")
    if select_pos < 0:
        raise ValueError("Could not locate top-level select")
    expression_start = select_pos + len("\nselect ")
    comma = text.find(",", expression_start)
    if comma < 0:
        raise ValueError("Batch query select must begin with an entity followed by a comma")
    entity = text[expression_start:comma].strip()
    prefix = (
        "\nselect "
        + entity
        + ".getLocation().getFile().getRelativePath(), "
        + entity
        + ".getLocation().getStartLine(), "
    )
    return text[:select_pos] + prefix + text[expression_start:]


def _line_window(text: str) -> tuple[int, int]:
    # Certificate templates bind an exact point, including when that binding is
    # expressed through a materialized point predicate rather than '=' syntax.
    if '"fpm-bound-v1"' in text and "{{line}}" in text and "{{column}}" in text:
        if re.search(r"\{\{\s*line\s*\}\}\s*[+-]\s*\d+", text):
            raise ValueError("Authorizing certificate template must bind an exact point")
        return 0, 0
    before_values = [int(value) for value in re.findall(r"\{\{\s*line\s*\}\}\s*-\s*(\d+)", text)]
    after_values = [int(value) for value in re.findall(r"\{\{\s*line\s*\}\}\s*\+\s*(\d+)", text)]
    exact = bool(re.search(r"=\s*\{\{\s*line\s*\}\}", text))
    before = max(before_values, default=0)
    after = max(after_values, default=0)
    if not before_values and not after_values and not exact:
        raise ValueError("Could not determine template line window")
    return before, after


def _matching_brace(text: str, open_brace: int) -> int:
    depth = 0
    for index in range(open_brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("Unmatched predicate brace")


def _deduplicate_requests(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduplicated: dict[str, dict[str, Any]] = {}
    for request in requests:
        dedupe_id = _dedupe_id(request)
        if dedupe_id not in deduplicated:
            item = dict(request)
            item["request_id"] = dedupe_id
            deduplicated[dedupe_id] = item
    return list(deduplicated.values())


def _dedupe_id(request: dict[str, Any]) -> str:
    return request["template_id"] + ":" + _canonical_json(request.get("parameters", {}))


def _failed_group(
    requests: list[dict[str, Any]], template_id: str, error: str
) -> dict[str, dict[str, Any]]:
    return {
        request["request_id"]: {
            "status": "failed",
            "template_id": template_id,
            "parameters": request.get("parameters", {}),
            "error": error[-4000:],
        }
        for request in requests
    }


def _hash_file(digest: Any, path: Path, root: Path) -> None:
    digest.update(str(path.relative_to(root)).encode("utf-8"))
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
