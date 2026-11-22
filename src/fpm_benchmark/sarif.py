from __future__ import annotations

from pathlib import Path
from typing import Any

from .cwe_profiles import profile_for
from .evidence import (
    build_evidence_slots,
    infer_missing_evidence,
    read_source_line,
    read_source_without_comments,
)
from .ground_truth import attach_ground_truth, load_expected_results
from .utils import canonical_cwe, read_json, stable_id


def sarif_to_evidence(
    sarif_path: str | Path,
    expected_path: str | Path | None = None,
    source_root: str | Path | None = None,
    target_cwes: set[str] | None = None,
) -> list[dict[str, Any]]:
    sarif = read_json(sarif_path)
    expected = load_expected_results(expected_path) if expected_path else {}
    records: list[dict[str, Any]] = []

    for run_index, run in enumerate(sarif.get("runs", [])):
        rules = _rules_by_id(run)
        for result_index, result in enumerate(run.get("results", [])):
            rule_id = result.get("ruleId") or result.get("rule", {}).get("id")
            rule = rules.get(rule_id, {})
            cwe = _extract_cwe(result, rule)
            if target_cwes and cwe not in target_cwes:
                continue
            primary = _primary_location(result, source_root)
            trace = _annotated_trace(result, primary, source_root)
            profile = profile_for(cwe)
            slots = build_evidence_slots(cwe, trace)
            missing = infer_missing_evidence(cwe, slots)
            message = _message_text(result.get("message"))
            fingerprints = result.get("partialFingerprints", {})
            alert_id = stable_id(
                rule_id,
                cwe,
                primary.get("file"),
                primary.get("start_line"),
                primary.get("start_column"),
                primary.get("end_line"),
                primary.get("end_column"),
                fingerprints.get("primaryLocationLineHash"),
                fingerprints.get("primaryLocationStartColumnFingerprint"),
                message,
            )

            evidence = {
                "alert_id": alert_id,
                "alert_contract": {
                    "tool": "CodeQL",
                    "rule_id": rule_id,
                    "cwe": cwe,
                    "message": message,
                    "severity": _severity(rule),
                    "primary_location": primary,
                    "rule": {
                        "name": rule.get("name"),
                        "short_description": _message_text(rule.get("shortDescription")),
                        "full_description": _message_text(rule.get("fullDescription")),
                    },
                    "sarif_indices": {"run": run_index, "result": result_index},
                    "sarif_fingerprints": fingerprints,
                },
                "cwe_profile": profile,
                "annotated_trace": trace,
                "code_context": {
                    "source_root": str(source_root) if source_root else None,
                    "primary_snippet": primary.get("code"),
                    "related_source_no_comments": read_source_without_comments(
                        source_root, primary.get("file")
                    ),
                },
                "evidence_slots": slots,
                "missing_evidence": missing,
                "query_history": [],
                "decision": {"verdict": "UNDECIDED", "confidence": "low"},
                "provenance": [
                    {
                        "fact": "initial_alert",
                        "source": "sarif",
                        "sarif_result_index": result_index,
                        "confidence": "high",
                    }
                ],
            }
            if expected:
                evidence = attach_ground_truth(evidence, expected)
            records.append(evidence)
    return records


def normalized_alerts_to_evidence(
    normalized_path: str | Path,
    expected_path: str | Path | None = None,
    source_root: str | Path | None = None,
    target_cwes: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Import canonical/normalized OWASP alerts into the same evidence schema.

    This is useful for pilot experiments when the original SARIF is unavailable
    but a normalized CodeQL-like alert file already exists.
    """

    expected = load_expected_results(expected_path) if expected_path else {}
    records: list[dict[str, Any]] = []
    with Path(normalized_path).open("r", encoding="utf-8") as f:
        for result_index, line in enumerate(f):
            if not line.strip():
                continue
            alert = read_json_line(line)
            cwe = canonical_cwe(alert.get("cwe"))
            if target_cwes and cwe not in target_cwes:
                continue
            alert_line = alert.get("alert_line")
            inferred_line = infer_alert_line(
                source_root,
                alert.get("alert_file"),
                alert_line,
                alert.get("sink") or alert.get("highlighted_line"),
                cwe,
            )
            primary_code = alert.get("highlighted_line") or alert.get("sink")
            if not primary_code:
                primary_code = read_source_line(source_root, alert.get("alert_file"), inferred_line)
            primary = {
                "file": alert.get("alert_file"),
                "uri": alert.get("alert_file"),
                "start_line": inferred_line,
                "start_column": None,
                "end_line": None,
                "end_column": None,
                "code": primary_code,
                "message": alert.get("alert_message"),
            }
            trace = _trace_from_normalized(alert, primary)
            profile = profile_for(cwe)
            slots = build_evidence_slots(cwe, trace)
            if alert.get("source"):
                slots["source_identified"] = "yes"
            if alert.get("sink"):
                if "sink_identified" in slots:
                    slots["sink_identified"] = "yes"
                if "sink_dangerous" in slots:
                    slots["sink_dangerous"] = "yes"
            if alert.get("source") and alert.get("sink") and "path_exists" in slots:
                slots["path_exists"] = "unknown"
            missing = infer_missing_evidence(cwe, slots)
            alert_id = stable_id(
                alert.get("sample_id"), alert.get("rule_id"), cwe, primary.get("file"), primary.get("start_line")
            )
            evidence = {
                "alert_id": alert_id,
                "alert_contract": {
                    "tool": "CodeQL-like normalized alert",
                    "rule_id": alert.get("rule_id"),
                    "cwe": cwe,
                    "message": alert.get("alert_message"),
                    "severity": None,
                    "primary_location": primary,
                    "rule": {
                        "name": alert.get("rule_id"),
                        "short_description": alert.get("alert_message"),
                        "full_description": None,
                    },
                    "sarif_indices": {"run": None, "result": result_index},
                },
                "cwe_profile": profile,
                "annotated_trace": trace,
                "code_context": {
                    "source_root": str(source_root) if source_root else None,
                    "primary_snippet": primary.get("code"),
                    "local_code": alert.get("local_code"),
                    "vulnerability_snippet": alert.get("vulnerability_snippet"),
                    "surrounding_context": alert.get("surrounding_context"),
                    "file_imports": alert.get("file_imports"),
                    "related_source_no_comments": read_source_without_comments(
                        source_root, primary.get("file")
                    ),
                },
                "evidence_slots": slots,
                "missing_evidence": missing,
                "query_history": [],
                "decision": {"verdict": "UNDECIDED", "confidence": "low"},
                "provenance": [
                    {
                        "fact": "normalized_alert",
                        "source": "normalized_alerts_jsonl",
                        "record_index": result_index,
                        "confidence": "medium",
                    }
                ],
            }
            if expected:
                evidence = attach_ground_truth(evidence, expected)
            records.append(evidence)
    return records


def read_json_line(line: str) -> dict[str, Any]:
    import json

    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object per line")
    return value


def infer_alert_line(
    source_root: str | Path | None,
    uri: str | None,
    alert_line: Any,
    sink_text: str | None,
    cwe: str | None,
) -> int | None:
    parsed = _to_int(alert_line)
    if parsed is not None:
        return parsed
    text_line = _line_from_highlight(sink_text)
    if text_line is not None:
        return text_line
    if not source_root or not uri:
        return None
    path = Path(source_root) / uri
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    if sink_text:
        needle = _normalize_code_text(sink_text)
        for index, line in enumerate(lines, start=1):
            if needle and needle in _normalize_code_text(line):
                return index

    patterns = _cwe_sink_patterns(cwe)
    for index, line in enumerate(lines, start=1):
        normalized = _normalize_code_text(line)
        if any(pattern in normalized for pattern in patterns):
            return index
    return None


def _to_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _line_from_highlight(value: str | None) -> int | None:
    if not value:
        return None
    import re

    match = re.search(r">>>\s*(\d+)\s*:", value)
    if not match:
        return None
    return int(match.group(1))


def _normalize_code_text(value: str | None) -> str:
    if not value:
        return ""
    import re

    value = re.sub(r">>>\s*\d+\s*:", "", value)
    return re.sub(r"\s+", "", value)


def _cwe_sink_patterns(cwe: str | None) -> list[str]:
    if cwe == "CWE-078":
        return [".exec(", "newProcessBuilder(", ".start("]
    if cwe == "CWE-022":
        return [
            "newFile(",
            "newjava.io.File(",
            "FileInputStream(",
            "newjava.io.FileInputStream(",
            "FileOutputStream(",
            "newjava.io.FileOutputStream(",
            "Files.",
            ".getCanonicalPath(",
        ]
    if cwe == "CWE-089":
        return [".execute(", ".executeQuery(", ".executeUpdate(", ".queryForList(", ".update("]
    if cwe == "CWE-079":
        return [".getWriter().print", ".getWriter().write", ".getWriter().printf"]
    return []


def _trace_from_normalized(alert: dict[str, Any], primary: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    if alert.get("source"):
        steps.append(
            {
                "step": 1,
                "role": "SOURCE_CANDIDATE",
                "file": alert.get("alert_file"),
                "uri": alert.get("alert_file"),
                "start_line": None,
                "start_column": None,
                "code": alert.get("source"),
                "message": "normalized source expression",
                "sarif_message": "normalized source expression",
                "semantic_tag": "user_input_candidate",
                "confidence": "medium",
                "provenance": "normalized_alert.source",
            }
        )
    sink_line = alert.get("alert_line")
    if alert.get("sink") or primary:
        steps.append(
            {
                "step": len(steps) + 1,
                "role": "SINK_CANDIDATE" if len(steps) else "ALERT_LOCATION",
                "file": alert.get("alert_file"),
                "uri": alert.get("alert_file"),
                "start_line": sink_line,
                "start_column": None,
                "code": alert.get("sink") or primary.get("code"),
                "message": "normalized sink expression",
                "sarif_message": "normalized sink expression",
                "semantic_tag": _semantic_tag({"code": alert.get("sink") or primary.get("code")}),
                "confidence": "medium",
                "provenance": "normalized_alert.sink",
            }
        )
    return steps


def _rules_by_id(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    driver = run.get("tool", {}).get("driver", {})
    for rule in driver.get("rules", []):
        if rule.get("id"):
            rules[rule["id"]] = rule
    for extension in run.get("tool", {}).get("extensions", []):
        for rule in extension.get("rules", []):
            if rule.get("id"):
                rules[rule["id"]] = rule
    return rules


def _extract_cwe(result: dict[str, Any], rule: dict[str, Any]) -> str | None:
    candidates: list[Any] = []
    for obj in (result, rule):
        props = obj.get("properties", {}) if isinstance(obj, dict) else {}
        candidates.extend(props.get("tags", []) or [])
        candidates.extend(props.get("security-severity", []) if isinstance(props.get("security-severity"), list) else [])
        candidates.append(props.get("cwe"))
    for rel in rule.get("relationships", []) or []:
        candidates.append(rel.get("target", {}).get("id"))
        candidates.append(rel.get("target", {}).get("guid"))
    for candidate in candidates:
        cwe = canonical_cwe(candidate)
        if cwe:
            return cwe
    return None


def _message_text(message: Any) -> str | None:
    if isinstance(message, dict):
        return message.get("text") or message.get("markdown")
    if message is None:
        return None
    return str(message)


def _severity(rule: dict[str, Any]) -> str | None:
    props = rule.get("properties", {})
    return props.get("problem.severity") or props.get("precision") or rule.get("defaultConfiguration", {}).get(
        "level"
    )


def _primary_location(result: dict[str, Any], source_root: str | Path | None) -> dict[str, Any]:
    locations = result.get("locations") or []
    if not locations:
        return {}
    return _location_to_dict(locations[0], source_root)


def _location_to_dict(location: dict[str, Any], source_root: str | Path | None) -> dict[str, Any]:
    physical = location.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    uri = artifact.get("uri")
    line = region.get("startLine")
    code = None
    snippet = region.get("snippet", {})
    if isinstance(snippet, dict):
        code = snippet.get("text")
    code = code or read_source_line(source_root, uri, line)
    return {
        "file": uri,
        "uri": uri,
        "start_line": line,
        "start_column": region.get("startColumn"),
        "end_line": region.get("endLine"),
        "end_column": region.get("endColumn"),
        "code": code,
        "message": _message_text(location.get("message")),
    }


def _annotated_trace(
    result: dict[str, Any], primary: dict[str, Any], source_root: str | Path | None
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for code_flow in result.get("codeFlows", []) or []:
        for thread_flow in code_flow.get("threadFlows", []) or []:
            for loc in thread_flow.get("locations", []) or []:
                location = loc.get("location", loc)
                step = _location_to_dict(location, source_root)
                step["sarif_message"] = _message_text(location.get("message")) or _message_text(
                    loc.get("message")
                )
                step["provenance"] = "sarif.codeFlows"
                steps.append(step)
    if not steps and primary:
        step = dict(primary)
        step["sarif_message"] = primary.get("message")
        step["provenance"] = "sarif.locations"
        steps.append(step)

    for index, step in enumerate(steps, start=1):
        step["step"] = index
        if len(steps) == 1:
            step["role"] = "ALERT_LOCATION"
        elif index == 1:
            step["role"] = "SOURCE_CANDIDATE"
        elif index == len(steps):
            step["role"] = "SINK_CANDIDATE"
        else:
            step["role"] = "PROPAGATION"
        step["semantic_tag"] = _semantic_tag(step)
        step["confidence"] = "medium" if step["role"].endswith("CANDIDATE") else "low"
    return steps


def _semantic_tag(step: dict[str, Any]) -> str:
    text = " ".join(str(step.get(k) or "") for k in ("code", "sarif_message")).lower()
    if any(x in text for x in ["getparameter", "getheader", "getcookies", "request."]):
        return "user_input_candidate"
    if any(x in text for x in ["executequery", "executeupdate", "preparestatement", "statement.execute"]):
        return "sql_sink_candidate"
    if any(x in text for x in ["runtime.getruntime", "processbuilder"]):
        return "command_sink_candidate"
    if any(x in text for x in ["print", "write", "getwriter"]):
        return "response_sink_candidate"
    if any(x in text for x in ["setsecure", "cookie"]):
        return "cookie_security_candidate"
    if any(x in text for x in ["messagedigest", "cipher.getinstance"]):
        return "crypto_api_candidate"
    if any(x in text for x in ["random", "securerandom"]):
        return "randomness_candidate"
    return "program_fact"
