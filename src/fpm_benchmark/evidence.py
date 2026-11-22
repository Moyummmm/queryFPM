from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .cwe_profiles import default_slots, profile_for


_STATIC_FIELD_DECLARATION = re.compile(
    r"\b(?:(?:public|protected|private)\s+)?static\s+"
    r"[A-Za-z_$][\w$]*(?:\s*<[^;=]+>)?(?:\s*\[\s*\])?\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?:=[^;]*)?;"
)


def read_source_line(source_root: str | Path | None, uri: str | None, line: int | None) -> str | None:
    if not source_root or not uri or not line:
        return None
    path = Path(source_root) / uri
    if not path.exists():
        path = Path(uri)
    if not path.exists() or not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return None


def read_source_without_comments(
    source_root: str | Path | None,
    uri: str | None,
    *,
    max_chars: int = 20_000,
) -> str | None:
    if not source_root or not uri:
        return None
    path = Path(source_root) / uri
    if not path.exists():
        path = Path(uri)
    if not path.exists() or not path.is_file():
        return None
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    cleaned = strip_java_comments(source)
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[:max_chars] + "\n...[source truncated]"


def strip_java_comments(source: str) -> str:
    output: list[str] = []
    state = "code"
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if char == '"':
                state = "string"
                output.append(char)
            elif char == "'":
                state = "char"
                output.append(char)
            elif char == "/" and next_char == "/":
                state = "line_comment"
                output.extend("  ")
                index += 1
            elif char == "/" and next_char == "*":
                state = "block_comment"
                output.extend("  ")
                index += 1
            else:
                output.append(char)
        elif state == "line_comment":
            if char == "\n":
                state = "code"
                output.append(char)
            else:
                output.append(" ")
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                state = "code"
                output.extend("  ")
                index += 1
            elif char == "\n":
                output.append(char)
            else:
                output.append(" ")
        else:
            output.append(char)
            if char == "\\" and index + 1 < len(source):
                index += 1
                output.append(source[index])
            elif state == "string" and char == '"':
                state = "code"
            elif state == "char" and char == "'":
                state = "code"
        index += 1
    return "".join(output)


def build_evidence_slots(cwe: str | None, trace: list[dict[str, Any]]) -> dict[str, str]:
    profile = profile_for(cwe)
    slots = default_slots(profile["category"])
    if profile["category"] == "source_sink":
        if trace:
            slots["source_identified"] = "yes"
            slots["sink_identified"] = "yes"
            slots["sink_dangerous"] = "yes"
        if len(trace) >= 2:
            slots["path_exists"] = "yes"
            if trace[0].get("role") == "SOURCE_CANDIDATE":
                slots["source_user_controlled"] = "yes"
    elif profile["category"] == "api_misuse":
        if trace:
            slots["api_identified"] = "yes"
    elif profile["category"] == "security_config":
        if trace:
            slots["cookie_created"] = "yes"
            slots["secure_flag_checked"] = "unknown"
    elif profile["category"] == "trust_boundary":
        if trace:
            slots["source_identified"] = "yes"
        if len(trace) >= 2 and trace[0].get("role") == "SOURCE_CANDIDATE":
            slots["source_user_controlled"] = "yes"
            slots["trust_boundary_crossing"] = "yes"
    return slots


def detect_cross_context_field_ambiguity(evidence: dict[str, Any]) -> dict[str, Any] | None:
    """Detect a SARIF path that crosses files through an explicit static field.

    This is deliberately narrower than checking for any static token. A mutable
    field declaration embedded in a cross-file CodeQL trace is evidence that
    path construction may have merged writes from different entry-call contexts.
    """
    cwe = evidence.get("alert_contract", {}).get("cwe")
    if profile_for(cwe).get("category") != "source_sink":
        return None
    trace = evidence.get("annotated_trace", [])
    files = {
        str(item.get("file") or item.get("uri"))
        for item in trace
        if item.get("file") or item.get("uri")
    }
    if len(files) < 2:
        return None
    field_names: list[str] = []
    declaration_steps: list[int] = []
    for item in trace:
        match = _STATIC_FIELD_DECLARATION.search(str(item.get("code") or ""))
        if not match:
            continue
        field_names.append(match.group("name"))
        if isinstance(item.get("step"), int):
            declaration_steps.append(item["step"])
    field_names = sorted(set(field_names))
    if len(field_names) != 1:
        return None
    return {
        "kind": "cross_file_static_field",
        "field_name": field_names[0],
        "trace_file_count": len(files),
        "declaration_steps": declaration_steps,
        "reason": (
            "The SARIF path crosses files through a static field. Source and sink must be "
            "aligned to the same caller before the path is treated as feasible."
        ),
    }


def enrich_core_evidence_slots(evidence: dict[str, Any]) -> None:
    """Backfill deterministic core facts for evidence generated by older import versions."""
    cwe = evidence.get("alert_contract", {}).get("cwe")
    inferred = build_evidence_slots(cwe, evidence.get("annotated_trace", []))
    slots = evidence.setdefault("evidence_slots", {})
    for name, value in inferred.items():
        if value == "yes" and slots.get(name) in {None, "unknown"}:
            slots[name] = "yes"
    evidence["missing_evidence"] = infer_missing_evidence(cwe, slots)
    ambiguity = detect_cross_context_field_ambiguity(evidence)
    if ambiguity:
        evidence["context_ambiguity"] = ambiguity
        slots["call_context_required"] = "yes"
        slots.setdefault("call_context_resolved", "unknown")
        if slots.get("call_context_resolved") != "yes":
            missing = evidence.setdefault("missing_evidence", [])
            if "MISSING_CALL_CONTEXT_ALIGNMENT" not in missing:
                missing.append("MISSING_CALL_CONTEXT_ALIGNMENT")


def infer_missing_evidence(cwe: str | None, slots: dict[str, str]) -> list[str]:
    profile = profile_for(cwe)
    missing: list[str] = []
    for slot in profile.get("sufficiency_checklist", []):
        if slots.get(slot) in {None, "unknown", "no"}:
            missing.append(slot_to_missing_type(slot))
    return missing


def slot_to_missing_type(slot: str) -> str:
    mapping = {
        "source_user_controlled": "MISSING_SOURCE_TRUST_LEVEL",
        "sink_dangerous": "MISSING_SINK_SEMANTICS",
        "path_exists": "MISSING_DATAFLOW_PATH",
        "sanitizer_present": "MISSING_SANITIZER_CHECK",
        "validator_present": "MISSING_VALIDATOR_OR_GUARD",
        "path_feasible": "MISSING_CONTROL_FLOW_FEASIBILITY",
        "sink_argument_origin": "MISSING_SINK_ARGUMENT_ORIGIN",
        "safe_api_usage": "MISSING_SAFE_API_USAGE_CHECK",
        "api_identified": "MISSING_API_CALL",
        "argument_extracted": "MISSING_API_ARGUMENT",
        "argument_is_constant": "MISSING_ARGUMENT_ORIGIN",
        "randomness_source_known": "MISSING_RANDOMNESS_SOURCE",
        "cookie_created": "MISSING_COOKIE_CREATION",
        "secure_flag_checked": "MISSING_COOKIE_SECURE_FLAG",
        "secure_flag_set": "MISSING_COOKIE_SECURE_FLAG",
        "trust_boundary_crossing": "MISSING_TRUST_BOUNDARY_TRANSFER",
    }
    return mapping.get(slot, f"MISSING_{slot.upper()}")


def compact_for_llm(evidence: dict[str, Any], view: str = "structured") -> dict[str, Any]:
    """Remove evaluation-only fields and keep the evidence contract compact."""

    blocked = {"ground_truth"}
    compact = {k: v for k, v in evidence.items() if k not in blocked}
    if "supplemental_evidence" in compact:
        compact["supplemental_evidence"] = compact_supplemental_evidence(
            evidence.get("supplemental_evidence", [])
        )
    if view == "raw-sarif":
        compact = {
            "alert_id": evidence.get("alert_id"),
            "alert_contract": evidence.get("alert_contract"),
            "annotated_trace": evidence.get("annotated_trace"),
            "code_context": evidence.get("code_context"),
        }
    elif view == "direct":
        compact = {
            "alert_id": evidence.get("alert_id"),
            "alert": evidence.get("alert_contract"),
            "local_code": {
                "primary_snippet": evidence.get("code_context", {}).get("primary_snippet"),
                "surrounding_context": evidence.get("code_context", {}).get("surrounding_context"),
                "local_code": evidence.get("code_context", {}).get("local_code"),
            },
        }
    elif view == "llm4sa":
        compact = {
            "alert_id": evidence.get("alert_id"),
            "warning": evidence.get("alert_contract"),
            "related_code": {
                "imports": evidence.get("code_context", {}).get("file_imports"),
                "vulnerability_snippet": evidence.get("code_context", {}).get(
                    "vulnerability_snippet"
                ),
                "surrounding_context": evidence.get("code_context", {}).get("surrounding_context"),
                "local_code": evidence.get("code_context", {}).get("local_code"),
            },
        }
    elif view == "zerofalse":
        compact = {
            "alert_id": evidence.get("alert_id"),
            "alert_contract": evidence.get("alert_contract"),
            "annotated_trace": evidence.get("annotated_trace"),
            "cwe_profile": evidence.get("cwe_profile"),
            "evidence_slots": evidence.get("evidence_slots"),
            "missing_evidence": evidence.get("missing_evidence"),
            "context_ambiguity": evidence.get("context_ambiguity"),
            "query_history": compact_query_history(evidence.get("query_history", [])),
            "supplemental_evidence": compact_supplemental_evidence(
                evidence.get("supplemental_evidence", [])
            ),
            "code_context": evidence.get("code_context"),
        }
    elif view == "source-chain":
        context = evidence.get("code_context", {})
        contract = dict(evidence.get("alert_contract", {}))
        primary_location = dict(contract.get("primary_location", {}))
        primary_location["code"] = strip_java_comments(str(primary_location.get("code") or ""))
        contract["primary_location"] = primary_location
        trace = []
        for item in evidence.get("annotated_trace", []):
            cleaned_item = dict(item)
            cleaned_item["code"] = strip_java_comments(str(cleaned_item.get("code") or ""))
            trace.append(cleaned_item)
        compact = {
            "alert_id": evidence.get("alert_id"),
            "alert_contract": contract,
            "annotated_trace": trace,
            "cwe_profile": evidence.get("cwe_profile"),
            "code_context": {
                "primary_snippet": strip_java_comments(
                    str(context.get("primary_snippet") or "")
                ),
                "related_source_no_comments": context.get("related_source_no_comments"),
            },
        }
    elif view == "query-centered":
        compact = compact_for_llm(evidence, view="source-chain")
        compact["query_history"] = compact_query_history(evidence.get("query_history", []))
        compact["supplemental_evidence"] = compact_supplemental_evidence(
            evidence.get("supplemental_evidence", [])
        )
    if evidence.get("dataset", {}).get("label_blind") is True:
        compact = redact_benchmark_label_tokens(compact, salt=str(evidence.get("alert_id", "")))
    trace = compact.get("annotated_trace") or []
    if len(trace) > 12:
        compact["annotated_trace"] = trace[:6] + [{"omitted_steps": len(trace) - 12}] + trace[-6:]
    return compact


_JULIET_COMPOUND_LABEL = re.compile(
    r"(?<![A-Za-z0-9])(?:good(?:(?:G2B|B2G)(?:Sink|Source)?|Sink|Source|\d+)|"
    r"bad(?:Sink|Source|Only)|bad\d+)(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)
_JULIET_CALL_LABEL = re.compile(r"\b(?:good|bad)(?=\s*\()", flags=re.IGNORECASE)
_JULIET_QUALIFIED_LABEL = re.compile(
    r"(?<=\.)(?:good|bad)(?=[^A-Za-z0-9_$]|$)", flags=re.IGNORECASE
)
_JULIET_SUFFIX_LABEL = re.compile(
    r"(?<=_)(?:good|bad)(?=(?:\.java)?(?:[^A-Za-z0-9]|$))",
    flags=re.IGNORECASE,
)


def redact_benchmark_label_tokens(value: Any, *, salt: str) -> Any:
    """Remove Juliet good/bad naming signals from the LLM-visible projection."""

    if isinstance(value, dict):
        return {
            key: redact_benchmark_label_tokens(item, salt=salt)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_benchmark_label_tokens(item, salt=salt) for item in value]
    if not isinstance(value, str):
        return value

    def alias(match: re.Match[str]) -> str:
        digest = hashlib.sha256(f"{salt}\0{match.group(0).lower()}".encode()).hexdigest()[:10]
        return f"caseSymbol_{digest}"

    value = _JULIET_COMPOUND_LABEL.sub(alias, value)
    value = _JULIET_CALL_LABEL.sub(alias, value)
    value = _JULIET_QUALIFIED_LABEL.sub(alias, value)
    return _JULIET_SUFFIX_LABEL.sub(alias, value)


def compact_query_history(history: list[dict[str, Any]], max_items: int = 6) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for item in history[-max_items:]:
        compact.append(
            {
                "iteration": item.get("iteration"),
                "template_id": item.get("template_id"),
                "parameters": item.get("parameters"),
                "status": item.get("status"),
                "reason": item.get("reason"),
                "error": _shorten(item.get("error")),
                "summary": item.get("summary"),
            }
        )
    return compact


def compact_supplemental_evidence(
    supplemental: list[dict[str, Any]], max_items: int = 6
) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for item in supplemental[-max_items:]:
        compact.append(
            {
                "template_id": item.get("template_id"),
                "status": item.get("status"),
                "parameters": item.get("parameters"),
                "summary": item.get("summary"),
                "error": _shorten(item.get("error")),
            }
        )
    return compact


def _shorten(value: object, limit: int = 600) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"
