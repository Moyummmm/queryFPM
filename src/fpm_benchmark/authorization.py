"""Versioned authorization over controller-owned, alert-bound analysis facts.

The serialized evidence store is trusted experiment input, never a model channel.
Natural-language messages, hit counts, confidence and model slots confer no authority.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

POLICY_VERSION = "explicit-bound-v3"
SCHEMA = "fpm-bound-v1"
FLOW_CWES = {"CWE-022", "CWE-078", "CWE-079", "CWE-089", "CWE-090", "CWE-643"}
CONSTANT_VALUE_ROUTES = ("container_list_value", "container_map_value",
                         "container_aggregate_value", "constant_branch_value")
ROUTES = {
    **{c: ("literal_sink_argument", "compile_time_sink_argument", *CONSTANT_VALUE_ROUTES,
           "safe_overwrite") for c in FLOW_CWES},
    "CWE-089": ("sql_parameterized", "literal_sink_argument", "compile_time_sink_argument",
                *CONSTANT_VALUE_ROUTES, "safe_overwrite"),
    "CWE-327": ("strong_crypto",),
    "CWE-330": ("secure_random",), "CWE-501": ("constant_trust_transfer",),
    "CWE-614": ("cookie_secure",),
}
EMITTERS = {
    "find-bound-literal-sink": {"literal_sink_argument": "literal-actual-argument-v1"},
    "find-bound-ldap-literal": {"literal_sink_argument": "literal-actual-argument-v1"},
    "find-bound-fixed-sink": {
        "compile_time_sink_argument": "compile-time-actual-argument-v1",
        "safe_overwrite": "unconditional-local-string-overwrite-v1"},
    "find-bound-constant-value": {
        "container_list_value": "container-list-slot-constant-v1",
        "container_map_value": "container-map-slot-constant-v1",
        "container_aggregate_value": "container-all-elements-constant-v1",
        "constant_branch_value": "constant-selector-branch-v1"},
    "find-sql-parameterization": {"sql_parameterized": "constant-sql-same-receiver-v1"},
    "find-crypto-algorithm": {"crypto_effective": "constant-actual-algorithm-v1"},
    "find-bound-randomness": {"secure_random": "direct-jdk-securerandom-v1"},
    "find-bound-trust-transfer": {"constant_trust_transfer": "literal-name-and-value-v1"},
    "find-bound-cookie": {"cookie_secure": "unescaped-local-cookie-secure-before-send-v1"},
}
SLOT_BY_ROUTE = {"literal_sink_argument": "literal_sink_argument",
    "compile_time_sink_argument": "compile_time_sink_argument", "safe_overwrite": "constant_overwrite",
    "container_list_value": "constant_value_certificate",
    "container_map_value": "constant_value_certificate",
    "container_aggregate_value": "constant_value_certificate",
    "constant_branch_value": "constant_value_certificate",
    "sql_parameterized": "safe_api_usage", "strong_crypto": "known_strong_algorithm",
    "secure_random": "secure_random", "constant_trust_transfer": "constant_trust_transfer",
    "cookie_secure": "secure_flag_set"}


def canonical_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":")).encode()).hexdigest()


def location(evidence: dict[str, Any]) -> tuple[str, int, int]:
    p = evidence.get("alert_contract", {}).get("primary_location", {})
    try:
        return (str(p.get("file") or p.get("uri") or "").replace("\\", "/"),
                int(p.get("start_line") or 0), int(p.get("start_column") or 0))
    except (TypeError, ValueError):
        return "", 0, 0


def classify_algorithm(value: str) -> str | None:
    v = value.strip().upper().replace("SHA-", "SHA")
    if v.split("/")[0] in {"DES", "DESEDE", "TRIPLEDES", "RC4", "RC2", "MD5", "SHA1"}:
        return "weak"
    if v in {"SHA256", "SHA384", "SHA512", "HMACSHA256", "HMACSHA384", "HMACSHA512", "AES/GCM/NOPADDING"}:
        return "strong"
    # AES alone leaves provider defaults unresolved; AES/ECB is not blanket safety.
    return None


def resolve_property_algorithm(*, key: str, configured: dict[str, str] | None,
                               default: str | None, resource_verified: bool) -> str | None:
    """Callers must establish the loaded resource/receiver and no later mutations."""
    if not resource_verified or configured is None:
        return None
    return configured.get(key, default)


def typed_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    names = ("schema", "kind", "cwe", "sink_file", "sink_line", "sink_column",
             "subject", "detail", "proof_rule")
    rows = result.get("result", {}).get("#select", {}).get("tuples", [])
    return [dict(zip(names, row)) for row in rows
            if isinstance(row, list) and len(row) == 9 and row[0] == SCHEMA]


def establish_facts(evidence: dict[str, Any], result: dict[str, Any]) -> list[dict[str, Any]]:
    if result.get("status") != "ok" or result.get("producer") not in {"codeql-v2", "verified-replay-v2"}:
        return []
    provenance = result.get("provenance", {})
    if not all(provenance.get(k) for k in ("database_hash", "template_hash", "parameters_hash")):
        return []
    expected_database=evidence.get("analysis_provenance",{}).get("database_hash")
    if expected_database and provenance["database_hash"] != expected_database:
        return []
    params = result.get("parameters", {})
    if provenance["parameters_hash"] != canonical_hash(params):
        return []
    file, line, column = location(evidence)
    if not file or not line or not column:
        return []  # Multiple expressions on one line require a column binding.
    if str(params.get("file", "")).replace("\\", "/") != file or params.get("line") != line:
        return []
    cwe = evidence.get("alert_contract", {}).get("cwe")
    tid = str(result.get("template_id", ""))
    rules = EMITTERS.get(tid, {})
    facts = []
    for row in typed_rows(result):
        if (row["cwe"] != cwe or row["kind"] not in rules or
                row["proof_rule"] != rules[row["kind"]] or
                str(row["sink_file"]).replace("\\", "/") != file or
                row["sink_line"] != line or row["sink_column"] != column):
            continue
        kind = row["kind"]
        if kind == "crypto_effective":
            cls = classify_algorithm(str(row["detail"]))
            if cls is None:
                continue
            kind = "strong_crypto" if cls == "strong" else "weak_crypto"
        f = {**row, "sink_file": file, "kind": kind, "alert_id": evidence.get("alert_id"),
             "template_id": tid, "provenance": dict(provenance)}
        f["fact_id"] = canonical_hash(f)
        facts.append(f)
    stored = evidence.setdefault("backend_facts", [])
    existing = {f.get("fact_id") for f in stored}
    for f in facts:
        if f["fact_id"] not in existing:
            stored.append(f)
            existing.add(f["fact_id"])
        slot = SLOT_BY_ROUTE.get(f["kind"])
        if slot:
            evidence.setdefault("evidence_slots", {})[slot] = "yes"
        if f["kind"] == "weak_crypto":
            evidence.setdefault("evidence_slots", {})["known_weak_api_or_algorithm"] = "yes"
    return facts


def verified_facts(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    valid = []
    for f in evidence.get("backend_facts", []):
        unsigned = {k: v for k, v in f.items() if k != "fact_id"}
        if f.get("fact_id") != canonical_hash(unsigned) or f.get("alert_id") != evidence.get("alert_id"):
            continue
        if (f.get("sink_file"), f.get("sink_line"), f.get("sink_column")) != location(evidence):
            continue
        if any(q.get("status") == "ok" and q.get("producer") in {"codeql-v2", "verified-replay-v2"}
               and q.get("template_id") == f.get("template_id")
               and q.get("provenance") == f.get("provenance")
               for q in evidence.get("query_history", [])):
            valid.append(f)
    return valid


def authorization(evidence: dict[str, Any], verdict: str) -> dict[str, Any]:
    facts = verified_facts(evidence)
    cwe = evidence.get("alert_contract", {}).get("cwe")
    slots = evidence.get("evidence_slots", {})
    base = {"policy_version": POLICY_VERSION, "authorized": False,
            "route": None, "fact_ids": [], "reason": "no_bound_safety_fact"}
    if cwe not in ROUTES:
        return {**base, "reason": "unsupported_cwe"}
    if any(v in {"error", "checked_error"} for v in slots.values()):
        return {**base, "reason": "evidence_error"}
    if slots.get("call_context_required") == "yes":
        return {**base, "reason": "shared_context_not_certified"}
    kinds = {f["kind"] for f in facts}
    if {"strong_crypto", "weak_crypto"} <= kinds:
        return {**base, "reason": "conflicting_facts"}
    if verdict == "TP":
        if cwe == "CWE-327" and "weak_crypto" in kinds:
            return {**base, "authorized": True, "route": "weak_crypto",
                    "fact_ids": [f["fact_id"] for f in facts if f["kind"] == "weak_crypto"],
                    "reason": "bound_weak_algorithm"}
        return {**base, "reason": "semantic_tp_unverified"}
    if verdict != "FP" or "weak_crypto" in kinds:
        return {**base, "reason": "not_safe_fp_candidate"}
    for route in ROUTES[cwe]:
        chosen = [f for f in facts if f["kind"] == route]
        if chosen:
            return {**base, "authorized": True, "route": route,
                    "fact_ids": [f["fact_id"] for f in chosen], "reason": "bound_safety_fact"}
    return base
