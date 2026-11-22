"""Auditable bounded runner used by the revised experimental protocol."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from .authorization import POLICY_VERSION, authorization, canonical_hash, establish_facts, location
from .codeql import execute_template_query, database_fingerprint
from .batch_codeql import execute_batched_template_queries
from .llm import DeepSeekClient, LLMInfrastructureError
from .query_templates import allowed_templates_for_llm, find_template
from .cwe_profiles import profile_for
from .revision_prompts import messages, normalize

SEQUENCES = {
    "CWE-089": ["find-bound-constant-value", "find-sql-parameterization", "find-bound-fixed-sink"],
    "CWE-079": ["find-bound-fixed-sink", "find-bound-constant-value", "find-xss-encoder-nearby"],
    "CWE-078": ["find-bound-fixed-sink", "find-bound-constant-value", "find-command-execution-arguments"],
    "CWE-022": ["find-bound-fixed-sink", "find-bound-constant-value", "find-path-canonical-guard"],
    "CWE-090": ["find-bound-fixed-sink", "find-bound-constant-value", "find-sanitizer-on-path"],
    "CWE-643": ["find-bound-fixed-sink", "find-bound-constant-value", "find-sanitizer-on-path"],
    "CWE-327": ["find-crypto-algorithm"], "CWE-330": ["find-bound-randomness", "find-randomness-source"],
    "CWE-501": ["find-bound-trust-transfer", "find-session-attribute-origin"],
    "CWE-614": ["find-bound-cookie", "find-cookie-secure-flag"],
}


def applicable_actions(manifest: dict, cwe: str, language: str) -> list[dict]:
    category = profile_for(cwe).get("category")
    specific = {tid for seq in SEQUENCES.values() for tid in seq}
    ids = {t["id"] for t in manifest.get("templates", [])
           if t.get("enabled", True) and t.get("language", "java") == language
           and (not t.get("cwe_categories") or cwe in t["cwe_categories"] or category in t["cwe_categories"])
           and (t["id"] not in specific or t["id"] in SEQUENCES.get(cwe, []))}
    return [a for a in allowed_templates_for_llm(manifest) if a["template_id"] in ids]


def select_action(evidence: dict, candidate: dict, actions: list[dict]) -> dict | None:
    available = {a["template_id"]: a for a in actions}
    used = {q.get("template_id") for q in evidence.get("query_history", [])}
    proposed = candidate.get("next_query", {}).get("template_id")
    cwe = evidence.get("alert_contract", {}).get("cwe")
    sequence = [proposed] + SEQUENCES.get(cwe, []) + [a['template_id'] for a in actions]
    file, line, column = location(evidence)
    for tid in sequence:
        if tid not in available or tid in used or not file or not line: continue
        values = {"file": file, "line": line, "column": column, "cwe": cwe}
        field = evidence.get("context_ambiguity", {}).get("field_name")
        if field: values["field_name"] = field
        required = available[tid].get("parameters", [])
        # All location and selector values come from the controller; raw model values ignored.
        if any(k not in values or values[k] in (None, "", 0) for k in required): continue
        return {"template_id": tid, "parameters": {k: values[k] for k in required}}
    return None


def replay_action(evidence: dict, request: dict, archive: list[dict]) -> dict:
    """Only exact action/parameter records can answer a replay request."""
    for item in archive:
        if (item.get("alert_id") == evidence.get("alert_id") and
            item.get("template_id") == request["template_id"] and
            item.get("parameters") == request["parameters"] and
            item.get("status") == "ok" and item.get("producer") == "codeql-v2" and
            item.get("provenance", {}).get("parameters_hash") == canonical_hash(request["parameters"])):
            r = copy.deepcopy(item)
            r["producer"] = "verified-replay-v2"
            r["replay_source_hash"] = canonical_hash(item)
            return r
    return {**request, "status": "unavailable", "reason": "no_exact_archived_action"}


def triage_record(record: dict, *, client: Any, manifest: dict, cfg: dict,
                  method: str = "queryfpm", budget: int = 2, guidance: bool = True,
                  prefetch: bool = False, query_executor=None, replay: list[dict] | None = None,
                  fp_policy=None, tp_policy=None) -> dict:
    if budget not in {0, 1, 2, 3}: raise ValueError("budget must be 0/1/2/3")
    if fp_policy is not None and method != "queryfpm":
        raise ValueError("The optional FP policy applies only to method=queryfpm")
    if (cfg.get("fp_policy") or {}).get("mode") == "source_location_unverified" and fp_policy is None:
        raise ValueError("Explicit FP configuration requires its frozen runtime policy")
    if tp_policy is not None:
        if method != "queryfpm":
            raise ValueError("The optional TP policy applies only to method=queryfpm")
        tp_policy.validate_input(record)
    if (cfg.get("tp_policy") or {}).get("mode") == "semantic_tp_v2_1" and tp_policy is None:
        raise ValueError("Explicit TP configuration requires its frozen runtime policy")
    e = copy.deepcopy(record)
    # New runs never inherit model output, trusted facts or successful action history.
    for k in ("decision", "authorization", "backend_facts", "llm_trace", "query_history", "supplemental_evidence"):
        e.pop(k, None)
    e["query_history"], e["llm_trace"], e["backend_facts"] = [], [], []
    e["policy_version"] = POLICY_VERSION
    e["evidence_slots"] = {k: (v if k in {"call_context_required"} else "unknown")
                           for k, v in e.get("evidence_slots", {}).items()}
    language = cfg.get("language", "java")
    actions = applicable_actions(manifest, e.get("alert_contract", {}).get("cwe"), language)
    started = time.perf_counter()
    usage_total = {}
    infra_errors = []

    def decision_gate(candidate, *, confirmed_action_exhaustion=False):
        if fp_policy is not None and candidate["verdict"] == "FP":
            return fp_policy.evaluate(e, candidate, infrastructure_errors=infra_errors)
        if tp_policy is not None and candidate["verdict"] == "TP":
            return tp_policy.evaluate(e, candidate, infrastructure_errors=infra_errors,
                query_budget=budget, confirmed_action_exhaustion=confirmed_action_exhaustion)
        return authorization(e, candidate["verdict"])

    def execute(request):
        start = time.perf_counter()
        if replay is not None:
            result = replay_action(e, request, replay)
        elif query_executor is not None:
            result = query_executor(e, request)
        elif not cfg.get("database"):
            result = {**request, "status": "unavailable", "reason": "no_database"}
        else:
            try:
                if cfg.get('query_cache_dir'):
                    def invoke_batch():
                        result_set, _ = execute_batched_template_queries(
                            requests=[{'request_id': e['alert_id'], **request}],
                            codeql_bin=cfg['codeql_bin'], database=cfg['database'], manifest=manifest,
                            template_root=cfg['template_root'], cache_dir=cfg['query_cache_dir'],
                            additional_packs_root=cfg.get('additional_packs_root'))
                        return result_set[e['alert_id']]
                    mutex = cfg.get('_query_mutex')
                    if mutex is None:
                        result = invoke_batch()
                    else:
                        with mutex:
                            result = invoke_batch()
                else:
                    result = execute_template_query(
                    codeql_bin=cfg["codeql_bin"], database=cfg["database"], manifest=manifest,
                    template_id=request["template_id"], parameters=request["parameters"],
                    template_root=cfg["template_root"], output_dir=cfg["query_output_dir"],
                    additional_packs_root=cfg.get("additional_packs_root"))
            except (OSError, ValueError, KeyError) as exc:
                result = {**request, "status": "failed", "error_type": type(exc).__name__}
        result = {**request, **result, "runtime_seconds": time.perf_counter() - start}
        e["query_history"].append(result)
        e.setdefault("supplemental_evidence", []).append(result)
        establish_facts(e, result)
        if result.get("status") == "failed": infra_errors.append("codeql_failure")
        return result

    if prefetch:
        for _ in range(budget):
            req = select_action(e, {}, actions)
            if not req: break
            if execute(req).get("status") != "ok": break
    candidate = normalize(None)
    stop_reason = "budget_exhausted"
    tp_actions_exhausted = False
    rounds = 1 if method != "queryfpm" or prefetch else budget + 1
    for round_id in range(rounds):
        prompt = messages(e, actions, guidance=guidance, method=method,
                          view=cfg.get("view", "zerofalse"),max_chars=cfg.get("max_input_chars",40000))
        llm_start = time.perf_counter()
        try:
            raw, usage = client.chat_json(prompt, temperature=cfg.get("temperature", 0),
                                         max_tokens=cfg.get("max_output_tokens", 4096))
            candidate = normalize(raw)
        except LLMInfrastructureError as exc:
            raw, usage, candidate = {"error_type": exc.error_type}, exc.usage, normalize(None)
            infra_errors.append("llm_failure")
        if "MALFORMED_LLM_OUTPUT" in candidate["missing_evidence"]: infra_errors.append("malformed_output")
        for k, v in usage.items():
            if isinstance(v, int): usage_total[k] = usage_total.get(k, 0) + v
        gate = decision_gate(candidate)
        final = candidate["sufficient"] and gate["authorized"]
        e["llm_trace"].append({"round": round_id + 1, "messages": prompt,
            "prompt_hash": canonical_hash(prompt), "raw_response": raw, "candidate": candidate,
            "gate": gate, "controller_final": final, "usage": usage,
            "runtime_seconds": time.perf_counter() - llm_start,
            "query_count": len(e["query_history"])})
        if method != "queryfpm" or final or infra_errors or prefetch:
            stop_reason = ("infrastructure_failure" if infra_errors else "authorized_verdict" if final
                           else "fixed_prefetch_complete" if prefetch else "one_shot_complete")
            break
        if len(e["query_history"]) >= budget: break
        request = select_action(e, candidate, actions)
        if request is None:
            stop_reason = "no_executable_action"
            if (tp_policy is not None and candidate["verdict"] == "TP"
                    and gate.get("reason") == "tp_wait_for_evidence" and not infra_errors):
                after_exhaustion = decision_gate(candidate, confirmed_action_exhaustion=True)
                if candidate["sufficient"] and after_exhaustion["authorized"]:
                    e["llm_trace"][-1]["gate_before_action_exhaustion"] = gate
                    e["llm_trace"][-1]["gate"] = after_exhaustion
                    e["llm_trace"][-1]["controller_final"] = True
                    e["llm_trace"][-1]["tp_actions_exhausted"] = True
                    tp_actions_exhausted = True
                    stop_reason = "tp_evidence_actions_exhausted"
            break
        status = execute(request).get("status")
        if status != "ok":
            stop_reason = "action_unavailable" if status == "unavailable" else "infrastructure_failure"
            break
    gate = decision_gate(candidate, confirmed_action_exhaustion=tp_actions_exhausted)
    e["candidate_decision"] = candidate
    e["authorization"] = gate
    if infra_errors:
        e["decision"] = {"verdict": "INFRA_ERROR", "sufficient": False}
    elif method != "queryfpm":
        e["decision"] = {**candidate, "verdict": candidate["verdict"] if candidate["sufficient"] else "UNKNOWN"}
    elif candidate["sufficient"] and gate["authorized"]:
        if tp_policy is not None and candidate["verdict"] == "TP" and gate.get("gate_policy") == tp_policy.gate_version:
            e["decision"] = {**candidate, "verification": gate["verification"]}
            e["tp_reporting"] = {"status": gate["verification"], "gate_policy": tp_policy.gate_version,
                "route": gate.get("route"), "original_gate": copy.deepcopy(gate.get("original_gate")),
                "security_operation": "KEEP", "interpretation":
                "TP classification based on model and static evidence; vulnerability not independently proven."}
        else:
            e["decision"] = candidate
    else:
        e["decision"] = {**candidate, "verdict": "UNKNOWN", "sufficient": False,
                         "retention_reason": gate["reason"]}
    e["operation"] = "SUPPRESS" if e["decision"]["verdict"] == "FP" else "KEEP"
    e["infrastructure_errors"] = infra_errors
    e["stop_reason"] = stop_reason
    e["llm_usage_total"] = usage_total
    e["runtime_seconds"] = time.perf_counter() - started
    e["experiment_condition"] = {"method": method, "budget": budget, "guidance": guidance,
                                  "prefetch": prefetch, "language": language}
    if fp_policy is not None:
        e["fp_policy"] = fp_policy.metadata()
        if gate.get("verification") == "unverified_high_recall":
            e["decision"]["verification"] = gate["verification"]
            e["decision"]["safety_proven"] = False
    if tp_policy is not None:
        e["tp_policy"] = tp_policy.metadata()
    return e


def make_client(cfg: dict) -> DeepSeekClient:
    llm = cfg["llm"]
    key = os.environ.get(llm["api_key_env"])
    if not key: raise RuntimeError("Configured model credential environment variable is unset")
    return DeepSeekClient(api_key=key, base_url=llm["base_url"], model=llm["model"],
                          timeout=llm.get("timeout_seconds", 120), max_retries=llm.get("max_retries", 3),
                          thinking=llm.get('thinking'), capture_response_metadata=True,
                          use_environment_proxy=llm.get('use_environment_proxy', True))
