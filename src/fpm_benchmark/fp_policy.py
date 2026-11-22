"""Explicit, unverified FP permission; never a replacement safety authority.

Source locations and successful queries establish input binding, not safety.
A wrong model FP proposal can suppress a true vulnerability in this mode.
The default authorization function and all non-FP branches remain unchanged.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType

from .authorization import ROUTES, authorization, canonical_hash, verified_facts
from .batch_codeql import hash_template
from .codeql import summarize_bqrs_json

VERSION = "source-location-unverified-v1"
REFERENCE_VERSION = "bound-fp-strict2-reference-v1"
MODE = "source_location_unverified"
STATIC_FIELDS = ("analysis_provenance", "alert_contract", "annotated_trace")
EVIDENCE_FIELDS = (*STATIC_FIELDS, "alert_id", "query_history", "backend_facts",
                   "evidence_slots", "infrastructure_errors")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _digest(value):
    data = json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def strict_fp_reference(evidence, verdict):
    """Strict2 reference only; never install this or the optional gate globally."""
    if verdict != "FP":
        return authorization(evidence, verdict)
    facts = evidence.get("backend_facts", [])
    excluded = {"find-bound-constant-value", "find-escaped-output"}
    view = {**evidence, "backend_facts": [f for f in facts if f.get("template_id") not in excluded]}
    result = authorization(view, verdict)
    result["policy_version"] = REFERENCE_VERSION
    if (not result["authorized"] and result["reason"] == "no_bound_safety_fact"
            and len(view["backend_facts"]) != len(facts)):
        result["reason"] = "certificate_context_not_established"
    return result


class FrozenSourceContext:
    """Controller-created per-alert contracts and source/query trust anchors.

    The opaque alert ID is an integrity lookup key, never a prediction feature.
    Only the three static fields enter the trusted contract; labels are excluded.
    """

    def __init__(self, *, source_root, source_manifest, template_manifest, trusted_alerts):
        self.source_root = Path(source_root).resolve(strict=True)
        self.source_manifest = Path(source_manifest).resolve(strict=True)
        self.template_manifest = Path(template_manifest).resolve(strict=True)
        if not self.source_root.is_dir() or not isinstance(trusted_alerts, dict) or not trusted_alerts:
            raise ValueError("A source directory and nonempty trusted input mapping are required")
        self.source_manifest_sha256 = _sha(self.source_manifest)
        self.template_manifest_sha256 = _sha(self.template_manifest)
        hashes = json.loads(self.source_manifest.read_text(encoding="utf-8"))["files"]
        if not isinstance(hashes, dict) or not hashes:
            raise ValueError("Source manifest must contain a nonempty files mapping")
        for name, digest in hashes.items():
            if (not isinstance(name, str) or not self._relative(name)
                    or not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
                raise ValueError("Invalid frozen source path/hash")
        self.source_hashes = MappingProxyType(copy.deepcopy(hashes))
        specs = json.loads(self.template_manifest.read_text(encoding="utf-8"))["templates"]
        self.specs = {s["id"]: copy.deepcopy(s) for s in specs}
        if len(self.specs) != len(specs):
            raise ValueError("Duplicate template IDs")
        self.template_hashes = {tid: hash_template(spec, self.template_manifest.parent)
                                for tid, spec in self.specs.items()}
        frozen, provenance = {}, set()
        for alert_id, original in copy.deepcopy(trusted_alerts).items():
            if (not isinstance(alert_id, str) or not alert_id or not isinstance(original, dict)
                    or set(original) != set(STATIC_FIELDS)):
                raise ValueError("Trusted entries require exactly three static fields, no labels")
            p = original["analysis_provenance"]
            if (not isinstance(p, dict) or p.get("language") != "java"
                    or not isinstance(original["alert_contract"], dict)
                    or not isinstance(original["annotated_trace"], list)):
                raise ValueError("This optional mode requires normalized Java input")
            pair = (p.get("database_hash"), p.get("sarif_sha256"))
            if any(not isinstance(v, str) or not _SHA256.fullmatch(v) for v in pair):
                raise ValueError("Frozen database and SARIF SHA256 values are required")
            provenance.add(pair)
            frozen[alert_id] = _digest(original)
        if len(provenance) != 1:
            raise ValueError("One frozen database/SARIF pair is required per run")
        self.database_hash, self.sarif_sha256 = next(iter(provenance))
        self._contracts = MappingProxyType(frozen)
        self._contracts_sha256 = _digest(frozen)

    @staticmethod
    def _relative(name):
        path = PurePosixPath(name)
        return (not path.is_absolute() and ".." not in path.parts
                and path.as_posix() == name and "\\" not in name and ":" not in name)

    def metadata(self):
        return {"source_manifest_sha256": self.source_manifest_sha256,
                "template_manifest_sha256": self.template_manifest_sha256,
                "database_hash": self.database_hash, "sarif_sha256": self.sarif_sha256,
                "trusted_alert_count": len(self._contracts),
                "trusted_alerts_sha256": self._contracts_sha256}

    def contract_ok(self, evidence):
        try:
            wanted = self._contracts.get(evidence.get("alert_id"))
            return wanted is not None and _digest({k: evidence[k] for k in STATIC_FIELDS}) == wanted
        except (KeyError, TypeError, ValueError):
            return False

    def located_source(self, evidence):
        if not self.contract_ok(evidence):
            return {"ok": False, "reason": "immutable_alert_contract_mismatch", "locations": []}
        output = []
        try:
            if _sha(self.source_manifest) != self.source_manifest_sha256:
                return {"ok": False, "reason": "source_manifest_changed", "locations": []}
            locations = [evidence["alert_contract"].get("primary_location", {})]
            locations += evidence["annotated_trace"]
            for loc in locations:
                if not isinstance(loc, dict):
                    raise ValueError("Invalid source location")
                name = loc.get("file") or loc.get("uri")
                first, column = loc.get("start_line"), loc.get("start_column")
                last, end_column = loc.get("end_line"), loc.get("end_column")
                if last is None:
                    last = first
                if (not isinstance(name, str) or not self._relative(name)
                        or any(type(v) is not int for v in (first, last, column))
                        or first < 1 or last < first or column < 1
                        or (end_column is not None and (type(end_column) is not int or end_column < 1))
                        or (last == first and end_column is not None and end_column < column)):
                    raise ValueError("Invalid source range")
                path = (self.source_root / name).resolve(strict=True)
                path.relative_to(self.source_root)
                raw, wanted = path.read_bytes(), self.source_hashes.get(name)
                if wanted is None or hashlib.sha256(raw).hexdigest() != wanted:
                    return {"ok": False, "reason": "source_hash_mismatch", "locations": output}
                lines = raw.decode("utf-8").splitlines()
                width = lambda value: len(value.encode("utf-16-le")) // 2 + 1
                if (last > len(lines) or column > width(lines[first - 1])
                        or (end_column is not None and end_column > width(lines[last - 1]))
                        or not any(line.strip() for line in lines[first - 1:last])):
                    raise ValueError("Unavailable source range")
                output.append({"file": name, "start_line": first, "end_line": last,
                    "start_column": column, "end_column": end_column, "source_sha256": wanted})
        except (OSError, ValueError, UnicodeError):
            return {"ok": False, "reason": "source_unavailable_or_invalid", "locations": output}
        return {"ok": True, "reason": "located_frozen_source_not_safety_proof", "locations": output}

    def query_checks(self, evidence):
        history = evidence.get("query_history", [])
        if not isinstance(history, list):
            return [{"ok": False, "reason": "invalid_query_history"}]
        primary = evidence["alert_contract"]["primary_location"]
        target = {"file": primary.get("file") or primary.get("uri"),
                  "line": primary["start_line"], "column": primary["start_column"],
                  "cwe": evidence["alert_contract"].get("cwe")}
        output = []
        for index, query in enumerate(history):
            item = {"query_index": index, "ok": False}
            output.append(item)
            try:
                if (not isinstance(query, dict) or query.get("status") != "ok"
                        or query.get("producer") != "codeql-v2"
                        or query.get("error") or query.get("error_type")):
                    raise ValueError("query_not_successful_trusted_controller_output")
                tid = query.get("template_id")
                spec = self.specs.get(tid) if isinstance(tid, str) else None
                params = query.get("parameters")
                if (spec is None or not spec.get("enabled", True)
                        or spec.get("language", "java") != "java" or not isinstance(params, dict)
                        or set(params) != set(spec.get("parameters", []))):
                    raise ValueError("query_parameter_schema_mismatch")
                if (any(params.get(k) != target[k] for k in ("file", "line", "column"))
                        or type(params.get("line")) is not int or type(params.get("column")) is not int
                        or ("cwe" in params and params["cwe"] != target["cwe"])):
                    raise ValueError("query_target_mismatch")
                if query.get("provenance") != {"database_hash": self.database_hash,
                        "parameters_hash": canonical_hash(params), "template_hash": self.template_hashes[tid]}:
                    raise ValueError("query_provenance_mismatch")
                if (_sha(self.template_manifest) != self.template_manifest_sha256
                        or hash_template(spec, self.template_manifest.parent) != self.template_hashes[tid]):
                    raise ValueError("frozen_template_changed")
                result, summary = query.get("result"), query.get("summary")
                if not isinstance(result, dict) or not isinstance(summary, dict):
                    raise ValueError("query_result_missing")
                select = result.get("#select")
                if not isinstance(select, dict):
                    raise ValueError("query_result_missing")
                if any(key in obj and obj[key] is not False
                       for obj in (query, result, select, summary)
                       for key in ("truncated", "is_truncated", "partial", "incomplete")):
                    raise ValueError("query_result_truncated_or_incomplete")
                rows, columns = select.get("tuples"), select.get("columns")
                if (not isinstance(rows, list) or not isinstance(columns, list)
                        or any(not isinstance(row, list) or len(row) != len(columns) for row in rows)):
                    raise ValueError("query_result_invalid")
                if summary != summarize_bqrs_json(tid, result):
                    raise ValueError("query_summary_mismatch")
                for row in rows:
                    if row and row[0] == "fpm-bound-v1":
                        if (len(row) != 9 or row[2:6] != [target[k] for k in ("cwe", "file", "line", "column")]
                                or type(row[4]) is not int or type(row[5]) is not int):
                            raise ValueError("typed_observation_target_mismatch")
                item.update({"ok": True, "template_id": tid, "row_count": len(rows),
                             "query_sha256": _digest(query), "safety_proven": False})
            except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
                item["reason"] = str(exc)
        return output


class SourceLocationUnverifiedPolicy:
    def __init__(self, context):
        self.context = context

    def metadata(self):
        return {"version": VERSION, "mode": MODE, "module_sha256": _sha(__file__),
                "safety_proven": False, "reference_policy": REFERENCE_VERSION,
                "binding_context": self.context.metadata(), "confidence_input_used": False,
                "risk": "A wrong model FP proposal can suppress a true vulnerability"}

    def evaluate(self, evidence, candidate, *, infrastructure_errors):
        # Non-FP delegates to the unchanged strict authority. The runner only
        # invokes this strategy on actual FP candidates; no global alias changes.
        if candidate.get("verdict") != "FP":
            return authorization(evidence, candidate.get("verdict"))
        clean = {key: copy.deepcopy(evidence[key]) for key in EVIDENCE_FIELDS if key in evidence}
        base = {"policy_version": VERSION, "authorized": False, "route": None,
                "fact_ids": [], "security_operation": "KEEP", "gate_branch": "FP",
                "verification": "unverified_high_recall", "safety_proven": False,
                "risk": "Model errors can cause false suppression; located source is not safety proof"}
        if infrastructure_errors or clean.get("infrastructure_errors"):
            return {**base, "reason": "infrastructure_failure"}
        if candidate.get("sufficient") is not True or candidate.get("missing_evidence") != []:
            return {**base, "reason": "incomplete_fp_candidate"}
        located = self.context.located_source(clean)
        if not located["ok"]:
            return {**base, "reason": located["reason"], "source_evidence": located}
        checks = self.context.query_checks(clean)
        if any(not q["ok"] for q in checks):
            return {**base, "reason": "invalid_query_history", "query_checks": checks}
        if clean["alert_contract"].get("cwe") not in ROUTES:
            return {**base, "reason": "unsupported_cwe"}
        slots = clean.get("evidence_slots", {})
        if not isinstance(slots, dict) or any(v in ("error", "checked_error") for v in slots.values()):
            return {**base, "reason": "evidence_error"}
        if slots.get("call_context_required") == "yes":
            return {**base, "reason": "shared_context_not_certified"}
        facts = clean.get("backend_facts", [])
        if not isinstance(facts, list) or any(not isinstance(f, dict) for f in facts):
            return {**base, "reason": "invalid_backend_facts"}
        if any(f.get("kind") == "weak_crypto" for f in verified_facts(clean)):
            return {**base, "reason": "known_weak_crypto_veto"}
        strict = strict_fp_reference(clean, "FP")
        if strict["authorized"]:
            return strict
        return {**base, "authorized": True, "route": "unverified_model_fp_plus_located_source",
                "security_operation": "SUPPRESS", "reason": "explicit_unverified_fp_permission",
                "strict_reference": strict, "source_evidence": located, "query_checks": checks}


def build_fp_policy(config, inputs, *, template_manifest, method):
    """Construct opt-in runtime policy before creating any model client."""
    if config is None:
        return None
    if not isinstance(config, dict):
        raise ValueError("fp_policy must be an explicit configuration object")
    mode = config.get("mode")
    if config == {"mode": "default"}:
        return None
    if mode != MODE or set(config) != {"mode", "source_root", "source_manifest"}:
        raise ValueError("Unsupported or incomplete fp_policy configuration")
    if method != "queryfpm":
        raise ValueError("The optional FP policy applies only to method=queryfpm")
    trusted = {}
    for record in inputs:
        alert_id = record.get("alert_id")
        if alert_id in trusted:
            raise ValueError("Duplicate trusted alert IDs")
        try:
            trusted[alert_id] = {key: copy.deepcopy(record[key]) for key in STATIC_FIELDS}
        except KeyError as exc:
            raise ValueError("Missing static alert contract field: " + str(exc)) from exc
    context = FrozenSourceContext(source_root=config["source_root"],
        source_manifest=config["source_manifest"], template_manifest=template_manifest,
        trusted_alerts=trusted)
    for record in inputs:
        check = context.located_source(record)
        if not check["ok"]:
            raise ValueError("Frozen source preflight failed: " + check["reason"])
    return SourceLocationUnverifiedPolicy(context)
