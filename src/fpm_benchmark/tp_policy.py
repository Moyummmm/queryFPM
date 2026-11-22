"""Opt-in TP v2.1 structural classification; always KEEP, never suppression."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from types import MappingProxyType

from .authorization import authorization, canonical_hash
from .fp_policy import FrozenSourceContext, STATIC_FIELDS
from .java_source_lexer import mask_java_comments
from .tp_structure import TrustedContext, VARIANTS
from .tp_gate_v2_1 import evaluate, VERSION as GATE_VERSION

MODE = "semantic_tp_v2_1"
VERSION = "semantic-tp-v2.1-optional-v1"
INPUT_FIELDS = ("alert_id", *STATIC_FIELDS, "code_context")


class SemanticTPPolicy:
    gate_version = GATE_VERSION

    def __init__(self, context, records, *, variant, minimum_successful_queries_before_tp):
        if variant not in VARIANTS:
            raise ValueError("Unknown TP structural variant")
        if (type(minimum_successful_queries_before_tp) is not int
                or minimum_successful_queries_before_tp not in {0, 1, 2}):
            raise ValueError("Minimum successful TP queries must be 0, 1 or 2")
        self.context = context
        self.variant = variant
        self.minimum = minimum_successful_queries_before_tp
        snapshots = {r["alert_id"]: canonical_hash({k: copy.deepcopy(r.get(k)) for k in INPUT_FIELDS})
                     for r in records}
        if len(snapshots) != len(records):
            raise ValueError("Duplicate TP input IDs")
        self._input_hashes = MappingProxyType(snapshots)
        self.trust = TrustedContext(context.source_root, dict(context.source_hashes),
            context.database_hash, context.sarif_sha256, mask_java_comments)

    def metadata(self):
        return {"mode": MODE, "version": VERSION, "gate_version": GATE_VERSION,
            "variant": self.variant, "minimum_successful_queries_before_tp": self.minimum,
            "verification": "model_classified_unverified", "operation": "KEEP",
            "binding_context": self.context.metadata(),
            "static_inputs_sha256": canonical_hash(dict(self._input_hashes)),
            "component_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                for name in ("tp_policy.py", "tp_gate_v2_1.py", "tp_structure.py", "tp_crypto_guard.py",
                             "java_source_lexer.py", "fp_policy.py")},
            "interpretation": "Model TP plus checked static structure; exploitability is not proven",
            "threshold_semantics": "Wait below the query minimum while budget remains; budget exhaustion can finalize with fewer queries"}

    def _input_ok(self, record):
        try:
            return self._input_hashes.get(record.get("alert_id")) == canonical_hash(
                {k: record.get(k) for k in INPUT_FIELDS}) and self.context.contract_ok(record)
        except (TypeError, ValueError):
            return False

    def validate_input(self, record):
        if not self._input_ok(record):
            raise ValueError("TP input differs from its frozen static snapshot")
        if not self.context.located_source(record)["ok"]:
            raise ValueError("TP input source differs from the frozen source snapshot")

    def evaluate(self, evidence, candidate, *, infrastructure_errors, query_budget,
                 confirmed_action_exhaustion=False):
        if candidate.get("verdict") != "TP":
            return authorization(evidence, candidate.get("verdict"))
        # This check also prevents a cached lexical view from hiding later
        # source-file changes. Labels and model prose are not integrity inputs.
        if not self._input_ok(evidence) or not self.context.located_source(evidence)["ok"]:
            return {"authorized": False, "route": None, "fact_ids": [],
                "reason": "tp_frozen_input_or_source_mismatch", "gate_policy": GATE_VERSION,
                "gate_branch": "TP", "security_operation": "KEEP", "verification": "not_classified"}
        return evaluate(evidence, candidate, trusted_context=self.trust,
            variant=self.variant, infrastructure_errors=infrastructure_errors,
            minimum_successful_queries_before_tp=self.minimum, query_budget=query_budget,
            confirmed_action_exhaustion=confirmed_action_exhaustion)


def build_tp_policy(config, inputs, *, template_manifest, method):
    if config is None or config == {"mode": "default"}:
        return None
    required = {"mode", "source_root", "source_manifest"}
    allowed = required | {"variant", "minimum_successful_queries_before_tp"}
    if (not isinstance(config, dict) or config.get("mode") != MODE
            or not required <= set(config) or not set(config) <= allowed):
        raise ValueError("Unsupported or incomplete tp_policy configuration")
    if method != "queryfpm":
        raise ValueError("The optional TP policy applies only to method=queryfpm")
    trusted = {}
    for record in inputs:
        alert_id = record.get("alert_id")
        if alert_id in trusted:
            raise ValueError("Duplicate trusted TP alert IDs")
        try:
            trusted[alert_id] = {key: copy.deepcopy(record[key]) for key in STATIC_FIELDS}
        except KeyError as exc:
            raise ValueError("Missing TP static input field: " + str(exc)) from exc
    context = FrozenSourceContext(source_root=config["source_root"],
        source_manifest=config["source_manifest"], template_manifest=template_manifest,
        trusted_alerts=trusted)
    policy = SemanticTPPolicy(context, inputs, variant=config.get("variant", "flow_or_api"),
        minimum_successful_queries_before_tp=config.get("minimum_successful_queries_before_tp", 2))
    for record in inputs:
        policy.validate_input(record)
    return policy
