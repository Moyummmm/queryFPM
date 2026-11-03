# Optional TP v2.1 structural classification

The `semantic_tp_v2_1` option classifies a sufficient model TP proposal when
the applicable source structure and policy conditions are satisfied. Its action
is always `KEEP`. It records `model_classified_unverified`: checked source/sink
structure is not proof that the reported vulnerability is exploitable.

The default runner retains its existing behavior. The TP option is independent
of `source_location_unverified`; enabling one does not enable the other. Strict
FP facts are checked through a separate strict reference function. Unverified
FP permission is never treated as a safety certificate or a TP conflict.

An explicit revised-run configuration uses:

```json
{
  "tp_policy": {
    "mode": "semantic_tp_v2_1",
    "source_root": "/path/to/frozen/java/source",
    "source_manifest": "/path/to/source_hashes.json",
    "variant": "flow_or_api",
    "minimum_successful_queries_before_tp": 2
  }
}
```

As with the FP option, the input contracts and source snapshot must bind to an
actual CodeQL database, including for query budget zero. Only Java is supported.
The CLI constructs frozen source and input contexts before creating a client.
TP snapshots additionally bind `code_context`, and exclude evaluation labels.
When both options are selected, they must use the same source/alert context.

`flow_strict` supports ordered source/sink traces for CWE-022, 078, 079, 089,
090 and 643. `flow_or_api` also permits supported API alerts for CWE-327, 330
and 614. These checks verify static structure; they do not establish flow
feasibility or exploitability. Unsupported or incomplete structures remain
UNKNOWN. CWE-327 dynamic or property-derived algorithms remain UNKNOWN unless
the strict gate independently establishes a bound weak-algorithm fact. A direct
weak literal must fall inside the reported call's source region.

The query threshold is bounded by the query budget. The original v2.1 semantics
are preserved:

- While query budget remains, a semantic TP normally waits for the configured
  minimum successful queries (0, 1 or 2).
- Reaching the total query budget allows a structurally eligible TP to finalize
  with fewer queries. In particular, `--budget 0` allows a semantic TP after
  zero queries, even when the configured minimum is 2.
- If the controller finds no further executable action after at least one
  successful query, it may finalize an eligible TP and records
  `tp_evidence_actions_exhausted`. Model prose cannot set this state.
- A missing first action, failed/unavailable query, infrastructure error,
  insufficient model judgment or conflicting strict FP fact does not authorize
  semantic TP. A bound weak-algorithm fact remains a distinct strict route.

Earlier finalization can retain an FP that a longer trajectory might later
classify differently. Semantic TP is a model label, not independently verified
ground truth. This portable option does not reproduce the earlier 500-alert
experiment or establish its measured rates: the published package's templates,
prompts and enabled transports differ from that separately frozen run.
