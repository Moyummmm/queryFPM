# Optional source-location FP policy

The revised CLI supports an explicit `source_location_unverified` FP policy.
It can suppress a true vulnerability when the model incorrectly proposes FP.
Frozen source locations and successful query provenance are not safety proofs.
The existing authorization function and default command behavior are unchanged.
This option does not change the original scaffold CLI.

To select it, add this object to an ordinary revised-run configuration:

```json
{
  "query_cache_dir": "/path/to/isolated/query-cache",
  "fp_policy": {
    "mode": "source_location_unverified",
    "source_root": "/path/to/frozen/java/source",
    "source_manifest": "/path/to/source_hashes.json"
  }
}
```

The source manifest has the form `{"files": {"relative/Case.java": "sha256"}}`.
Paths are relative to `source_root`; values are the SHA256 hashes of exact file
bytes. The normalized Java inputs must contain an opaque `alert_id`,
`analysis_provenance` with `language`, `database_hash`, and `sarif_sha256`, an
`alert_contract` with a primary file/line/column, and an `annotated_trace` list.
One database/SARIF identity is required per run. Input labels are excluded from
the policy's trusted contracts. After entering the FP strategy, only an explicit
allowlist of contract, query, fact, slot and infrastructure fields is used for
decisions; label fields and model explanations are discarded.
The CLI requires an existing CodeQL database with `codeql-database.yml`, even
when the query budget is zero. Its actual extraction fingerprint must match
every frozen input contract before a model client can be created.
The revised CLI holds an exclusive lock at the database root before database
fingerprinting, preflight and client creation. Different output directories do
not permit concurrent runs against the same database. All outputs in one
directory share a second lock, so different databases can run concurrently with
separate output directories. Main outputs cannot use coordination-lock names
or reside inside reserved `*.records` or `queries` artifact directories.
Final output/sidecar symlinks are rejected; directory symlink aliases share the
same namespace. Existing result files and coordination inodes are preserved.
Lock files are retained; OS locks
are released when the run finishes or its process closes.

Use the existing command with `--method queryfpm`. Omitting `fp_policy`, or
setting it to `{"mode": "default"}`, keeps the existing behavior. Other
methods reject this opt-in configuration. No hardcoded cohort size is required.
The source/contract preflight runs before a model client is created. The input
contracts, source manifest, templates and policy implementation are bound into
the run fingerprint, so changed inputs cannot silently resume an old run.

With a positive query budget, this optional FP strategy requires an absolute
`query_cache_dir`, selecting the package's existing batch executor. Its query
validator binds the canonical batch template hash. The direct executor records
a different rendered-query hash and is not supported by this mode; missing or
relative cache configuration is rejected before client/guard construction. No
cache is required at budget zero. This restriction does not change the default
strict policy or the independent TP mode. Use a new isolated cache for a new
experimental condition; a cache is not a safety certificate.

Only actual FP candidates use the optional strategy. They must be sufficient
and have an empty missing-evidence list. Every primary and trace location must
match its original per-alert static contract and exact frozen source bytes.
Every nonempty query history is checked for successful `codeql-v2` output,
controller-owned target parameters, database/template/parameter hashes, matching
raw results and summaries, and absence of truncation. A valid empty history or
zero-row query remains permissible; neither establishes safety. Archived replay
producers do not acquire authority through this mode.

Infrastructure errors, unresolved shared context, evidence errors, unsupported
CWEs, invalid locations and verified weak-crypto facts veto authorization. The
strict reference policy excludes constant-value and escaped-output certificates
from safety authorization. If it independently authorizes a checked safety fact,
that original route is retained. Otherwise the optional source route records:

- `route: unverified_model_fp_plus_located_source`
- `verification: unverified_high_recall`
- `safety_proven: false`
- no safety `fact_ids`
- the strict reference assessment and source/query binding details

TP and UNKNOWN candidates still call the existing strict authorization function.
The optional policy never replaces that function globally or creates backend
safety facts. Future TP conflict checks must continue to use a strict safety
authority, not the optional permission strategy.

This package mode does not claim exact reproduction of the earlier 500-alert
experiment: that run used separately frozen templates, prompts, a TP extension,
token guards and an accelerated CodeQL backend. Those components are not enabled
by this option. All new tests use synthetic records and in-memory model clients;
they do not run a model or CodeQL.
