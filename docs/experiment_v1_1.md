# Query-Centered FPM Experiment v1.1

This version supersedes `experiment-v1` for the OWASP main experiment. The v1 tag remains
unchanged for provenance.

## Objective Fixes

- Backfill deterministic `source_user_controlled`, `path_exists`, and trust-boundary core slots
  from explicit SARIF `SOURCE_CANDIDATE -> SINK_CANDIDATE` traces.
- Apply the same enrichment at runtime so the frozen 1,974-record input does not need rewriting.
- Recompute advisory missing-evidence labels after enrichment.
- Repair `find-crypto-algorithm` so it supports batch rendering and compiles on CodeQL 2.25.5.

These changes address two observed implementation failures: all 1,974 alerts being forced into
Round 2 despite 1,918 sufficient Round 1 LLM decisions, and all CWE-327 query batches failing.

## Validation

- Offline replay predicts 1,239 Round 1 final decisions and 735 Round 2 candidates.
- The crypto template compiled and executed against the frozen OWASP CodeQL database with
  `status=ok` and returned the target algorithm argument.
- The complete unit-test suite passes.

## Updated Hashes

| Artifact | SHA-256 |
|---|---|
| Controller | `ad6838081f6498e22b96c7933cc5f10e3da1382c493338fd191695561c0e5029` |
| Evidence construction | `08028eb7f44523eb3964eb9e48b9f8a175a2b33b3931f85b71d394b973cdffd1` |
| Crypto query template | `602d7f8bd5eeb9cf150a038644bdda1d3a74455492a60add45c84dfe72721f36` |
| Combined CodeQL template tree | `04aec9298b395b0b0405f07c04716fc02ba75957a4807769c8fbb4dc0cd8b045` |

All other dataset, model, prompt, metric, and runtime requirements remain as documented in
`experiment_v1.md`.
