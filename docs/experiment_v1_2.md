# Query-Centered FPM Experiment v1.2

This version supersedes `experiment-v1.1` for subsequent OWASP main experiments. Earlier tags
remain unchanged for provenance.

## Method Changes

- Split TP and FP prerequisite gates. TP still requires affirmative source/sink/path or API core
  facts. FP no longer requires a confirmed vulnerable path, but requires an identified sink/API
  plus positive safety evidence or a relevant query result.
- A single-location alert can pass the FP gate only with a nonempty relevant query result.
- A complete source-to-sink trace can pass after a successful relevant query, including an empty
  safety query, only when the LLM returns a high-confidence sufficient FP decision based on the
  complete supplied evidence.
- Expand the CWE-330 randomness search window to cover sources preceding the reported sink and
  identify both `java.util.Random` and `java.security.SecureRandom`.

## Validation

- The revised randomness query compiled and executed on CodeQL 2.25.5, returning
  `randomness source: java.util.Random` for a source 29 lines before the alert sink.
- Replay of the zero-failure v1.1 run predicts 100% TP retention, 92% FP reduction, and 1.27%
  UNKNOWN. This replay is diagnostic and not a replacement for a fresh v1.2 full run.
- Empty query results alone remain insufficient FP evidence.
