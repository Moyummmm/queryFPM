# selected_labeled_200.csv — evaluation subset (200 alerts)

A held-out test subset used to evaluate false-positive suppression on
CodeQL alerts for the OWASP Benchmark for Java (v1.2).

## Provenance

- **Underlying scan.** CodeQL CLI 2.26.0 (`java` queries) run against the
  public OWASP Benchmark for Java v1.2; the alert stream has SHA-256
  `640cf9bc6b709704741a3552fb30d729d54a98434bc087404af595b591a4745f`
  (SARIF result indices in this CSV refer to `runs[0].results` of that file).
- **Labels.** Official benchmark ground truth (`expectedresults-1.2.csv`)
  matched to each alert at *exact CWE* level (`match_quality = exact_cwe`
  for all 200 rows). 1,609 alerts in the scan carried exact labels.
- **Sampling.** Proportional stratified sample over strata
  *(label, CWE)* of the 1,559 exactly-labeled alerts that remain after
  excluding a 50-alert development subset used for certificate tuning.
  Largest-remainder rounding; fixed seed `20261013`; deterministic.
- **Composition.** 164 TP / 36 FP across nine CWEs:
  022 (17/8), 078 (10/3), 079 (31/11), 089 (35/10), 090 (3/1),
  327 (33/3), 330 (28/0), 614 (5/0), 643 (2/0).

## Columns

`alert_id` internal identifier (prefix of the pipeline alert fingerprint) ·
`benchmark_test` Benchmark test class · `cwe` CWE reported by the alert ·
`rule_id` CodeQL query id · `sarif_result_index` index into the SARIF run ·
`file` `start_line` `start_column` primary location ·
`label` TP (expected-vulnerable) / FP (expected-safe, wrong-CWE-free match) ·
`expected_cwe` benchmark ground-truth CWE · `match_quality` label match kind ·
`alert_message` first line of the CodeQL alert message (truncated to 160 chars).
