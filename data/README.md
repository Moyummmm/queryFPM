# QueryFPM OWASP Benchmark Java Manifests

This directory publishes the alert membership and benchmark labels used for the
200-alert development set and the 1,409-alert held-out test set described in the
QueryFPM manuscript.

The files are minimal manifests. They do not contain source code, SARIF files,
CodeQL databases, model outputs, or retrieved evidence.

## Files

- `selected_labeled_200.csv`: 200 development alerts
  - 164 TP and 36 FP
- `selected_labeled_1409.csv`: 1,409 held-out alerts
  - 1,126 TP and 283 FP

The two sets have no overlapping `alert_id`.

## Columns

| Column | Meaning |
|---|---|
| `alert_id` | Stable QueryFPM alert identifier |
| `cwe` | Exact CWE assigned after rule and expected-result matching |
| `label` | Benchmark label, `TP` or `FP` |
| `benchmark_test` | OWASP Benchmark test class |
| `primary_file` | Source path reported for the primary location |
| `start_line` | Primary-location start line |
| `start_column` | Primary-location start column |

Labels follow the OWASP Benchmark Java v1.2 expected results after exact CWE
matching and alert-by-alert review. The manifests preserve the alert ordering of
the frozen evaluation inputs.

## Source input hashes

The CSV files were exported from the following frozen JSONL inputs:

| Cohort | SHA-256 of source JSONL |
|---|---|
| Development, 200 alerts | `32a8484e48e5e94d1ba6537255e86f8c00ad302cafbbe2597ff24240b6943b61` |
| Held-out, 1,409 alerts | `db32cfb528d207ffc74fdafb1dbeeda094322063578335947accb9aa9f26e57d` |

The held-out hash matches the input used for the reported primary evaluation.
