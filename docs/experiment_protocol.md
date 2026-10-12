# Experiment Protocol

## Goal

Evaluate whether LLM-guided iterative evidence retrieval reduces false positives in CodeQL alerts while retaining true positives.

## Dataset

- OWASP Benchmark Java v1.2
- Ground truth: `expectedresults-1.2.csv`
- Target CWEs:
  - CWE-022
  - CWE-078
  - CWE-079
  - CWE-089
  - CWE-090
  - CWE-327
  - CWE-330
  - CWE-501
  - CWE-614
  - CWE-643

Ground truth is only used for evaluation, never in LLM prompts.

## Analyzer

- CodeQL CLI latest at experiment time
- Query suite: default `codeql/java-queries`
- Initial alerts: SARIF
- Extra evidence: BQRS decoded to JSON

## Methods

| ID | Method |
| --- | --- |
| B0 | Raw CodeQL |
| B1 | SARIF summary + one-shot LLM |
| B2 | Structured evidence + one-shot LLM |
| B3 | Structured evidence + one extra query |
| B4 | Full iterative method, max iteration = 3 |

## Structured Evidence

Each alert is converted into:

- `alert_contract`: CodeQL rule, CWE, message, primary location
- `annotated_trace`: SARIF code flow as SOURCE / PROPAGATION / SINK steps
- `code_context`: local source snippets
- `cwe_profile`: CWE-specific risky/safe patterns
- `evidence_slots`: yes/no/unknown sufficiency fields
- `missing_evidence`: candidate missing facts
- `query_history`: executed or requested evidence templates

## LLM

- Model: `deepseek-v4-flash`
- Temperature: `0`
- Output: strict JSON
- Final labels: `TP`, `FP`, `UNKNOWN`

## Iteration Budget

- Max iterations per alert: `3`
- LLM cannot write arbitrary CodeQL.
- LLM can only select a template and fill parameters.

## Metrics

Operational setting treats `UNKNOWN` as kept, because a real triage tool should not automatically remove uncertain alerts.

```text
Precision = Kept_TP / (Kept_TP + Kept_FP)
TP Retention = Kept_TP / Original_TP
FP Reduction = Removed_FP / Original_FP
F1 = 2 * Precision * TP_Retention / (Precision + TP_Retention)
Unknown Rate = Unknown / All Alerts
```

Selective setting excludes `UNKNOWN` and reports:

- Coverage
- Selective Accuracy
- Selective Precision
- Selective Recall
- Selective F1
- Selective MCC

## Research Questions

1. Does the framework reduce false positives compared with raw CodeQL?
2. Does structured evidence improve LLM triage over raw SARIF prompts?
3. Does iterative CodeQL evidence retrieval outperform one-shot LLM triage?
4. How does performance vary across CWE categories?
5. What is the cost in queries, runtime, and LLM tokens?
