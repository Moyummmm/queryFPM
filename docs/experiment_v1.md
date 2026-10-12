# Query-Centered FPM Experiment v1

Frozen on 2026-07-12 for the OWASP Benchmark Java 1.2 main experiment.

## Method Contract

- Dataset: OWASP Benchmark Java 1.2, 1,974 aligned CodeQL alerts
- Target CWEs: 022, 078, 079, 089, 090, 327, 330, 501, 614, and 643
- Model: `deepseek-v4-flash`
- Provider API: OpenCode Go, OpenAI-compatible endpoint
- Temperature: 0
- Maximum evidence rounds: 3
- Primary run concurrency: 8 workers
- Output policy: TP, FP, or conservative UNKNOWN
- Gate: CWE- and verdict-conditioned evidence gate
- Query execution: template-batched, cached, and protected by a database lock

Ground truth is evaluation-only and is removed from every LLM evidence view.

## Frozen Artifact Hashes

| Artifact | SHA-256 |
|---|---|
| Input evidence JSONL | `6565b66fd02863c015f430e862cf4e45e5fb7a3fc8d4571a25e5b7432b53cf8d` |
| Local experiment config | `8c528d57f07cb5d01b2ec766468e3538abe047aaceeaabc490370016f59683fb` |
| CodeQL database descriptor | `d05d42a782f4d9304451666b5e3e8bf899c6107807dd9df3b981b7bb7bc26224` |
| Combined CodeQL template tree | `ec2d52dc927584ed5b1cb34a1dada14b4bc2046384af57a46a90c56f3746f4b0` |
| Template manifest | `0e9510f060765774a2f30a8db678de82a99827927c35c856044c4167b0a384b6` |
| Prompt implementation | `22b690a63c7bb0f7445197a9e53543df48c8e7810db1b569bc69ff5dbc69bd56` |
| Controller and gate implementation | `d9bec5f92defc9c9aa2404ab35cd9d95b824f5172254d8175ba877fd6adc7421` |

CodeQL CLI version: `2.25.5`.

## Valid Run Criteria

A main-experiment result is valid only when all of the following hold:

- Exactly 1,974 decisions are produced.
- LLM infrastructure failures are zero.
- CodeQL query failures are zero.
- Final verdict counts sum to 1,974.
- The saved configuration and input hashes match this manifest.

Provider rate limits, network errors, malformed responses, and database lock errors are
infrastructure failures, not model UNKNOWN decisions.

## Change Policy

After this freeze, changes to prompts, CWE profiles, gate conditions, evidence-slot semantics,
query templates, template order, or final-decision policy require a new method version. Logging,
reporting, retry, and resume fixes may be backported only when they do not change an alert's
semantic evidence or verdict.
