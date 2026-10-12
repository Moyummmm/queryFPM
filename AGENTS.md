# AGENTS.md

Stdlib-only Python (`requires-python >=3.11`, no dependencies). Package: `src/fpm_benchmark/`, CLI entry `fpm_benchmark.cli:main`.

## Run commands

- Prefer `PYTHONPATH=src python3 -m fpm_benchmark.cli …` — `fpm-bench` exists only after `python -m pip install -e .`.
- Env check: `scripts/check_env.sh`. Java 17 + Maven are required to build BenchmarkJava / create the CodeQL DB (`scripts/bootstrap_local_toolchain.sh`, `scripts/bootstrap_assets.sh`).
- API keys only via env (`DEEPSEEK_API_KEY`, or whatever `llm.api_key_env` names in the chosen config; `DEEPSEEK_BASE_URL` overrides base URL). Never put keys in `.env.example` or commit them.

## Tests / lint

- All tests need `PYTHONPATH=src`: `PYTHONPATH=src python3 -m unittest discover -s tests`
- Single file: `PYTHONPATH=src python3 -m unittest tests.test_cli -v` (bare `python3 -m unittest` fails with import errors — that is expected, not a broken tree).
- Lint config: `pyproject.toml` `[tool.ruff]` (line-length 100, `py311`). `ruff` may not be installed; don't add dependencies to run it.

## Configs — don't trust defaults

- Default `--config configs/experiment.json` contains machine-specific absolute paths (`codeql_bin`, `additional_packs_root`, `database`, `sarif`). Always pass an explicit `--config` and `--codeql-db` / `--input` for real runs (e.g. `configs/experiment.opencode-go.local.json`).
- `data/` (all run outputs, caches, local dataset copies), `BenchmarkJava/`, `codeql-home/`, `tools/` binaries, `.m2/`, `*.sarif` are gitignored and rebuilt via `scripts/bootstrap_*.sh`. Only `tests/fixtures/` (e.g. `decisions-mini.jsonl`, `expectedresults-mini.csv`) is committed — use it for offline verification.

## Pipeline order

`parse-sarif` (or `import-normalized` / `prepare-juliet`) → `llm-triage` → `evaluate`. `scripts/run_pipeline.sh` shows the minimal offline flow (`CONFIG`/`SARIF`/`EXPECTED`/`SOURCE_ROOT` env overrides). Other subcommands: `raw-codeql`, `dataset-summary`, `diagnostic-prepare`, `diagnostic-compare`.

## `llm-triage` gotchas

- `--mode iterative` forces `--baseline ours_query_centered` regardless of the flag; one-shot baselines (`b1…b5`) only apply in `--mode one-shot`.
- Omitting `--codeql-db` is safe but degrades: requests are recorded as `not_executed_no_codeql_db` and iteration stops. Only pass a DB whose dir contains `codeql-database.yml`.
- Frozen runs (`scripts/run_owasp_1974_*.sh`): require exactly 1974 input rows, `WORKERS` 1–16 (default 8; lower on HTTP 429), take an `flock` on `$DATABASE/.fpm-experiment.lock` — never run two iterative jobs against the same DB. A run is valid only with zero LLM/CodeQL infra failures (`records_with_llm_failure == 0`).
- Resume interrupted iterative runs with `--resume` (reuses `--input` as prior decisions); query cache lives in `--query-cache-dir`.

## Controller / gate (do not bypass)

- LLM output `sufficient:true` + `TP/FP` is **not** final. `cli.py:_decision_is_final` additionally requires CWE checklist slots (`TP_REQUIRED_SLOTS` / `FP_REQUIRED_SLOTS`) and semantic consistency — fix evidence/slots, never weaken the gate.
- Query location params (`file`, `line`, `cwe`, `field_name`, source/sink locs) are controller-owned (`_normalize_query_request` overwrites LLM values). Invalid/disabled template IDs (e.g. disabled `find-source-to-sink-path`) fall back to `_next_mandatory_query`.
- LLM picks only `template_id` + params from `templates/codeql/templates.json`; it never writes raw CodeQL. Nearby-query hits (`nearby_*`, `checked_none`) don't prove path sanitization.
- Ground truth (`expectedresults-1.2.csv`) is evaluation-only — never add it to prompts/views. Frozen method contract + artifact hashes: `docs/experiment_v1.md`; protocol/metrics definitions: `docs/experiment_protocol.md`.

## Metrics

`src/fpm_benchmark/metrics.py`: operational setting treats `UNKNOWN` as kept; `INFRA_ERROR` verdicts are excluded and make `experiment_complete=false`. Distinguish infra failures (rate limit/network/malformed/lock) from model `UNKNOWN`.
