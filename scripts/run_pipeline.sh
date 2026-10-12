#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-configs/experiment.json}"
SARIF="${SARIF:-data/raw/codeql-default.sarif}"
EXPECTED="${EXPECTED:-BenchmarkJava/expectedresults-1.2.csv}"
SOURCE_ROOT="${SOURCE_ROOT:-BenchmarkJava}"

if command -v fpm-bench >/dev/null 2>&1; then
  FPM_BENCH=(fpm-bench)
else
  export PYTHONPATH="${PYTHONPATH:-$PWD/src}"
  FPM_BENCH=(python3 -m fpm_benchmark.cli)
fi

"${FPM_BENCH[@]}" parse-sarif \
  --sarif "$SARIF" \
  --expected "$EXPECTED" \
  --source-root "$SOURCE_ROOT" \
  --config "$CONFIG" \
  --out data/interim/evidence.jsonl

"${FPM_BENCH[@]}" raw-codeql \
  --input data/interim/evidence.jsonl \
  --out data/results/decisions.raw_codeql.jsonl

"${FPM_BENCH[@]}" evaluate \
  --decisions data/results/decisions.raw_codeql.jsonl \
  --out data/results/metrics.raw_codeql.json

"${FPM_BENCH[@]}" llm-triage \
  --input data/interim/evidence.jsonl \
  --out data/results/decisions.one_shot.jsonl \
  --config "$CONFIG" \
  --mode one-shot \
  --view structured

"${FPM_BENCH[@]}" evaluate \
  --decisions data/results/decisions.one_shot.jsonl \
  --out data/results/metrics.one_shot.json
