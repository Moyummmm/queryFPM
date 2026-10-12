#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DEEPSEEK_OFFICIAL_API_KEY:-}" ]]; then
  echo "DEEPSEEK_OFFICIAL_API_KEY is not set" >&2
  exit 2
fi

INPUT="data/interim/owasp-zerofalse-style-1974.labeled.jsonl"
CONFIG="configs/experiment.deepseek-official.json"
DATABASE="data/codeql-db/owasp-benchmark-java-1.2-codeql-2.25.5-frozen"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
WORKERS="${WORKERS:-64}"
RUN_DIR="data/results/owasp-1974-deepseek-official-v4-flash-${RUN_ID}"
DECISIONS="${RUN_DIR}/decisions.jsonl"
RUNTIME="${RUN_DIR}/runtime.json"
METRICS="${RUN_DIR}/metrics.json"
SUMMARY="${RUN_DIR}/summary.json"
LOG="${RUN_DIR}/run.log"
CACHE_DIR="data/cache/owasp-1974-deepseek-official-v4-flash-${RUN_ID}"

if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || (( WORKERS < 1 || WORKERS > 500 )); then
  echo "WORKERS must be an integer between 1 and 500 (got: $WORKERS)" >&2
  exit 2
fi
if [[ ! -f "$INPUT" ]] || [[ "$(wc -l < "$INPUT")" -ne 1974 ]]; then
  echo "Expected 1974 input records at $INPUT" >&2
  exit 2
fi
if [[ ! -f "$DATABASE/codeql-database.yml" ]]; then
  echo "Missing CodeQL database: $DATABASE" >&2
  exit 2
fi

mkdir -p "$RUN_DIR" "$CACHE_DIR"
export PYTHONPATH="${PYTHONPATH:-}:src"

exec 9>"$DATABASE/.fpm-experiment.lock"
if ! flock -n 9; then
  echo "Another experiment still holds the CodeQL database lock" >&2
  exit 5
fi

echo "provider: DeepSeek official"
echo "model: deepseek-v4-flash"
echo "run directory: $RUN_DIR"
echo "workers: $WORKERS"

python3 -u -m fpm_benchmark.cli llm-triage \
  --input "$INPUT" \
  --out "$DECISIONS" \
  --config "$CONFIG" \
  --mode iterative \
  --baseline ours_query_centered \
  --view auto \
  --codeql-db "$DATABASE" \
  --max-iterations 3 \
  --workers "$WORKERS" \
  --query-cache-dir "$CACHE_DIR" \
  --runtime-report "$RUNTIME" 2>&1 | tee "$LOG"

python3 -m fpm_benchmark.cli evaluate --decisions "$DECISIONS" --out "$METRICS"
python3 scripts/summarize_decisions.py \
  --decisions "$DECISIONS" --out "$SUMMARY" | tee -a "$LOG"

python3 - "$SUMMARY" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    report = json.load(handle)
failures = report["diagnostics"]["records_with_llm_failure"]
if failures:
    raise SystemExit(f"experiment invalid: {failures} records contain LLM failures")
PY

echo "experiment completed successfully"
