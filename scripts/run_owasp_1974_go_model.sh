#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
  echo "DEEPSEEK_API_KEY is not set" >&2
  exit 2
fi
if [[ -z "${MODEL:-}" ]]; then
  echo "MODEL is required, for example: MODEL=deepseek-v4-pro $0" >&2
  exit 2
fi

INPUT="${INPUT:-data/interim/owasp-zerofalse-style-1974.labeled.jsonl}"
BASE_CONFIG="${BASE_CONFIG:-configs/experiment.opencode-go.local.json}"
DATABASE="${DATABASE:-data/codeql-db/owasp-benchmark-java-1.2-codeql-2.25.5-frozen}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
WORKERS="${WORKERS:-8}"
MODEL_SLUG="$(printf '%s' "$MODEL" | tr -cs 'A-Za-z0-9._-' '-')"
RUN_DIR="data/results/owasp-1974-${MODEL_SLUG}-${RUN_ID}"
DECISIONS="${RUN_DIR}/decisions.jsonl"
RUNTIME="${RUN_DIR}/runtime.json"
METRICS="${RUN_DIR}/metrics.json"
SUMMARY="${RUN_DIR}/summary.json"
LOG="${RUN_DIR}/run.log"
CONFIG="${RUN_DIR}/experiment.json"
CACHE_DIR="data/cache/owasp-1974-${MODEL_SLUG}-${RUN_ID}"

if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || (( WORKERS < 1 || WORKERS > 16 )); then
  echo "WORKERS must be an integer between 1 and 16 (got: $WORKERS)" >&2
  exit 2
fi

if [[ ! -f "$INPUT" ]] || [[ "$(wc -l < "$INPUT")" -ne 1974 ]]; then
  echo "Expected a 1974-record input at $INPUT" >&2
  exit 2
fi
if [[ ! -f "$BASE_CONFIG" ]]; then
  echo "Missing base config: $BASE_CONFIG" >&2
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
  echo "Stop the earlier run before starting this one" >&2
  exit 5
fi

python3 - "$BASE_CONFIG" "$CONFIG" "$MODEL" <<'PY'
import json
import sys

source, destination, model = sys.argv[1:]
with open(source) as handle:
    config = json.load(handle)
config["llm"]["model"] = model
with open(destination, "w") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY

echo "model: $MODEL"
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

python3 -m fpm_benchmark.cli evaluate \
  --decisions "$DECISIONS" \
  --out "$METRICS"

python3 scripts/summarize_decisions.py \
  --decisions "$DECISIONS" \
  --out "$SUMMARY" | tee -a "$LOG"

if python3 - "$SUMMARY" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    report = json.load(handle)
raise SystemExit(report["diagnostics"]["records_with_llm_failure"] > 0)
PY
then
  echo "experiment completed successfully"
else
  echo "experiment completed with LLM failures; inspect $SUMMARY" >&2
  exit 3
fi
