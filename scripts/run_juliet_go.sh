#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
  echo "DEEPSEEK_API_KEY is not set" >&2
  exit 2
fi

MODEL="${MODEL:-deepseek-v4-flash}"
SCOPE="${SCOPE:-pilot}"
WORKERS="${WORKERS:-8}"
BASE_CONFIG="${BASE_CONFIG:-configs/experiment.opencode-go.local.json}"
DATABASE="${DATABASE:-data/codeql-db/juliet-target-cwes-compiled}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
MODEL_SLUG="$(printf '%s' "$MODEL" | tr -cs 'A-Za-z0-9._-' '-')"

case "$SCOPE" in
  pilot)
    INPUT="${INPUT:-data/interim/juliet-pilot-204.jsonl}"
    EXPECTED_RECORDS=204
    ;;
  full)
    INPUT="${INPUT:-data/interim/juliet-target-evidence.labeled.jsonl}"
    EXPECTED_RECORDS=4012
    ;;
  *)
    echo "SCOPE must be pilot or full (got: $SCOPE)" >&2
    exit 2
    ;;
esac

RUN_DIR="data/results/juliet-${SCOPE}-${MODEL_SLUG}-${RUN_ID}"
DECISIONS="$RUN_DIR/decisions.jsonl"
RUNTIME="$RUN_DIR/runtime.json"
METRICS="$RUN_DIR/metrics.json"
SUMMARY="$RUN_DIR/summary.json"
LOG="$RUN_DIR/run.log"
CONFIG="$RUN_DIR/experiment.json"
CACHE_DIR="data/cache/juliet-${SCOPE}-${MODEL_SLUG}-${RUN_ID}"

if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || (( WORKERS < 1 || WORKERS > 16 )); then
  echo "WORKERS must be an integer between 1 and 16 (got: $WORKERS)" >&2
  exit 2
fi
if [[ ! -f "$BASE_CONFIG" ]]; then
  echo "Missing base config: $BASE_CONFIG" >&2
  exit 2
fi
if [[ ! -f "$DATABASE/codeql-database.yml" ]]; then
  echo "Missing CodeQL database: $DATABASE" >&2
  echo "Run: bash scripts/prepare_juliet_static.sh" >&2
  exit 2
fi

export PYTHONPATH="${PYTHONPATH:-}:src"

if [[ "$SCOPE" == "pilot" ]]; then
  python3 scripts/build_juliet_pilot.py
fi
if [[ ! -f "$INPUT" ]] || [[ "$(wc -l < "$INPUT")" -ne "$EXPECTED_RECORDS" ]]; then
  echo "Expected $EXPECTED_RECORDS records at $INPUT" >&2
  exit 2
fi

mkdir -p "$RUN_DIR" "$CACHE_DIR"
exec 9>"$DATABASE/.fpm-experiment.lock"
if ! flock -n 9; then
  echo "Another experiment still holds the Juliet CodeQL database lock" >&2
  exit 5
fi

python3 - "$BASE_CONFIG" "$CONFIG" "$MODEL" "$DATABASE" <<'PY'
import json
import sys

source, destination, model, database = sys.argv[1:]
with open(source) as handle:
    config = json.load(handle)
config["dataset"] = {
    "name": "NIST SARD Juliet Test Suite for Java",
    "version": "1.3",
    "label_blind": True,
}
config["codeql"]["database"] = database
config["codeql"]["sarif"] = "data/raw/juliet-target-cwes-compiled.sarif"
config["llm"]["model"] = model
with open(destination, "w") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY

echo "scope: $SCOPE"
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

python3 - "$SUMMARY" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    report = json.load(handle)
failures = report["diagnostics"]["records_with_llm_failure"]
if failures:
    raise SystemExit(f"experiment completed with {failures} LLM failures")
print("experiment completed successfully")
PY
