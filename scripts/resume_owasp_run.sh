#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
  echo "DEEPSEEK_API_KEY is not set" >&2
  exit 2
fi
if [[ -z "${RUN_DIR:-}" ]]; then
  echo "RUN_DIR is required" >&2
  exit 2
fi

DECISIONS="${RUN_DIR}/decisions.jsonl"
CONFIG="${CONFIG:-${RUN_DIR}/experiment.json}"
RUNTIME="${RUN_DIR}/runtime.json"
METRICS="${RUN_DIR}/metrics.json"
SUMMARY="${RUN_DIR}/summary.json"
LOG="${RUN_DIR}/run.log"
DATABASE="${DATABASE:-data/codeql-db/owasp-benchmark-java-1.2-codeql-2.25.5-frozen}"
WORKERS="${WORKERS:-8}"
CACHE_DIR="data/cache/$(basename "$RUN_DIR")"

if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || (( WORKERS < 1 || WORKERS > 16 )); then
  echo "WORKERS must be an integer between 1 and 16 (got: $WORKERS)" >&2
  exit 2
fi

if [[ ! -f "$DECISIONS" ]] || [[ "$(wc -l < "$DECISIONS")" -ne 1974 ]]; then
  echo "Expected 1974 saved decisions at $DECISIONS" >&2
  exit 2
fi
if [[ ! -f "$CONFIG" ]]; then
  CONFIG="configs/experiment.opencode-go.local.json"
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "Missing experiment config" >&2
  exit 2
fi
if [[ ! -f "$DATABASE/codeql-database.yml" ]]; then
  echo "Missing CodeQL database: $DATABASE" >&2
  exit 2
fi

FAILED_QUERIES="$(python3 - "$DECISIONS" <<'PY'
import json
import sys

count = 0
with open(sys.argv[1]) as handle:
    for line in handle:
        record = json.loads(line)
        count += sum(
            item.get("status") not in {"ok", "empty"}
            for item in record.get("query_history", [])
        )
print(count)
PY
)"
if [[ "$FAILED_QUERIES" -ne 0 ]]; then
  echo "Cannot safely resume: checkpoint contains $FAILED_QUERIES failed queries" >&2
  echo "Restart the experiment after the other CodeQL process has stopped" >&2
  exit 4
fi

export PYTHONPATH="${PYTHONPATH:-}:src"

exec 9>"$DATABASE/.fpm-experiment.lock"
if ! flock -n 9; then
  echo "Another experiment still holds the CodeQL database lock" >&2
  echo "Stop the earlier run before resuming this one" >&2
  exit 5
fi

echo "resuming: $RUN_DIR" | tee -a "$LOG"
python3 -u -m fpm_benchmark.cli llm-triage \
  --input "$DECISIONS" \
  --out "$DECISIONS" \
  --config "$CONFIG" \
  --mode iterative \
  --baseline ours_query_centered \
  --view auto \
  --codeql-db "$DATABASE" \
  --max-iterations 3 \
  --workers "$WORKERS" \
  --query-cache-dir "$CACHE_DIR" \
  --runtime-report "$RUNTIME" \
  --resume 2>&1 | tee -a "$LOG"

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
