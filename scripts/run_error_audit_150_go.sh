#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
  echo "DEEPSEEK_API_KEY is not set" >&2
  exit 2
fi

SOURCE_INPUT="data/interim/owasp-zerofalse-style-1974.labeled.jsonl"
SOURCE_DECISIONS="data/results/owasp-1974-deepseek-official-v4-flash-20260712-205104/decisions.jsonl"
INPUT="data/interim/owasp-error-audit-150.jsonl"
MANIFEST="data/reports/owasp-error-audit-150.manifest.json"
BASE_CONFIG="configs/experiment.opencode-go.local.json"
DATABASE="data/codeql-db/owasp-benchmark-java-1.2-codeql-2.25.5-frozen"
MODEL="${MODEL:-deepseek-v4-flash}"
WORKERS="${WORKERS:-8}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
MODEL_SLUG="$(printf '%s' "$MODEL" | tr -cs 'A-Za-z0-9._-' '-')"
RUN_DIR="data/results/owasp-error-audit-150-${MODEL_SLUG}-${RUN_ID}"
CACHE_DIR="data/cache/owasp-error-audit-150-${MODEL_SLUG}-${RUN_ID}"
CONFIG="$RUN_DIR/experiment.json"

if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || (( WORKERS < 1 || WORKERS > 16 )); then
  echo "WORKERS must be an integer between 1 and 16 (got: $WORKERS)" >&2
  exit 2
fi

export PYTHONPATH="${PYTHONPATH:-}:src"
python3 scripts/build_error_audit_cohort.py \
  --input "$SOURCE_INPUT" \
  --decisions "$SOURCE_DECISIONS" \
  --out "$INPUT" \
  --manifest "$MANIFEST"

mkdir -p "$RUN_DIR" "$CACHE_DIR"
python3 - "$BASE_CONFIG" "$CONFIG" "$MODEL" <<'PY'
import json
import sys

source, destination, model = sys.argv[1:]
config = json.load(open(source))
config["llm"]["model"] = model
with open(destination, "w") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY

exec 9>"$DATABASE/.fpm-experiment.lock"
if ! flock -n 9; then
  echo "Another experiment still holds the CodeQL database lock" >&2
  exit 5
fi

echo "provider: OpenCode Go"
echo "model: $MODEL"
echo "run directory: $RUN_DIR"
echo "workers: $WORKERS"
python3 -u -m fpm_benchmark.cli llm-triage \
  --input "$INPUT" \
  --out "$RUN_DIR/decisions.jsonl" \
  --config "$CONFIG" \
  --mode iterative \
  --baseline ours_query_centered \
  --view auto \
  --codeql-db "$DATABASE" \
  --max-iterations 3 \
  --workers "$WORKERS" \
  --query-cache-dir "$CACHE_DIR" \
  --runtime-report "$RUN_DIR/runtime.json" 2>&1 | tee "$RUN_DIR/run.log"

python3 -m fpm_benchmark.cli evaluate \
  --decisions "$RUN_DIR/decisions.jsonl" --out "$RUN_DIR/metrics.json"
python3 scripts/summarize_decisions.py \
  --decisions "$RUN_DIR/decisions.jsonl" --out "$RUN_DIR/summary.json" | tee -a "$RUN_DIR/run.log"

python3 - "$RUN_DIR/summary.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
metrics = report["metrics"]["overall"]
diagnostics = report["diagnostics"]
failures = diagnostics["records_with_llm_failure"]
retention = metrics["operational"]["tp_retention"]
if failures:
    raise SystemExit(f"FAIL: {failures} records contain LLM failures")
if retention != 1.0:
    raise SystemExit(f"FAIL: TP retention is {retention:.2%}, expected 100%")
print("PASS: zero LLM failures and 100% TP retention")
PY

echo "experiment completed successfully: $RUN_DIR"
