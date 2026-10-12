#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DEEPSEEK_OFFICIAL_API_KEY:-}" ]]; then
  echo "DEEPSEEK_OFFICIAL_API_KEY is not set" >&2
  exit 2
fi

SOURCE_INPUT="data/interim/owasp-zerofalse-style-1974.labeled.jsonl"
PREVIOUS="data/results/owasp-1974-deepseek-official-v4-flash-20260712-173521/decisions.jsonl"
INPUT="data/interim/owasp-targeted-regression-50.jsonl"
MANIFEST="data/interim/owasp-targeted-regression-50.manifest.json"
CONFIG="configs/experiment.deepseek-official.json"
DATABASE="data/codeql-db/owasp-benchmark-java-1.2-codeql-2.25.5-frozen"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
WORKERS="${WORKERS:-16}"
RUN_DIR="data/results/owasp-targeted-50-deepseek-official-${RUN_ID}"
CACHE_DIR="data/cache/owasp-targeted-50-deepseek-official-${RUN_ID}"

export PYTHONPATH="${PYTHONPATH:-}:src"
python3 scripts/build_targeted_regression.py \
  --input "$SOURCE_INPUT" \
  --previous-decisions "$PREVIOUS" \
  --out "$INPUT" \
  --manifest "$MANIFEST"

mkdir -p "$RUN_DIR" "$CACHE_DIR"
exec 9>"$DATABASE/.fpm-experiment.lock"
if ! flock -n 9; then
  echo "Another experiment still holds the CodeQL database lock" >&2
  exit 5
fi

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
tp_retention = metrics["operational"]["tp_retention"]
unknown_rate = metrics["unknown"]["rate"]
if failures:
    raise SystemExit(f"FAIL: {failures} records contain LLM failures")
if tp_retention != 1.0:
    raise SystemExit(f"FAIL: TP retention is {tp_retention:.2%}, expected 100%")
if unknown_rate is not None and unknown_rate > 0.10:
    raise SystemExit(f"FAIL: unknown rate is {unknown_rate:.2%}, expected <= 10%")
print("PASS: zero LLM failures, 100% TP retention, unknown rate <= 10%")
PY
