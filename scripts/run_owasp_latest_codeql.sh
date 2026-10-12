#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CODEQL_BIN="${CODEQL_BIN:-$ROOT_DIR/tools/codeql-bundle-v2.25.5/codeql/codeql}"
QUERY_SOURCE="${QUERY_SOURCE:-$ROOT_DIR/tools/codeql-queries-v2.26.0}"
DATABASE="${DATABASE:-$ROOT_DIR/data/codeql-db/owasp-benchmark-java-1.2-codeql-2.25.5-frozen}"
SOURCE_ROOT="${SOURCE_ROOT:-$ROOT_DIR/data/source/owasp-benchmark-java-1.2}"
EXPECTED="${EXPECTED:-$SOURCE_ROOT/expectedresults-1.2.csv}"
CONFIG="${CONFIG:-$ROOT_DIR/configs/experiment.json}"
THREADS="${THREADS:-0}"
CHECK_ONLY="${CHECK_ONLY:-0}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"

if [[ ! -x "$CODEQL_BIN" ]]; then
  echo "CodeQL executable not found: $CODEQL_BIN" >&2
  exit 1
fi

if [[ ! -f "$DATABASE/codeql-database.yml" ]]; then
  echo "Frozen OWASP CodeQL database not found: $DATABASE" >&2
  exit 1
fi

if [[ ! -f "$EXPECTED" ]]; then
  echo "OWASP ground truth not found: $EXPECTED" >&2
  exit 1
fi

QUERY_PACK="$QUERY_SOURCE/java/ql/src"
QUERY_SUITE="$QUERY_PACK/codeql-suites/java-code-scanning.qls"
if [[ ! -f "$QUERY_PACK/qlpack.yml" || ! -f "$QUERY_SUITE" ]]; then
  echo "CodeQL v2.26.0 Java query source is incomplete: $QUERY_SOURCE" >&2
  exit 1
fi

PACK_INFO="$($CODEQL_BIN resolve packs --additional-packs="$QUERY_SOURCE" --format=json | jq -c \
  --arg path "$QUERY_PACK/qlpack.yml" \
  '[.. | objects | select(has("codeql/java-queries")) | .["codeql/java-queries"] |
    select(type == "object" and .path == $path)] | first')"
PACK_VERSION="$(jq -r '.version // empty' <<<"$PACK_INFO")"
if [[ -z "$PACK_VERSION" ]]; then
  echo "CodeQL could not resolve codeql/java-queries from: $QUERY_SOURCE" >&2
  exit 1
fi

QUERY_SOURCE_COMMIT="$(git -C "$QUERY_SOURCE" rev-parse HEAD 2>/dev/null || printf unknown)"

RUN_DIR="${RUN_DIR:-$ROOT_DIR/data/results/owasp-codeql-default-java-queries-${PACK_VERSION}-${RUN_ID}}"
SARIF="$RUN_DIR/alerts.sarif"
EVIDENCE="$RUN_DIR/evidence.jsonl"
MATCHED="$RUN_DIR/evidence.matched.jsonl"
SUMMARY="$RUN_DIR/ground-truth-summary.json"
MANIFEST="$RUN_DIR/manifest.json"

CODEQL_VERSION_JSON="$($CODEQL_BIN version --format=json)"
CODEQL_VERSION="$(jq -r '.version' <<<"$CODEQL_VERSION_JSON")"

echo "run directory: $RUN_DIR"
echo "CodeQL CLI: $CODEQL_VERSION"
echo "Java query pack: codeql/java-queries@$PACK_VERSION"
echo "query source commit: $QUERY_SOURCE_COMMIT"
echo "query suite: java-code-scanning.qls"
echo "database: $DATABASE"
echo "threads: $THREADS"
echo

if [[ "$CHECK_ONLY" == "1" ]]; then
  QUERY_COUNT="$($CODEQL_BIN resolve queries "$QUERY_SUITE" \
    --additional-packs="$QUERY_SOURCE" | wc -l)"
  echo "health check passed: $QUERY_COUNT queries resolved"
  exit 0
fi

mkdir -p "$RUN_DIR"

"$CODEQL_BIN" database analyze "$DATABASE" "$QUERY_SUITE" \
  --additional-packs="$QUERY_SOURCE" \
  --format=sarif-latest \
  --output="$SARIF" \
  --threads="$THREADS" \
  --rerun \
  --sarif-add-snippets \
  --sarif-run-property="fpm.queryPack=codeql/java-queries@$PACK_VERSION" \
  --sarif-run-property="fpm.codeqlCli=$CODEQL_VERSION"

PYTHONPATH=src python3 -m fpm_benchmark.cli parse-sarif \
  --sarif "$SARIF" \
  --expected "$EXPECTED" \
  --source-root "$SOURCE_ROOT" \
  --config "$CONFIG" \
  --out "$EVIDENCE"

PYTHONPATH=src python3 -m fpm_benchmark.cli dataset-summary \
  --input "$EVIDENCE" \
  --expected "$EXPECTED" \
  --matched-out "$MATCHED" \
  --out "$SUMMARY" \
  --config "$CONFIG"

jq -n \
  --arg created_at "$(date --iso-8601=seconds)" \
  --arg git_commit "$(git rev-parse HEAD 2>/dev/null || printf unknown)" \
  --arg database "$DATABASE" \
  --arg database_metadata_sha256 "$(sha256sum "$DATABASE/codeql-database.yml" | cut -d' ' -f1)" \
  --arg query_pack "codeql/java-queries" \
  --arg query_pack_version "$PACK_VERSION" \
  --arg query_source_commit "$QUERY_SOURCE_COMMIT" \
  --arg query_suite "$QUERY_SUITE" \
  --arg sarif "$SARIF" \
  --arg evidence "$EVIDENCE" \
  --arg matched "$MATCHED" \
  --arg summary "$SUMMARY" \
  --argjson codeql "$CODEQL_VERSION_JSON" \
  --argjson threads "$THREADS" \
  '{
    created_at: $created_at,
    git_commit: $git_commit,
    codeql: $codeql,
    query_pack: {
      name: $query_pack,
      version: $query_pack_version,
      source_commit: $query_source_commit
    },
    query_suite: $query_suite,
    database: $database,
    database_metadata_sha256: $database_metadata_sha256,
    threads: $threads,
    artifacts: {
      sarif: $sarif,
      evidence: $evidence,
      matched_evidence: $matched,
      ground_truth_summary: $summary
    }
  }' > "$MANIFEST"

echo
echo "Ground-truth alignment"
jq '{
  total_target_alerts,
  exact_cwe_alerts: ([.by_cwe[].exact_cwe_alerts] | add),
  cross_cwe_alerts: ([.by_cwe[].cross_cwe_alerts] | add),
  final_labeled_alerts,
  unmatched_alerts,
  tp_alerts,
  fp_alerts,
  unique_benchmark_tests
}' "$SUMMARY"

echo
printf '%-9s %8s %8s %8s %8s %8s %10s\n' \
  "CWE" "alerts" "exact" "cross" "TP" "FP" "tests"
jq -r '
  .by_cwe | to_entries[] |
  [.key, .value.alerts, .value.exact_cwe_alerts, .value.cross_cwe_alerts,
   .value.tp_alerts, .value.fp_alerts, .value.unique_benchmark_tests] |
  @tsv
' "$SUMMARY" | while IFS=$'\t' read -r cwe alerts exact cross tp fp tests; do
  printf '%-9s %8s %8s %8s %8s %8s %10s\n' \
    "$cwe" "$alerts" "$exact" "$cross" "$tp" "$fp" "$tests"
done

echo
echo "wrote SARIF to $SARIF"
echo "wrote matched evidence to $MATCHED"
echo "wrote summary to $SUMMARY"
echo "wrote manifest to $MANIFEST"
