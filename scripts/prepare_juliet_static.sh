#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JULIET_ROOT="${JULIET_ROOT:-$ROOT_DIR/data/raw/juliet-java-1.3/Java}"
CODEQL_BIN="${CODEQL_BIN:-$ROOT_DIR/tools/codeql-bundle-v2.25.5/codeql/codeql}"
JAVA_HOME="${JAVA_HOME:-$ROOT_DIR/tools/jdk-17}"
DB_DIR="${DB_DIR:-$ROOT_DIR/data/codeql-db/juliet-target-cwes-compiled}"
SARIF_OUT="${SARIF_OUT:-$ROOT_DIR/data/raw/juliet-target-cwes-compiled.sarif}"
CALLABLES_BQRS="${CALLABLES_BQRS:-$ROOT_DIR/data/raw/juliet-target-callables.bqrs}"
CALLABLES_JSON="${CALLABLES_JSON:-$ROOT_DIR/data/raw/juliet-target-callables.json}"
EVIDENCE_OUT="${EVIDENCE_OUT:-$ROOT_DIR/data/interim/juliet-target-evidence.labeled.jsonl}"
SUMMARY_OUT="${SUMMARY_OUT:-$ROOT_DIR/data/interim/juliet-target-summary.json}"
CLASSES_DIR="${CLASSES_DIR:-/tmp/juliet-target-cwes-codeql-classes}"
FORCE="${FORCE:-0}"

CWE_DIRS=(
  CWE23_Relative_Path_Traversal
  CWE36_Absolute_Path_Traversal
  CWE78_OS_Command_Injection
  CWE80_XSS
  CWE81_XSS_Error_Message
  CWE83_XSS_Attribute
  CWE89_SQL_Injection
  CWE90_LDAP_Injection
  CWE327_Use_Broken_Crypto
  CWE336_Same_Seed_in_PRNG
  CWE338_Weak_PRNG
  CWE614_Sensitive_Cookie_Without_Secure
  CWE643_Xpath_Injection
)

if [[ ! -x "$CODEQL_BIN" ]]; then
  echo "CodeQL executable not found: $CODEQL_BIN" >&2
  exit 2
fi
if [[ ! -x "$JAVA_HOME/bin/javac" ]]; then
  echo "javac not found: $JAVA_HOME/bin/javac" >&2
  exit 2
fi
if [[ ! -d "$JULIET_ROOT/src/testcases" ]]; then
  echo "Juliet Java root not found: $JULIET_ROOT" >&2
  exit 2
fi

export JAVA_HOME
export JAVAC_BIN="$JAVA_HOME/bin/javac"
export PATH="$JAVA_HOME/bin:$PATH"
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

mkdir -p "$(dirname "$DB_DIR")" "$(dirname "$SARIF_OUT")" \
  "$(dirname "$EVIDENCE_OUT")"

BUILD_COMMAND="$ROOT_DIR/scripts/build_juliet_subset.sh $JULIET_ROOT $CLASSES_DIR ${CWE_DIRS[*]}"

if [[ "$FORCE" == "1" || ! -d "$DB_DIR" ]]; then
  "$CODEQL_BIN" database create "$DB_DIR" \
    --language=java \
    --source-root="$JULIET_ROOT" \
    --command="$BUILD_COMMAND" \
    --threads=0 \
    --overwrite
else
  echo "reusing CodeQL database: $DB_DIR"
fi

if [[ "$FORCE" == "1" || ! -f "$SARIF_OUT" ]]; then
  "$CODEQL_BIN" database analyze "$DB_DIR" \
    codeql/java-queries:codeql-suites/java-code-scanning.qls \
    --format=sarif-latest \
    --output="$SARIF_OUT" \
    --threads=0 \
    --ram=8192
else
  echo "reusing SARIF: $SARIF_OUT"
fi

if [[ "$FORCE" == "1" || ! -f "$CALLABLES_BQRS" ]]; then
  "$CODEQL_BIN" query run "$ROOT_DIR/queries/juliet-labeling/CallableLocations.ql" \
    --database="$DB_DIR" \
    --output="$CALLABLES_BQRS"
else
  echo "reusing callable ranges: $CALLABLES_BQRS"
fi

"$CODEQL_BIN" bqrs decode "$CALLABLES_BQRS" \
  --format=json \
  --output="$CALLABLES_JSON"

python3 -m fpm_benchmark.cli prepare-juliet \
  --sarif "$SARIF_OUT" \
  --callables "$CALLABLES_JSON" \
  --source-root "$JULIET_ROOT" \
  --out "$EVIDENCE_OUT" \
  --summary "$SUMMARY_OUT"

python3 -m json.tool "$SUMMARY_OUT"
