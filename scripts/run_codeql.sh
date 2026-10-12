#!/usr/bin/env bash
set -euo pipefail

BENCHMARK_DIR="${BENCHMARK_DIR:-BenchmarkJava}"
DB_DIR="${DB_DIR:-benchmark-db}"
SARIF_OUT="${SARIF_OUT:-data/raw/codeql-default.sarif}"
QUERY_SUITE="${QUERY_SUITE:-codeql/java-queries}"
ROOT_DIR="$(pwd)"
BENCHMARK_ABS="$(cd "$BENCHMARK_DIR" && pwd)"
DB_PARENT="$(dirname "$DB_DIR")"
DB_NAME="$(basename "$DB_DIR")"
mkdir -p "$DB_PARENT"
DB_ABS="$(cd "$DB_PARENT" && pwd)/$DB_NAME"
SARIF_PARENT="$(dirname "$SARIF_OUT")"
mkdir -p "$SARIF_PARENT"
SARIF_ABS="$(cd "$SARIF_PARENT" && pwd)/$(basename "$SARIF_OUT")"

CODEQL_BIN="${CODEQL_BIN:-codeql}"
if [[ -x "codeql-home/codeql/codeql" && "$CODEQL_BIN" == "codeql" ]]; then
  CODEQL_BIN="$ROOT_DIR/codeql-home/codeql/codeql"
fi

if [[ -x "$ROOT_DIR/tools/jdk-17/bin/java" ]]; then
  export JAVA_HOME="$ROOT_DIR/tools/jdk-17"
  export PATH="$ROOT_DIR/tools/jdk-17/bin:$PATH"
fi

if [[ -x "$ROOT_DIR/tools/apache-maven/bin/mvn" ]]; then
  export PATH="$ROOT_DIR/tools/apache-maven/bin:$PATH"
fi

if ! command -v "$CODEQL_BIN" >/dev/null 2>&1; then
  echo "codeql was not found on PATH. Install CodeQL CLI first." >&2
  exit 127
fi

if ! command -v java >/dev/null 2>&1; then
  echo "java was not found on PATH. Install a JDK before creating the CodeQL database." >&2
  exit 127
fi

if ! command -v mvn >/dev/null 2>&1; then
  echo "mvn was not found on PATH. Install Maven before creating the CodeQL database." >&2
  exit 127
fi

pushd "$BENCHMARK_ABS" >/dev/null
"$CODEQL_BIN" database create "$DB_ABS" \
  --language=java \
  --source-root . \
  --command="mvn -q -DskipTests package"
popd >/dev/null

"$CODEQL_BIN" database analyze "$DB_ABS" "$QUERY_SUITE" \
  --format=sarif-latest \
  --output="$SARIF_ABS" \
  --download
