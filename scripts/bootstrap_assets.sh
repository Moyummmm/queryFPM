#!/usr/bin/env bash
set -euo pipefail

BENCHMARK_DIR="${BENCHMARK_DIR:-BenchmarkJava}"
CODEQL_HOME="${CODEQL_HOME:-codeql-home}"
CODEQL_ZIP="${CODEQL_ZIP:-/tmp/codeql-linux64.zip}"

if [[ ! -d "$BENCHMARK_DIR/.git" ]]; then
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git "$BENCHMARK_DIR"
else
  echo "$BENCHMARK_DIR already exists; skipping clone."
fi

if [[ ! -x "$CODEQL_HOME/codeql/codeql" ]]; then
  mkdir -p "$CODEQL_HOME"
  curl --fail -L -C - \
    https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip \
    -o "$CODEQL_ZIP"
  if ! command -v unzip >/dev/null 2>&1; then
    echo "unzip is required to extract CodeQL CLI." >&2
    exit 127
  fi
  unzip -q "$CODEQL_ZIP" -d "$CODEQL_HOME"
else
  echo "CodeQL CLI already exists at $CODEQL_HOME/codeql/codeql; skipping download."
fi

echo
echo "Assets ready."
echo "Add CodeQL to PATH with:"
echo "  export PATH=\"$PWD/$CODEQL_HOME/codeql:\$PATH\""
