#!/usr/bin/env bash
set -euo pipefail

check() {
  local name="$1"
  local cmd="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    printf "%-12s OK  %s\n" "$name" "$(command -v "$cmd")"
  else
    printf "%-12s MISSING\n" "$name"
  fi
}

check_local_codeql() {
  if [[ -x "codeql-home/codeql/codeql" ]]; then
    printf "%-12s OK  %s\n" "codeql-local" "$PWD/codeql-home/codeql/codeql"
  else
    printf "%-12s MISSING\n" "codeql-local"
  fi
}

check "python3" "python3"
check "git" "git"
check "curl" "curl"
check "java" "java"
check "mvn" "mvn"
check "codeql" "codeql"
check_local_codeql

if [[ -x "tools/jdk-17/bin/java" ]]; then
  printf "%-12s OK  %s\n" "jdk-local" "$PWD/tools/jdk-17/bin/java"
else
  printf "%-12s MISSING\n" "jdk-local"
fi

if [[ -x "tools/apache-maven/bin/mvn" ]]; then
  printf "%-12s OK  %s\n" "mvn-local" "$PWD/tools/apache-maven/bin/mvn"
else
  printf "%-12s MISSING\n" "mvn-local"
fi

echo
echo "For this experiment, Java and Maven are required to build OWASP Benchmark Java."
echo "If Java/Maven are missing, run: scripts/bootstrap_local_toolchain.sh"
echo "If CodeQL is missing, run: scripts/bootstrap_assets.sh"
