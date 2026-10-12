#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 JULIET_JAVA_ROOT CLASSES_DIR CWE_DIR [CWE_DIR ...]" >&2
  exit 2
fi

JULIET_ROOT="$(cd "$1" && pwd)"
CLASSES_DIR="$2"
shift 2

JAVAC_BIN="${JAVAC_BIN:-javac}"
SOURCE_LIST="$(mktemp)"
trap 'rm -f "$SOURCE_LIST"' EXIT

find "$JULIET_ROOT/src/testcasesupport" \
  -type f -name '*.java' ! -path '*/antbuild/*' -print >"$SOURCE_LIST"

for cwe_dir in "$@"; do
  find "$JULIET_ROOT/src/testcases/$cwe_dir" \
    -type f -name '*.java' ! -path '*/antbuild/*' -print >>"$SOURCE_LIST"
done

mkdir -p "$CLASSES_DIR"
"$JAVAC_BIN" \
  -encoding UTF-8 \
  -cp "$JULIET_ROOT/lib/*" \
  -d "$CLASSES_DIR" \
  "@$SOURCE_LIST"
