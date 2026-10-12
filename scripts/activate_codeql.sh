#!/usr/bin/env bash

FPM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CODEQL_HOME="$FPM_ROOT/tools/codeql-bundle-v2.25.5/codeql"
export PATH="$CODEQL_HOME:$PATH"

if [[ -x "$FPM_ROOT/tools/jdk-17/bin/java" ]]; then
  export JAVA_HOME="$FPM_ROOT/tools/jdk-17"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

if [[ -x "$FPM_ROOT/tools/apache-maven/bin/mvn" ]]; then
  export PATH="$FPM_ROOT/tools/apache-maven/bin:$PATH"
fi

unset FPM_ROOT
