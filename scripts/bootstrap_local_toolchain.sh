#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="${TOOLS_DIR:-tools}"
JDK_DIR="$TOOLS_DIR/jdk-17"
MAVEN_DIR="$TOOLS_DIR/apache-maven"
JDK_TARBALL="${JDK_TARBALL:-/tmp/temurin-jdk17-tuna.tar.gz}"
MAVEN_TARBALL="${MAVEN_TARBALL:-/tmp/apache-maven.tar.gz}"
MAVEN_VERSION="${MAVEN_VERSION:-3.9.16}"
JDK_URL="${JDK_URL:-https://mirrors.tuna.tsinghua.edu.cn/Adoptium/17/jdk/x64/linux/OpenJDK17U-jdk_x64_linux_hotspot_17.0.19_10.tar.gz}"
MAVEN_URL="${MAVEN_URL:-https://mirrors.tuna.tsinghua.edu.cn/apache/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz}"

mkdir -p "$TOOLS_DIR"

if [[ ! -x "$JDK_DIR/bin/java" ]]; then
  echo "Downloading local JDK 17..."
  curl --fail -L -C - \
    "$JDK_URL" \
    -o "$JDK_TARBALL"
  rm -rf "$TOOLS_DIR"/jdk-* "$JDK_DIR"
  mkdir -p "$TOOLS_DIR/jdk-extract"
  tar -xzf "$JDK_TARBALL" -C "$TOOLS_DIR/jdk-extract"
  mv "$TOOLS_DIR"/jdk-extract/* "$JDK_DIR"
  rmdir "$TOOLS_DIR/jdk-extract"
else
  echo "Local JDK already exists at $JDK_DIR"
fi

if [[ ! -x "$MAVEN_DIR/bin/mvn" ]]; then
  echo "Downloading local Maven $MAVEN_VERSION..."
  curl --fail -L -C - \
    "$MAVEN_URL" \
    -o "$MAVEN_TARBALL"
  rm -rf "$TOOLS_DIR"/apache-maven-* "$MAVEN_DIR"
  tar -xzf "$MAVEN_TARBALL" -C "$TOOLS_DIR"
  mv "$TOOLS_DIR/apache-maven-$MAVEN_VERSION" "$MAVEN_DIR"
else
  echo "Local Maven already exists at $MAVEN_DIR"
fi

echo
echo "Local toolchain ready."
echo "Use it with:"
echo "  export JAVA_HOME=\"$PWD/$JDK_DIR\""
echo "  export PATH=\"$PWD/$JDK_DIR/bin:$PWD/$MAVEN_DIR/bin:\$PATH\""
