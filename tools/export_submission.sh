#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
DIST="$ROOT/dist"

rm -rf "$DIST"
mkdir -p "$DIST/kernel-src" "$DIST/build-env" "$DIST/docs" "$DIST/tests"

# Copy full source tree except dist/ into dist/kernel-src
(
  cd "$ROOT"
  tar --exclude="./dist" -cf - . | tar -xf - -C "$DIST/kernel-src"
)

# Build environment files
if [[ -d "$ROOT/build_env" ]]; then
  cp -a "$ROOT/build_env/." "$DIST/build-env/"
fi
cp -a "$ROOT/rust-toolchain.toml" "$DIST/build-env/" 2>/dev/null || true

# Docs
if [[ -d "$ROOT/docs" ]]; then
  cp -a "$ROOT/docs/." "$DIST/docs/"
fi

# Tests and scripts
if [[ -d "$ROOT/scripts" ]]; then
  cp -a "$ROOT/scripts/." "$DIST/tests/"
fi

# Manifest
GIT_COMMIT=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_CMD="make build ARCH=riscv64 PLATFORM=qemu"
TEST_CMD="make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu FS=path/to/ext4.img"

cat <<MANIFEST > "$DIST/MANIFEST.json"
{
  "project": "Project Aurora",
  "git_commit": "${GIT_COMMIT}",
  "build_command": "${BUILD_CMD}",
  "test_command": "${TEST_CMD}",
  "exported_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "notes": "Initial scaffold export"
}
MANIFEST

# SHA256 sums
(
  cd "$DIST"
  find . -type f ! -name "SHA256SUMS" -print0 | sort -z | xargs -0 sha256sum > "$DIST/SHA256SUMS"
)

echo "Exported submission to $DIST"
