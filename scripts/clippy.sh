#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
TARGET=riscv64gc-unknown-none-elf

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup not found; install rustup and the ${TARGET} target." >&2
  exit 1
fi

RUSTUP_TARGETS=$(rustup target list --installed 2>&1) || {
  echo "rustup failed while listing installed targets:" >&2
  echo "${RUSTUP_TARGETS}" >&2
  exit 1
}

if ! grep -q "^${TARGET}$" <<<"${RUSTUP_TARGETS}"; then
  echo "Rust target ${TARGET} not installed." >&2
  echo "Install with: rustup target add ${TARGET}" >&2
  exit 1
fi

(cd "${ROOT}" && cargo clippy -p axruntime --target "${TARGET}")
