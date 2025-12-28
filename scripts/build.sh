#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
ARCH=${ARCH:-riscv64}
PLATFORM=${PLATFORM:-qemu}
MODE=${MODE:-debug}
TARGET=riscv64gc-unknown-none-elf
CRATE=axruntime

if [[ "${ARCH}" != "riscv64" || "${PLATFORM}" != "qemu" ]]; then
  echo "Only ARCH=riscv64 PLATFORM=qemu is supported right now." >&2
  exit 1
fi

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

CARGO_FLAGS=()
OUT_DIR=debug
if [[ "${MODE}" == "release" ]]; then
  CARGO_FLAGS+=(--release)
  OUT_DIR=release
fi

(
  cd "${ROOT}"
  cargo build -p "${CRATE}" --target "${TARGET}" "${CARGO_FLAGS[@]}"
)

KERNEL="${ROOT}/target/${TARGET}/${OUT_DIR}/${CRATE}"
echo "Built kernel: ${KERNEL}"
