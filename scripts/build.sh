#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
ARCH=${ARCH:-riscv64}
PLATFORM=${PLATFORM:-qemu}
MODE=${MODE:-debug}
USER_TEST=${USER_TEST:-0}
SCHED_DEMO=${SCHED_DEMO:-0}
EXT4_WRITE_TEST=${EXT4_WRITE_TEST:-0}
NET_LOOPBACK_TEST=${NET_LOOPBACK_TEST:-0}
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
if [[ "${USER_TEST}" == "1" ]]; then
  CARGO_FLAGS+=(--features user-test)
fi
if [[ "${SCHED_DEMO}" == "1" ]]; then
  CARGO_FLAGS+=(--features sched-demo)
fi
if [[ "${EXT4_WRITE_TEST}" == "1" ]]; then
  CARGO_FLAGS+=(--features ext4-write-test)
fi
if [[ "${NET_LOOPBACK_TEST}" == "1" ]]; then
  CARGO_FLAGS+=(--features net-loopback-test)
fi

(
  cd "${ROOT}"
  cargo build -p "${CRATE}" --target "${TARGET}" "${CARGO_FLAGS[@]}"
)

KERNEL="${ROOT}/target/${TARGET}/${OUT_DIR}/${CRATE}"
echo "Built kernel: ${KERNEL}"
