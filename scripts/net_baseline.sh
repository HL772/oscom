#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARCH=${ARCH:-riscv64}
PLATFORM=${PLATFORM:-qemu}
OUT_DIR=${OUT_DIR:-"${ROOT}/build/net-baseline"}

mkdir -p "${OUT_DIR}"

run_case() {
  local name=$1
  shift
  local log="${OUT_DIR}/${name}.log"
  echo "==> ${name}" | tee "${log}"
  "$@" 2>&1 | tee -a "${log}"
}

run_case net env NET=1 EXPECT_NET=1 \
  make -C "${ROOT}" test-qemu-smoke ARCH="${ARCH}" PLATFORM="${PLATFORM}"

run_case net-loopback env NET=1 NET_LOOPBACK_TEST=1 EXPECT_NET_LOOPBACK=1 \
  make -C "${ROOT}" test-qemu-smoke ARCH="${ARCH}" PLATFORM="${PLATFORM}"

run_case tcp-echo env NET=1 TCP_ECHO_TEST=1 EXPECT_TCP_ECHO=1 \
  make -C "${ROOT}" test-qemu-smoke ARCH="${ARCH}" PLATFORM="${PLATFORM}"

run_case udp-echo env NET=1 UDP_ECHO_TEST=1 EXPECT_UDP_ECHO=1 \
  make -C "${ROOT}" test-qemu-smoke ARCH="${ARCH}" PLATFORM="${PLATFORM}"

echo "net baseline logs: ${OUT_DIR}"
