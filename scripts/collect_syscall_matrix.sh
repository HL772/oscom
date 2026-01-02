#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
OUT_DIR=${OUT_DIR:-"${ROOT}/build/syscall-matrix"}
STRACE_BIN=${STRACE_BIN:-strace}
IPERF3_BIN=${IPERF3_BIN:-iperf3}
REDIS_BIN=${REDIS_BIN:-redis-server}

missing=0
if ! command -v "${STRACE_BIN}" >/dev/null 2>&1; then
  echo "strace not found: ${STRACE_BIN}" >&2
  missing=1
fi
if ! command -v "${IPERF3_BIN}" >/dev/null 2>&1; then
  echo "iperf3 not found: ${IPERF3_BIN}" >&2
  missing=1
fi
if ! command -v "${REDIS_BIN}" >/dev/null 2>&1; then
  echo "redis-server not found: ${REDIS_BIN}" >&2
  missing=1
fi
if [[ "${missing}" -ne 0 ]]; then
  echo "Install missing tools and re-run. Example: sudo apt install strace iperf3 redis-server" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"

run_strace() {
  local label=$1
  shift
  local out_prefix="${OUT_DIR}/${label}"
  "${STRACE_BIN}" -ff -o "${out_prefix}" "$@" >/dev/null 2>&1 || true
}

run_strace "iperf3-help" "${IPERF3_BIN}" --help
run_strace "iperf3-version" "${IPERF3_BIN}" --version
run_strace "redis-version" "${REDIS_BIN}" --version

echo "Syscall traces written to ${OUT_DIR}"
