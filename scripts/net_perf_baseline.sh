#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARCH=${ARCH:-riscv64}
PLATFORM=${PLATFORM:-qemu}
OUT_DIR=${OUT_DIR:-"${ROOT}/build/net-perf"}
PERF_ROOTFS_DIR=${PERF_ROOTFS_DIR:-}
PERF_INIT_ELF=${PERF_INIT_ELF:-}
PERF_EXPECT=${PERF_EXPECT:-}

FS_IMAGE="${OUT_DIR}/rootfs-perf.ext4"
LOG="${OUT_DIR}/perf.log"
QEMU_LOG="${OUT_DIR}/qemu-smoke.log"

mkdir -p "${OUT_DIR}"

if [[ -z "${PERF_INIT_ELF}" ]]; then
  echo "PERF_INIT_ELF is required (custom /init that runs iperf/redis)." >&2
  exit 2
fi
if [[ ! -f "${PERF_INIT_ELF}" ]]; then
  echo "PERF_INIT_ELF not found: ${PERF_INIT_ELF}" >&2
  exit 1
fi
if [[ -z "${PERF_ROOTFS_DIR}" ]]; then
  echo "PERF_ROOTFS_DIR is required (directory with iperf3/redis binaries)." >&2
  exit 2
fi
if [[ ! -d "${PERF_ROOTFS_DIR}" ]]; then
  echo "PERF_ROOTFS_DIR not found: ${PERF_ROOTFS_DIR}" >&2
  exit 1
fi

OUT="${FS_IMAGE}" INIT_ELF="${PERF_INIT_ELF}" INIT_ELF_SKIP_BUILD=1 EXTRA_ROOTFS_DIR="${PERF_ROOTFS_DIR}" \
  "${ROOT}/scripts/mkfs_ext4.sh"

NET=1 EXPECT_NET=1 USER_TEST=1 EXPECT_EXT4=1 EXPECT_EXT4_ISSUE=0 FS="${FS_IMAGE}" LOG_FILE="${QEMU_LOG}" \
  "${ROOT}/scripts/test_qemu_smoke.sh" 2>&1 | tee "${LOG}"

if [[ -n "${PERF_EXPECT}" ]]; then
  IFS=',' read -r -a markers <<< "${PERF_EXPECT}"
  for marker in "${markers[@]}"; do
    if ! rg -F "${marker}" "${QEMU_LOG}" >/dev/null; then
      echo "missing marker: ${marker}" >&2
      exit 1
    fi
  done
fi

echo "net perf log: ${LOG}"
echo "qemu log: ${QEMU_LOG}"
