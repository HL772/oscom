#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
ARCH=${ARCH:-riscv64}
PLATFORM=${PLATFORM:-qemu}
MODE=${MODE:-debug}
TARGET=riscv64gc-unknown-none-elf
CRATE=axruntime
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
BIOS=${BIOS:-default}
MEM=${MEM:-512M}
SMP=${SMP:-1}
TIMEOUT=${TIMEOUT:-8}
EXPECT_INIT=${EXPECT_INIT:-0}
FS=${FS:-}
ROOTFS_IMAGE=${ROOTFS_IMAGE:-"${ROOT}/build/rootfs.ext4"}
BUILD_ROOTFS=${BUILD_ROOTFS:-1}
CASE_FILE=${CASE_FILE:-"${ROOT}/tests/self/cases.txt"}
LOG_DIR=${LOG_DIR:-"${ROOT}/build/selftest"}
SUMMARY_FILE="${LOG_DIR}/summary.txt"

abs_path() {
  local path="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path"
    return 0
  fi
  python3 - "$path" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
}

if [[ "${ARCH}" != "riscv64" || "${PLATFORM}" != "qemu" ]]; then
  echo "Only ARCH=riscv64 PLATFORM=qemu is supported right now." >&2
  exit 1
fi

if ! command -v "${QEMU_BIN}" >/dev/null 2>&1; then
  echo "QEMU binary not found: ${QEMU_BIN}" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}"

OUT_DIR=debug
if [[ "${MODE}" == "release" ]]; then
  OUT_DIR=release
fi
KERNEL="${ROOT}/target/${TARGET}/${OUT_DIR}/${CRATE}"

CASES=()
if [[ -f "${CASE_FILE}" ]]; then
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(printf "%s" "${line}" | tr -d '\r' | xargs)"
    if [[ -n "${line}" ]]; then
      CASES+=("${line}")
    fi
  done < "${CASE_FILE}"
fi

if [[ ${#CASES[@]} -eq 0 ]]; then
  CASES=(ramdisk ext4)
fi

if [[ -n "${FS}" && ! -f "${FS}" ]]; then
  echo "FS image not found: ${FS}" >&2
  exit 1
fi

FS_EXT4="${FS}"
ensure_ext4_image() {
  if [[ -n "${FS_EXT4}" && -f "${FS_EXT4}" ]]; then
    return 0
  fi
  if [[ "${BUILD_ROOTFS}" != "1" ]]; then
    echo "FS image not set and BUILD_ROOTFS=0; cannot run ext4 case." >&2
    return 1
  fi
  FS_EXT4="${ROOTFS_IMAGE}"
  OUT="${FS_EXT4}" "${ROOT}/scripts/mkfs_ext4.sh"
}

STATUS=0
cat <<EOF > "${SUMMARY_FILE}"
selftest_runner=scripts/test_oscomp.sh
kernel=${KERNEL}
arch=${ARCH}
platform=${PLATFORM}
cases=${CASES[*]}
expect_init=${EXPECT_INIT}
log_dir=${LOG_DIR}
EOF

for case_name in "${CASES[@]}"; do
  case_log="${LOG_DIR}/selftest-${case_name}.log"
  case_fs=""
  expect_ext4=0
  expect_fat32=0
  expect_ext4_write=0
  ext4_write_test=0
  net=0
  expect_net=0
  net_loopback_test=0
  expect_net_loopback=0
  tcp_echo_test=0
  expect_tcp_echo=0
  if [[ "${case_name}" == "ext4-init" ]]; then
    ensure_ext4_image
    FS_EXT4="$(abs_path "${FS_EXT4}")"
    set +e
    (cd "${ROOT}" && AXFS_EXT4_IMAGE="${FS_EXT4}" cargo test -p axfs ext4_init_image) \
      >"${case_log}" 2>&1
    case_status=$?
    set -e
    echo "${case_name}: status=${case_status} log=${case_log} fs=${FS_EXT4}" >> "${SUMMARY_FILE}"
    if [[ ${case_status} -ne 0 ]]; then
      STATUS=${case_status}
    fi
    continue
  fi

  if [[ "${case_name}" == "ext4" ]]; then
    ensure_ext4_image
    FS_EXT4="$(abs_path "${FS_EXT4}")"
    case_fs="${FS_EXT4}"
    expect_ext4=1
    expect_ext4_write=1
    ext4_write_test=1
  elif [[ "${case_name}" == "net" ]]; then
    net=1
    expect_net=1
  elif [[ "${case_name}" == "net-loopback" ]]; then
    net=1
    expect_net=1
    net_loopback_test=1
    expect_net_loopback=1
  elif [[ "${case_name}" == "tcp-echo" ]]; then
    tcp_echo_test=1
    expect_tcp_echo=1
  elif [[ "${case_name}" == "ramdisk" ]]; then
    expect_fat32=1
  fi

  set +e
  ARCH="${ARCH}" PLATFORM="${PLATFORM}" FS="${case_fs}" MODE="${MODE}" \
    USER_TEST=1 EXPECT_INIT="${EXPECT_INIT}" EXPECT_EXT4="${expect_ext4}" EXPECT_FAT32="${expect_fat32}" \
    EXT4_WRITE_TEST="${ext4_write_test}" EXPECT_EXT4_WRITE="${expect_ext4_write}" \
    NET="${net}" EXPECT_NET="${expect_net}" NET_LOOPBACK_TEST="${net_loopback_test}" \
    EXPECT_NET_LOOPBACK="${expect_net_loopback}" TCP_ECHO_TEST="${tcp_echo_test}" \
    EXPECT_TCP_ECHO="${expect_tcp_echo}" TIMEOUT="${TIMEOUT}" \
    QEMU_BIN="${QEMU_BIN}" BIOS="${BIOS}" MEM="${MEM}" SMP="${SMP}" \
    LOG_DIR="${LOG_DIR}" LOG_FILE="${case_log}" \
    "${ROOT}/scripts/test_qemu_smoke.sh"
  case_status=$?
  set -e

  echo "${case_name}: status=${case_status} log=${case_log} fs=${case_fs:-ramdisk}" >> "${SUMMARY_FILE}"
  if [[ ${case_status} -ne 0 ]]; then
    STATUS=${case_status}
  fi
done

if [[ ${STATUS} -ne 0 ]]; then
  echo "Self-test failed with status ${STATUS}" >&2
  exit ${STATUS}
fi

echo "Self-test passed."
