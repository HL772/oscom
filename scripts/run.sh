#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
ARCH=${ARCH:-riscv64}
PLATFORM=${PLATFORM:-qemu}
FS=${FS:-}
MODE=${MODE:-debug}
TARGET=riscv64gc-unknown-none-elf
CRATE=axruntime
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
BIOS=${BIOS:-default}
MEM=${MEM:-512M}
SMP=${SMP:-1}

if [[ "${ARCH}" != "riscv64" || "${PLATFORM}" != "qemu" ]]; then
  echo "Only ARCH=riscv64 PLATFORM=qemu is supported right now." >&2
  exit 1
fi

if ! command -v "${QEMU_BIN}" >/dev/null 2>&1; then
  echo "QEMU binary not found: ${QEMU_BIN}" >&2
  exit 1
fi

"${ROOT}/scripts/build.sh"

OUT_DIR=debug
if [[ "${MODE}" == "release" ]]; then
  OUT_DIR=release
fi
KERNEL="${ROOT}/target/${TARGET}/${OUT_DIR}/${CRATE}"

DRIVE_ARGS=()
if [[ -n "${FS}" ]]; then
  DRIVE_ARGS=(
    -drive "file=${FS},format=raw,if=none,id=x0"
    -device virtio-blk-device,drive=x0
  )
else
  echo "FS image not set; continuing without block device." >&2
fi

exec "${QEMU_BIN}" \
  -machine virt \
  -nographic \
  -bios "${BIOS}" \
  -m "${MEM}" \
  -smp "${SMP}" \
  -kernel "${KERNEL}" \
  "${DRIVE_ARGS[@]}"
