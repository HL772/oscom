#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
ARCH=${ARCH:-riscv64}
PLATFORM=${PLATFORM:-qemu}
MODE=${MODE:-debug}
NET=${NET:-0}
TARGET=riscv64gc-unknown-none-elf
CRATE=axruntime
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
BIOS=${BIOS:-default}
MEM=${MEM:-512M}
SMP=${SMP:-1}
GDB_PORT=${GDB_PORT:-1234}

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

NET_ARGS=()
if [[ "${NET}" == "1" ]]; then
  NET_ARGS=(
    -netdev user,id=net0
    -device virtio-net-device,netdev=net0
  )
fi

echo "QEMU waiting for GDB on tcp::${GDB_PORT}" >&2
exec "${QEMU_BIN}" \
  -global virtio-mmio.force-legacy=false \
  -machine virt \
  -nographic \
  -bios "${BIOS}" \
  -m "${MEM}" \
  -smp "${SMP}" \
  -kernel "${KERNEL}" \
  -S -gdb "tcp::${GDB_PORT}" \
  "${NET_ARGS[@]}"
