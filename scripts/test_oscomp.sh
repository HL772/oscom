#!/usr/bin/env bash
set -euo pipefail

ARCH=${ARCH:-riscv64}
PLATFORM=${PLATFORM:-qemu}
FS=${FS:-}

if [[ -z "${FS}" ]]; then
  echo "FS image not set; use FS=path/to/ext4.img" >&2
fi

echo "TODO: implement OSComp test suite for ARCH=${ARCH} PLATFORM=${PLATFORM}" >&2
exit 1
