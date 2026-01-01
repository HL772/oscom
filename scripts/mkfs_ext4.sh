#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
OUT=${OUT:-"${ROOT}/build/rootfs.ext4"}
SIZE=${SIZE:-16M}
WORKDIR=${WORKDIR:-"${ROOT}/build/rootfs"}
INIT_ELF=${INIT_ELF:-"${ROOT}/build/init.elf"}
TCP_ECHO_ELF=${TCP_ECHO_ELF:-}
UDP_ECHO_ELF=${UDP_ECHO_ELF:-}
EXTRA_ROOTFS_DIR=${EXTRA_ROOTFS_DIR:-}
INIT_ELF_SKIP_BUILD=${INIT_ELF_SKIP_BUILD:-0}

if ! command -v mke2fs >/dev/null 2>&1; then
  echo "mke2fs not found; please install e2fsprogs." >&2
  exit 1
fi

if [[ "${INIT_ELF_SKIP_BUILD}" != "1" ]]; then
  python3 "${ROOT}/tools/build_init_elf.py" --out "${INIT_ELF}"
else
  if [[ ! -f "${INIT_ELF}" ]]; then
    echo "INIT_ELF not found: ${INIT_ELF}" >&2
    exit 1
  fi
fi

rm -rf "${WORKDIR}"
mkdir -p "${WORKDIR}"
cp "${INIT_ELF}" "${WORKDIR}/init"
if [[ -n "${TCP_ECHO_ELF}" ]]; then
  if [[ ! -f "${TCP_ECHO_ELF}" ]]; then
    echo "TCP_ECHO_ELF not found: ${TCP_ECHO_ELF}" >&2
    exit 1
  fi
  cp "${TCP_ECHO_ELF}" "${WORKDIR}/tcp_echo"
fi
if [[ -n "${UDP_ECHO_ELF}" ]]; then
  if [[ ! -f "${UDP_ECHO_ELF}" ]]; then
    echo "UDP_ECHO_ELF not found: ${UDP_ECHO_ELF}" >&2
    exit 1
  fi
  cp "${UDP_ECHO_ELF}" "${WORKDIR}/udp_echo"
fi
if [[ -n "${EXTRA_ROOTFS_DIR}" ]]; then
  if [[ ! -d "${EXTRA_ROOTFS_DIR}" ]]; then
    echo "EXTRA_ROOTFS_DIR not found: ${EXTRA_ROOTFS_DIR}" >&2
    exit 1
  fi
  cp -a "${EXTRA_ROOTFS_DIR}/." "${WORKDIR}/"
fi
mkdir -p "${WORKDIR}/etc"
printf "Aurora ext4 test\n" > "${WORKDIR}/etc/issue"
WORKDIR="${WORKDIR}" python3 - <<'PY'
import os
path = os.path.join(os.environ["WORKDIR"], "etc", "large")
with open(path, "wb") as f:
    f.write(b"Z" * 8192)
PY

mke2fs -q -t ext4 -d "${WORKDIR}" -F "${OUT}" "${SIZE}"
echo "ext4 image created: ${OUT}"
