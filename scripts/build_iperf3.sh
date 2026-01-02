#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
IPERF3_SRC=${IPERF3_SRC:-}
OUT=${OUT:-"${ROOT}/build/iperf3"}
HOST=${HOST:-riscv64-linux-gnu}
CC_PREFIX=${CC_PREFIX:-${HOST}}
JOBS=${JOBS:-}

if [[ -z "${IPERF3_SRC}" ]]; then
  echo "IPERF3_SRC is not set (path to iperf3 source tree)." >&2
  exit 1
fi

if [[ ! -d "${IPERF3_SRC}" ]]; then
  echo "IPERF3_SRC not found: ${IPERF3_SRC}" >&2
  exit 1
fi

if [[ ! -x "${IPERF3_SRC}/configure" ]]; then
  echo "iperf3 configure script not found; use a release tarball with ./configure." >&2
  exit 1
fi

if ! command -v "${CC_PREFIX}-gcc" >/dev/null 2>&1; then
  echo "Cross compiler not found: ${CC_PREFIX}-gcc" >&2
  exit 1
fi

export CC="${CC_PREFIX}-gcc"
export AR="${CC_PREFIX}-ar"
export RANLIB="${CC_PREFIX}-ranlib"
export STRIP="${CC_PREFIX}-strip"
export CFLAGS="${CFLAGS:-"-O2 -pipe"}"
export LDFLAGS="${LDFLAGS:-"-static"}"

CONFIGURE_FLAGS=(
  "--host=${HOST}"
  "--disable-shared"
  "--enable-static"
  "--without-openssl"
)

MAKE_FLAGS=()
if [[ -n "${JOBS}" ]]; then
  MAKE_FLAGS+=("-j${JOBS}")
fi

(
  cd "${IPERF3_SRC}"
  ./configure "${CONFIGURE_FLAGS[@]}"
  make "${MAKE_FLAGS[@]}"
)

APP_BIN="${IPERF3_SRC}/src/iperf3"
if [[ ! -f "${APP_BIN}" ]]; then
  echo "iperf3 binary not found: ${APP_BIN}" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUT}")"
cp "${APP_BIN}" "${OUT}"
echo "Built iperf3 ELF: ${OUT}"
