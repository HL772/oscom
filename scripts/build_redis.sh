#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REDIS_SRC=${REDIS_SRC:-}
OUT=${OUT:-"${ROOT}/build/redis-server"}
HOST=${HOST:-riscv64-linux-gnu}
CC_PREFIX=${CC_PREFIX:-${HOST}}
JOBS=${JOBS:-}

if [[ -z "${REDIS_SRC}" ]]; then
  echo "REDIS_SRC is not set (path to redis source tree)." >&2
  exit 1
fi

if [[ ! -d "${REDIS_SRC}" ]]; then
  echo "REDIS_SRC not found: ${REDIS_SRC}" >&2
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

MAKE_FLAGS=(
  "BUILD_TLS=no"
  "MALLOC=libc"
  "USE_JEMALLOC=no"
  "USE_SYSTEMD=no"
)

if [[ -n "${JOBS}" ]]; then
  MAKE_FLAGS+=("-j${JOBS}")
fi

(
  cd "${REDIS_SRC}"
  make "${MAKE_FLAGS[@]}"
)

APP_BIN="${REDIS_SRC}/src/redis-server"
if [[ ! -f "${APP_BIN}" ]]; then
  echo "redis-server binary not found: ${APP_BIN}" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUT}")"
cp "${APP_BIN}" "${OUT}"
echo "Built redis-server ELF: ${OUT}"
