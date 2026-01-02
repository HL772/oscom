#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARCH=${ARCH:-riscv64}
PLATFORM=${PLATFORM:-qemu}
OUT_DIR=${OUT_DIR:-"${ROOT}/build/net-perf"}
PERF_ROOTFS_DIR=${PERF_ROOTFS_DIR:-}
PERF_INIT_ELF=${PERF_INIT_ELF:-}
PERF_EXPECT=${PERF_EXPECT:-}
PERF_HOST=${PERF_HOST:-127.0.0.1}
PERF_HOST_PORT=${PERF_HOST_PORT:-auto}
PERF_GUEST_PORT=${PERF_GUEST_PORT:-5201}
PERF_SEND_BYTES=${PERF_SEND_BYTES:-65536}
PERF_SEND_CHUNK=${PERF_SEND_CHUNK:-65536}
PERF_CONNECT_TIMEOUT=${PERF_CONNECT_TIMEOUT:-5}
PERF_SEND_DELAY=${PERF_SEND_DELAY:-0.5}
PERF_READY_TIMEOUT=${PERF_READY_TIMEOUT:-5}
PERF_QEMU_TIMEOUT=${PERF_QEMU_TIMEOUT:-20}

FS_IMAGE="${OUT_DIR}/rootfs-perf.ext4"
LOG="${OUT_DIR}/perf.log"
QEMU_LOG="${OUT_DIR}/qemu-smoke.log"
SENDER_LOG="${OUT_DIR}/sender.log"

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

if [[ "${PERF_HOST_PORT}" == "auto" ]]; then
  PERF_HOST_PORT=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.close()
print(port)
PY
)
fi

OUT="${FS_IMAGE}" INIT_ELF="${PERF_INIT_ELF}" INIT_ELF_SKIP_BUILD=1 EXTRA_ROOTFS_DIR="${PERF_ROOTFS_DIR}" \
  "${ROOT}/scripts/mkfs_ext4.sh"

TIMEOUT="${PERF_QEMU_TIMEOUT}" NET=1 EXPECT_NET=1 USER_TEST=1 EXPECT_EXT4=1 EXPECT_EXT4_ISSUE=0 FS="${FS_IMAGE}" LOG_FILE="${QEMU_LOG}" \
  NET_HOSTFWD="tcp::${PERF_HOST_PORT}-:${PERF_GUEST_PORT}" \
  "${ROOT}/scripts/test_qemu_smoke.sh" >"${LOG}" 2>&1 &
SMOKE_PID=$!

sleep "${PERF_SEND_DELAY}"
SENDER_STATUS=0
READY_DEADLINE=$((PERF_READY_TIMEOUT * 10))
ready_ok=0
for _ in $(seq 1 "${READY_DEADLINE}"); do
  if [[ -f "${QEMU_LOG}" ]] && rg --text -F "net-bench: ready" "${QEMU_LOG}" >/dev/null 2>&1; then
    ready_ok=1
    break
  fi
  sleep 0.1
done

if [[ "${ready_ok}" == "1" ]]; then
  python3 "${ROOT}/scripts/net_perf_send.py" \
    --host "${PERF_HOST}" \
    --port "${PERF_HOST_PORT}" \
    --bytes "${PERF_SEND_BYTES}" \
    --chunk "${PERF_SEND_CHUNK}" \
    --connect-timeout "${PERF_CONNECT_TIMEOUT}" \
    >"${SENDER_LOG}" 2>&1 || SENDER_STATUS=$?
else
  echo "net-perf: net-bench ready timeout" >"${SENDER_LOG}"
  SENDER_STATUS=1
fi

wait "${SMOKE_PID}"

if [[ -n "${PERF_EXPECT}" ]]; then
  IFS=',' read -r -a markers <<< "${PERF_EXPECT}"
  for marker in "${markers[@]}"; do
    if ! rg --text -F "${marker}" "${QEMU_LOG}" >/dev/null; then
      echo "missing marker: ${marker}" >&2
      exit 1
    fi
  done
fi

if [[ -s "${SENDER_LOG}" ]]; then
  cat "${SENDER_LOG}" >> "${LOG}"
fi

rx_line=$(rg --text -F "net-bench: rx_bytes=" "${QEMU_LOG}" | tail -n 1 || true)
if [[ -n "${rx_line}" ]]; then
  echo "${rx_line}" >> "${LOG}"
else
  echo "net-bench: rx_bytes=missing" >> "${LOG}"
fi

echo "net perf log: ${LOG}"
echo "qemu log: ${QEMU_LOG}"

if [[ "${SENDER_STATUS}" -ne 0 ]]; then
  exit "${SENDER_STATUS}"
fi
