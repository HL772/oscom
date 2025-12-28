#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
rm -rf "${ROOT}/target" "${ROOT}/dist" "${ROOT}/build"
