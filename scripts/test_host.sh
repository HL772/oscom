#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

shopt -s nullglob
CRATES=("${ROOT}"/crates/*)

if [[ ${#CRATES[@]} -eq 0 ]]; then
  echo "No host-testable crates yet." >&2
  exit 0
fi

for dir in "${CRATES[@]}"; do
  if [[ -f "${dir}/Cargo.toml" ]]; then
    echo "Running tests in ${dir}" >&2
    (cd "${dir}" && cargo test)
  fi
done
