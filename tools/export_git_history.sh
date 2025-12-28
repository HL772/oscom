#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
OUT_DIR="$ROOT/docs/process"

mkdir -p "$OUT_DIR"

git -C "$ROOT" log --stat --decorate --graph --date=iso > "$OUT_DIR/git-log.txt"
git -C "$ROOT" shortlog -s -n > "$OUT_DIR/git-shortlog.txt"

echo "Wrote $OUT_DIR/git-log.txt and $OUT_DIR/git-shortlog.txt"
