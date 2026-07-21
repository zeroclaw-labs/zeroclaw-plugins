#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/solana-core/src"
DESTS=(
  "$ROOT/plugins/depin-attest/src/vendor/solana_core" \
  "$ROOT/plugins/depin-uptime-watch/src/vendor/solana_core"
)

if [[ "${1:-}" == "--check" ]]; then
  for dest in "${DESTS[@]}"; do
    diff -ru "$SRC" "$dest"
  done
  exit 0
fi

for dest in "${DESTS[@]}"; do
  mkdir -p "$dest"
  rsync -a --delete --exclude 'vendor' "$SRC/" "$dest/"
done
echo "synced solana-core → plugin vendor trees"
