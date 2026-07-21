#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/solana-core/src"
for dest in \
  "$ROOT/plugins/depin-attest/src/vendor/solana_core" \
  "$ROOT/plugins/depin-uptime-watch/src/vendor/solana_core"
do
  mkdir -p "$dest"
  rsync -a --delete --exclude 'vendor' "$SRC/" "$dest/"
done
echo "synced solana-core → plugin vendor trees"
