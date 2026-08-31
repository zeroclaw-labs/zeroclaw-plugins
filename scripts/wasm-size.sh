#!/usr/bin/env bash
# Report the release wasm component size for each kiosk plugin.
# Target: < 250 KB. The zero-network plugin (kiosk-charge) meets it easily;
# the RPC plugins (kiosk-watch, kiosk-attest) are larger because they bundle the
# `waki` HTTP/TLS client — inherent to a network-touching component.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/kiosk-size}"
LIMIT_KB=250

rustup target list --installed 2>/dev/null | grep -q wasm32-wasip2 \
  || { echo "wasm32-wasip2 target missing — rustup target add wasm32-wasip2" >&2; exit 1; }

printf '%-16s %10s   %s\n' "PLUGIN" "SIZE" "vs 250KB target"
printf '%s\n' "-------------------------------------------------"
status=0
for p in kiosk-charge kiosk-watch kiosk-attest; do
  [ -d "$ROOT/plugins/$p" ] || continue
  ( cd "$ROOT/plugins/$p" && CARGO_TARGET_DIR="$TARGET_DIR/$p" \
      cargo build --target wasm32-wasip2 --release >/dev/null 2>&1 )
  wasm="$TARGET_DIR/$p/wasm32-wasip2/release/${p//-/_}.wasm"
  bytes=$(stat -f%z "$wasm" 2>/dev/null || stat -c%s "$wasm")
  kb=$(( bytes / 1024 ))
  if [ "$kb" -lt "$LIMIT_KB" ]; then mark="✔ under"; else mark="• over (network client)"; fi
  printf '%-16s %8dKB   %s\n' "$p" "$kb" "$mark"
done
exit $status
