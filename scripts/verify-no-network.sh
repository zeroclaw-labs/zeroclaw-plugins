#!/usr/bin/env bash
# Prove — not assert — that kiosk-charge (T1) imports zero network capability.
#
# A T1 plugin claims "zero network". This script builds the actual wasm component
# and greps its imported interfaces for `wasi:http`. The count MUST be 0. It also
# shows kiosk-watch's count for contrast: a read-only RPC client SHOULD import
# wasi:http, so a non-zero there is expected and proves the test discriminates.
#
# Exit 0 only if kiosk-charge has zero wasi:http imports.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/kiosk-verify}"

log()  { printf '\033[1;36m[verify]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[verify] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

command -v strings >/dev/null || die "'strings' not found (binutils)"
rustup target list --installed 2>/dev/null | grep -q wasm32-wasip2 \
  || die "wasm32-wasip2 target missing — run: rustup target add wasm32-wasip2"

log "building kiosk-charge for wasm32-wasip2 (release)…"
( cd "$ROOT/plugins/kiosk-charge" && CARGO_TARGET_DIR="$TARGET_DIR/charge" \
    cargo build --target wasm32-wasip2 --release >/dev/null 2>&1 )
CHARGE_WASM="$TARGET_DIR/charge/wasm32-wasip2/release/kiosk_charge.wasm"
[[ -f "$CHARGE_WASM" ]] || die "kiosk_charge.wasm not found at $CHARGE_WASM"

CHARGE_HTTP="$(strings "$CHARGE_WASM" | grep -c 'wasi:http' || true)"
log "kiosk-charge wasi:http import count = $CHARGE_HTTP (must be 0)"

if [[ "$CHARGE_HTTP" -ne 0 ]]; then
  echo "--- offending strings ---"
  strings "$CHARGE_WASM" | grep 'wasi:http' | sort -u
  die "kiosk-charge imports wasi:http — the T1 zero-network claim is BROKEN"
fi

# Contrast: kiosk-watch is a read-only RPC client and SHOULD import wasi:http.
if [[ -d "$ROOT/plugins/kiosk-watch" ]]; then
  log "building kiosk-watch for contrast…"
  ( cd "$ROOT/plugins/kiosk-watch" && CARGO_TARGET_DIR="$TARGET_DIR/watch" \
      cargo build --target wasm32-wasip2 --release >/dev/null 2>&1 )
  WATCH_WASM="$TARGET_DIR/watch/wasm32-wasip2/release/kiosk_watch.wasm"
  if [[ -f "$WATCH_WASM" ]]; then
    WATCH_HTTP="$(strings "$WATCH_WASM" | grep -c 'wasi:http' || true)"
    log "kiosk-watch  wasi:http import count = $WATCH_HTTP (expected > 0)"
  fi
fi

printf '\033[1;32m✔ PROVEN: kiosk-charge imports no wasi:http (network-free T1).\033[0m\n'
