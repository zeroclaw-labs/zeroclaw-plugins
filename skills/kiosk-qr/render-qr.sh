#!/usr/bin/env bash
# Render a Solana Pay `solana:` URL to a QR PNG and print a wallet tap-link.
# Host-side only — no network, no wasm. QR needs `qrencode` (brew/apt install qrencode).
#
# Usage: render-qr.sh '<solana: URL>' [out.png]

set -euo pipefail

URL="${1:-}"
OUT="${2:-kiosk-charge-qr.png}"

[ -n "$URL" ] || { echo "usage: render-qr.sh '<solana: URL>' [out.png]" >&2; exit 2; }
case "$URL" in
  solana:*) ;;
  *) echo "error: expected a 'solana:' URL, got: $URL" >&2; exit 2 ;;
esac

# QR image (skip gracefully if qrencode is absent — the tap-link still works).
if command -v qrencode >/dev/null 2>&1; then
  qrencode -o "$OUT" -s 8 -m 2 "$URL"
  echo "QR written: $OUT"
else
  echo "note: 'qrencode' not installed — skipping PNG (install: brew/apt install qrencode)" >&2
fi

# Tap-link fallback: the `solana:` URI is itself the tappable link — wallets
# (Phantom, Solflare, …) register the `solana:` scheme and open it directly with
# the payment pre-filled. No encoding or wrapper service needed.
echo "tap-link (opens a mobile wallet): $URL"
