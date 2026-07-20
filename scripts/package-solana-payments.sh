#!/usr/bin/env bash
# Package Track A Solana payment plugins: test, wasm build, stage for install.
# Usage (from zeroclaw-plugins repo root):
#   ./scripts/package-solana-payments.sh
#   SKIP_TESTS=1 ./scripts/package-solana-payments.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PLUGINS=(solana-pay-request payment-watch spl-transfer-build x402-settle)
STAGE="$ROOT/dist/solana-payments-suite"
rm -rf "$STAGE"
mkdir -p "$STAGE"

cp docs/solana-payments-suite.md docs/solana-payments-config.example.toml "$STAGE/"

for name in "${PLUGINS[@]}"; do
  dir="$ROOT/plugins/$name"
  echo ""
  echo "======== $name ========"
  pushd "$dir" >/dev/null
  if [[ "${SKIP_TESTS:-}" != "1" ]]; then
    cargo test
  fi
  rustup target add wasm32-wasip2 >/dev/null 2>&1 || true
  cargo build --target wasm32-wasip2 --release
  wasm=$(ls target/wasm32-wasip2/release/*.wasm | head -n1)
  cp "$wasm" "./$(basename "$wasm")"
  out="$STAGE/$name"
  mkdir -p "$out"
  cp manifest.toml README.md LICENSE "$(basename "$wasm")" "$out/"
  echo "Staged $out"
  popd >/dev/null
done

echo ""
echo "Done. Installable bundle: $STAGE"
find "$STAGE" -type f
