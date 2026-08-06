#!/usr/bin/env bash
# Safe Hands — prove the safety claim from a clean checkout, with NO keys, NO
# funds, and NO live network. Every RPC call in these tests is mocked; the only
# requirement is a Rust toolchain (pinned 1.96.1) with the wasm32-wasip2 target.
#
#   ./verify.sh
#
# Mirrors `just prove-safety` for reviewers who don't have `just` installed.
# Exit 0 means: every host test, the 28-fixture attack arena, and all three
# wasm32-wasip2 release builds passed — reproducibly, offline, key-free.
set -euo pipefail
cd "$(dirname "$0")"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
rule() { printf '==================================================\n'; }

CORE=libs/safe-hands-core/Cargo.toml
AUTHORIZE=plugins/solana-tx-authorize/Cargo.toml
SPL=plugins/spl-transfer-build/Cargo.toml
SQUADS=plugins/squads-proposal-build/Cargo.toml
CONF=conformance/Cargo.toml

rule
bold "Safe Hands — offline safety proof (no keys, no funds, no network)"
rule

echo "> ensuring the wasm32-wasip2 target is available"
rustup target add wasm32-wasip2 >/dev/null 2>&1 || true

echo
bold "1/3  Host tests (RPC mocked; includes property-based invariants + decoder fuzz)"
for manifest in "$CORE" "$AUTHORIZE" "$SPL" "$SQUADS"; do
  echo "  - cargo test --locked --manifest-path $manifest"
  cargo test --locked --manifest-path "$manifest"
done

echo
bold "2/3  The 28-fixture attack arena (real plugin entry points, mocked transports)"
cargo run --locked --release --manifest-path "$CONF"

echo
bold "3/3  wasm32-wasip2 release components"
for manifest in "$AUTHORIZE" "$SPL" "$SQUADS"; do
  echo "  - cargo build --locked --release --target wasm32-wasip2 --manifest-path $manifest"
  cargo build --locked --release --target wasm32-wasip2 --manifest-path "$manifest"
done

echo
rule
bold "ALL GREEN - the guard holds. No key, no fund, and no live network was used."
rule
