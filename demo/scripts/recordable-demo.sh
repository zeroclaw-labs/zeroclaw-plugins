#!/usr/bin/env bash
# Recordable DePIN demo script (terminal + explorer URL).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source demo/keys/env.sh

echo "=============================================="
echo " ZeroClaw DePIN demo — Solana attestation"
echo "=============================================="
echo
echo "Payer:  $DEPIN_PAYER"
echo "Nonce:  $DEPIN_NONCE_ACCOUNT"
echo "RPC:    $DEPIN_RPC_URL"
echo

echo ">> Step 1 — depin_attest builds unsigned durable-nonce memo tx"
echo "--------------------------------------------------------------"
DEPIN_SUBMIT=0 cargo +1.96.1 run --manifest-path demo/runner/Cargo.toml --release --quiet
echo

echo ">> Step 2 — human signs + submits (payer keypair)"
echo "--------------------------------------------------------------"
DEPIN_SUBMIT=1 cargo +1.96.1 run --manifest-path demo/runner/Cargo.toml --release --quiet | tee /tmp/depin-demo-out.txt
echo
echo "On-chain explorer (devnet):"
rg -o 'https://explorer\.solana\.com/tx/[A-Za-z0-9]+' /tmp/depin-demo-out.txt | head -1 | awk '{print $0 "?cluster=devnet"}' || true
echo

echo ">> Step 3 — watch verdict printed above after submit (OK when indexed)"
echo ">> Done. Custody T0/T1 — plugin never held a key / never called sendTransaction."
echo "  Plugin packages: demo/dist/{depin-attest,depin-uptime-watch}"
echo "  ZeroClaw binary:  ~/.cargo/bin/zeroclaw-plugins"
exit 0
