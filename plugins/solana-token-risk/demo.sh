#!/usr/bin/env bash
# Live judge demo for solana-token-risk.
#   1. Run the full pure-core test suite (deterministic, offline).
#   2. Fetch REAL mints from a live Solana RPC and score them with the EXACT same
#      core the wasm plugin runs — real chain data, no mocking.
#
# With no args it showcases two real tokens so you can see the tool DISCRIMINATE:
#   - BONK  : mint & freeze authority renounced  -> low / minimal
#   - USDC  : both authorities live (Circle)      -> flagged (accurate on-chain fact)
#
# Usage: ./demo.sh [MINT_ADDRESS] [RPC_URL]
set -euo pipefail
cd "$(dirname "$0")"

RPC_DEFAULT="https://api.mainnet-beta.solana.com"

echo "== 1. scoring-core tests (offline, deterministic) =="
cargo test --release --quiet
echo "   (build the example once, up front)"
cargo build --release --quiet --example assess_files

assess() {
  local MINT="$1" RPC="$2" LABEL="$3"
  local TMP; TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' RETURN
  echo
  echo "== $LABEL — $MINT =="
  curl -s "$RPC" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"$MINT\",{\"encoding\":\"jsonParsed\"}]}" \
    > "$TMP/acct.json"
  curl -s "$RPC" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTokenLargestAccounts\",\"params\":[\"$MINT\"]}" \
    > "$TMP/largest.json"

  # Build a map {account -> getAccountInfo response} that the file-backed demo
  # fetcher serves for (i) the top holders' owners — so the tool can tell an
  # off-curve LP/protocol vault apart from an on-curve whale wallet — and (ii) the
  # Metaplex metadata PDA — so mutable metadata is detected. Built with no jq.
  ADDRS=$( { grep -oE '"address":"[^"]+"' "$TMP/largest.json" || true; } | sed -E 's/"address":"([^"]+)"/\1/' | head -6 || true)
  PDA=$(cargo run --release --quiet --example print_pda -- "$MINT" 2>/dev/null || true)
  echo "{" > "$TMP/owners.json"; FIRST=1
  add_entry() {
    local A="$1" ENC="$2"
    local R
    R=$(curl -s "$RPC" -X POST -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"$A\",{\"encoding\":\"$ENC\"}]}")
    [ $FIRST -eq 0 ] && echo "," >> "$TMP/owners.json"; FIRST=0
    printf '"%s": %s' "$A" "$R" >> "$TMP/owners.json"
  }
  for A in $ADDRS; do add_entry "$A" "jsonParsed"; done
  [ -n "$PDA" ] && add_entry "$PDA" "base64"
  echo "}" >> "$TMP/owners.json"

  cargo run --release --quiet --example assess_files -- "$MINT" "$TMP/acct.json" "$TMP/largest.json" "$TMP/owners.json"
}

if [ "${1:-}" != "" ]; then
  assess "$1" "${2:-$RPC_DEFAULT}" "live assessment"
else
  assess "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" "$RPC_DEFAULT" "BONK (renounced — expect low)"
  assess "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" "$RPC_DEFAULT" "USDC (authorities live — expect flags)"
fi
