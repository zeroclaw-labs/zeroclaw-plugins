#!/usr/bin/env bash
# Live judge demo for solana-wallet-risk.
#   1. Run the pure-core test suite (deterministic, offline).
#   2. Fetch a REAL wallet's SPL + Token-2022 holdings from a live Solana RPC,
#      fetch each top mint, and score them with the EXACT same core the wasm
#      plugin runs — real chain data, no mocking.
#
# Usage: ./demo.sh [WALLET_ADDRESS] [RPC_URL]
#
# The default wallet holds ~142 positions and scans in about 6 seconds. It also
# scales: a wallet with 3,015 positions scans fine, it just spends longer pulling
# the account list from the RPC. Try:
#   ./demo.sh 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM
set -euo pipefail
# Don't die on SIGPIPE when the caller pipes us into `head`.
trap '' PIPE
cd "$(dirname "$0")"

WALLET="${1:-GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ}"
RPC="${2:-https://api.mainnet-beta.solana.com}"
SPL_PROGRAM="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
T22_PROGRAM="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== 1. scoring-core tests (offline, deterministic) =="
cargo test --quiet 2>&1 | grep -E "^test result" || true
cargo build --release --quiet --example scan_files

echo
echo "== 2. live wallet scan: $WALLET =="
echo "   RPC: $RPC"

fetch_accounts() {
  curl -s "$RPC" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTokenAccountsByOwner\",\"params\":[\"$WALLET\",{\"programId\":\"$1\"},{\"encoding\":\"jsonParsed\"}]}"
}
fetch_accounts "$SPL_PROGRAM" > "$TMP/spl.json"
fetch_accounts "$T22_PROGRAM" > "$TMP/t22.json"

# Collect the mints of the largest non-zero positions, then fetch each mint once.
MINTS=$(python3 - "$TMP/spl.json" "$TMP/t22.json" <<'PY'
import json, sys
rows = []
for path in sys.argv[1:]:
    try:
        d = json.load(open(path))
    except Exception:
        continue
    for e in (d.get("result") or {}).get("value", []) or []:
        info = ((e.get("account") or {}).get("data") or {}).get("parsed", {}).get("info", {})
        amt = (info.get("tokenAmount") or {}).get("uiAmount") or 0
        if info.get("mint") and amt and amt > 0:
            rows.append((amt, info["mint"]))
rows.sort(reverse=True)
seen, out = set(), []
for _a, m in rows:
    if m not in seen:
        seen.add(m); out.append(m)
    if len(out) >= 12:
        break
print("\n".join(out))
PY
)

echo "{" > "$TMP/mints.json"; FIRST=1
for M in $MINTS; do
  R=$(curl -s "$RPC" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"$M\",{\"encoding\":\"jsonParsed\"}]}")
  [ $FIRST -eq 0 ] && echo "," >> "$TMP/mints.json"; FIRST=0
  printf '"%s": %s' "$M" "$R" >> "$TMP/mints.json"
done
echo "}" >> "$TMP/mints.json"

cargo run --release --quiet --example scan_files -- "$WALLET" "$TMP/spl.json" "$TMP/t22.json" "$TMP/mints.json"
