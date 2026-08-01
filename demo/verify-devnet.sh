#!/usr/bin/env bash
# Re-check this suite's devnet evidence from a clean machine, with no credentials.
#
#   bash demo/verify-devnet.sh                     # public devnet RPC
#   RPC_URL=https://your-node bash demo/verify-devnet.sh
#
# There is no keypair, no wallet and no private key in this script, and nothing
# in it can sign or send. It only reads.
#
# Two kinds of check, and the difference matters:
#
#   INVARIANTS are properties of the chain and must hold, so they fail the run.
#   The supplier balance is the whole payment and nothing else has ever been
#   sent to that address. The nonce account's shape and parsed state are what
#   nonce-status reads.
#
#   The SETTLEMENT SIGNATURE is reported, not asserted. Devnet history depth is
#   a property of whichever node answers rather than a promise: this same
#   signature returned nothing from the public endpoint on 2026-07-30 and
#   returned finalized on 2026-08-01. A script that demanded either answer would
#   be lying to you about what devnet guarantees.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RPC=${RPC_URL:-https://api.devnet.solana.com}

# invoice 001, built unsigned by spl-transfer-build on 2026-07-26 and signed
# outside the agent by the owner. Addresses are hard-coded so this script is the
# claim: if any of them is wrong, this run says so.
SUPPLIER=8aFmTm6bbckG7fWVWrNeWAtCavTbXMjoe8JWo4NRDe9Y
OWNER=2PQcNtSophRAG7ZsHaDT87Zx8MNkCu3GPKsmrR2qthty
NONCE=GnGJjkuzDJTnyTzbw1tmtkrQ4icbDujJug1rx1HDBegX
SETTLEMENT=AxfCkYk7z53FqyTagrccJgwK8KHUXca27pqhZf55K2EBfmsFo1SJyuUDF4c34ZiJRDz8hzb8MDojmtPuXnwQke8

SYSTEM_PROGRAM=11111111111111111111111111111111
SUPPLIER_LAMPORTS=50000000   # 0.05 SOL, the whole of invoice 001
NONCE_LAMPORTS=2000000
NONCE_SPACE=80
NONCE_FEE=5000

FAILURES=0
stage() { printf '\n== %s\n' "$*"; }
ok() { printf '  ok    %s\n' "$*"; }
note() { printf '  note  %s\n' "$*"; }
bad() { FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$*"; }

rpc() { curl -sS --max-time 25 "$RPC" -H 'content-type: application/json' -d "$1"; }
# Walk a JSON response by key, list indices included. The body carries no single
# quotes so the shell hands it over intact, and it reads stdin, so callers pipe.
pick() { python3 -c '
import json, sys
d = json.load(sys.stdin)
for key in sys.argv[1:]:
    if d is None:
        break
    if isinstance(d, list):
        i = int(key)
        d = d[i] if i < len(d) else None
    elif isinstance(d, dict):
        d = d.get(key)
    else:
        d = None
print("null" if d is None else d)
' "$@"; }

command -v curl >/dev/null || { echo "curl is required"; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 2; }

printf 'Reading %s\n' "$RPC"
stage "Invariant: the supplier holds exactly invoice 001 and nothing else"
BAL=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"$SUPPLIER\"]}" | pick result value)
if [ "$BAL" = "$SUPPLIER_LAMPORTS" ]; then
  ok "$SUPPLIER holds $BAL lamports, exactly the 0.05 SOL of invoice 001"
else
  bad "$SUPPLIER holds ${BAL:-no answer} lamports, expected $SUPPLIER_LAMPORTS"
fi

OWNER_BAL=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"$OWNER\"]}" | pick result value)
note "owner $OWNER holds ${OWNER_BAL:-no answer} lamports (informational, it moves whenever we test)"

stage "Invariant: the nonce account is the shape nonce-status parses"
ACC=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"$NONCE\",{\"encoding\":\"base64\"}]}")
A_OWNER=$(printf '%s' "$ACC" | pick result value owner)
A_LAMPORTS=$(printf '%s' "$ACC" | pick result value lamports)
A_SPACE=$(printf '%s' "$ACC" | pick result value space)
if [ -z "$A_OWNER" ]; then
  bad "$NONCE does not exist on this node"
else
  [ "$A_OWNER" = "$SYSTEM_PROGRAM" ] && ok "owned by the system program" || bad "owner is $A_OWNER, expected the system program"
  [ "$A_LAMPORTS" = "$NONCE_LAMPORTS" ] && ok "$A_LAMPORTS lamports" || bad "$A_LAMPORTS lamports, expected $NONCE_LAMPORTS"
  [ "$A_SPACE" = "$NONCE_SPACE" ] && ok "$A_SPACE bytes of data" || bad "$A_SPACE bytes, expected $NONCE_SPACE"
fi
stage "Invariant: the nonce state decodes to an initialised durable nonce"
# The 80-byte layout lives in demo/decode-nonce.py, which takes the data on argv
# so nothing competes for stdin.
B64=$(printf '%s' "$ACC" | pick result value data 0)
if [ -n "$B64" ] && [ "$B64" != "null" ]; then
  python3 "$HERE/decode-nonce.py" "$B64" "$NONCE_FEE" || FAILURES=$((FAILURES + 1))
else
  bad "no account data to decode"
fi

stage "Reported, not asserted: the invoice 001 settlement"
SIG=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignatureStatuses\",\"params\":[[\"$SETTLEMENT\"],{\"searchTransactionHistory\":true}]}")
SLOT=$(printf '%s' "$SIG" | pick result value 0 slot)
STATUS=$(printf '%s' "$SIG" | pick result value 0 confirmationStatus)
ERR=$(printf '%s' "$SIG" | pick result value 0 err)
FIRST=$(rpc '{"jsonrpc":"2.0","id":1,"method":"getFirstAvailableBlock"}' | pick result)
SLOT_NOW=$(rpc '{"jsonrpc":"2.0","id":1,"method":"getSlot"}' | pick result)
if [ -n "$SLOT" ]; then
  note "$SETTLEMENT"
  note "resolves on this node: slot $SLOT, $STATUS, err $ERR"
else
  note "$SETTLEMENT"
  note "this node does not serve it. Its history starts at block ${FIRST:-unknown}, so the"
  note "transaction is older than what it keeps. The supplier balance above is the durable proof."
fi
note "node history window: first available block ${FIRST:-unknown}, current slot ${SLOT_NOW:-unknown}"

stage "Verdict"
if [ "$FAILURES" -eq 0 ]; then
  printf '  every invariant holds on %s\n' "$RPC"
  exit 0
fi
printf '  %d invariant(s) failed on %s\n' "$FAILURES" "$RPC"
exit 1
