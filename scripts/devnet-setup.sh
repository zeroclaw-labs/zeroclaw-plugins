#!/usr/bin/env bash
# ProofKiosk — one-command devnet/localnet setup.
#
# Creates everything rung 1 needs and prints a paste-ready config block:
#   (a) a running localnet validator, OR a devnet target
#   (b) a test SPL mint (6 decimals, USDC-like)
#   (c) that mint credited to a fresh test wallet
#   (d) the merchant_address / usdc_mint / rpc_url to paste into PROOFKIOSK.md
#
# Usage:
#   MODE=localnet ./scripts/devnet-setup.sh   # default: local test validator
#   MODE=devnet   ./scripts/devnet-setup.sh   # target public devnet (airdrops SOL)
#
# Requires the Solana CLI (`solana`, `solana-keygen`) and `spl-token`.
# Nothing here touches mainnet. All keys are throwaway test keys under ./.devnet.

set -euo pipefail

MODE="${MODE:-localnet}"
DECIMALS=6
MINT_AMOUNT="${MINT_AMOUNT:-1000}"        # test tokens minted to the wallet
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.devnet"
WALLET="$WORKDIR/merchant.json"
VALIDATOR_PID=""

log()  { printf '\033[1;36m[setup]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[setup] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v solana        >/dev/null || die "solana CLI not found — https://docs.solanalabs.com/cli/install"
command -v solana-keygen >/dev/null || die "solana-keygen not found (part of the Solana CLI)"
command -v spl-token     >/dev/null || die "spl-token not found — cargo install spl-token-cli"

mkdir -p "$WORKDIR"

cleanup() {
  if [[ -n "$VALIDATOR_PID" ]] && kill -0 "$VALIDATOR_PID" 2>/dev/null; then
    log "leaving solana-test-validator running (pid $VALIDATOR_PID); kill it with: kill $VALIDATOR_PID"
  fi
}
trap cleanup EXIT

# ── (a) endpoint ──────────────────────────────────────────────────────────────
case "$MODE" in
  localnet)
    RPC_URL="http://127.0.0.1:8899"
    if ! solana cluster-version --url "$RPC_URL" >/dev/null 2>&1; then
      command -v solana-test-validator >/dev/null || die "solana-test-validator not found"
      log "starting solana-test-validator (ledger in $WORKDIR/ledger)…"
      ( cd "$WORKDIR" && solana-test-validator --quiet --ledger ledger >/dev/null 2>&1 & echo $! > "$WORKDIR/validator.pid" )
      VALIDATOR_PID="$(cat "$WORKDIR/validator.pid")"
      # Wait for RPC to answer instead of a blind sleep.
      for _ in $(seq 1 30); do
        solana cluster-version --url "$RPC_URL" >/dev/null 2>&1 && break
        sleep 1
      done
      solana cluster-version --url "$RPC_URL" >/dev/null 2>&1 || die "validator did not come up"
    else
      log "reusing already-running local validator at $RPC_URL"
    fi
    ;;
  devnet)
    RPC_URL="https://api.devnet.solana.com"
    log "targeting public devnet"
    ;;
  *) die "MODE must be 'localnet' or 'devnet' (got '$MODE')" ;;
esac

solana config set --url "$RPC_URL" >/dev/null

# ── merchant wallet ─────────────────────────────────────────────────────────
if [[ ! -f "$WALLET" ]]; then
  log "generating throwaway merchant wallet → $WALLET"
  solana-keygen new --no-bip39-passphrase --silent --outfile "$WALLET" >/dev/null
fi
MERCHANT="$(solana-keygen pubkey "$WALLET")"

log "funding merchant with SOL (for rent/fees)…"
solana airdrop 2 "$MERCHANT" --url "$RPC_URL" >/dev/null 2>&1 || log "airdrop failed/limited — top up $MERCHANT manually if needed"

# ── (b) test SPL mint ─────────────────────────────────────────────────────────
log "creating test SPL mint ($DECIMALS decimals, USDC-like)…"
MINT="$(spl-token create-token --decimals "$DECIMALS" --url "$RPC_URL" --fee-payer "$WALLET" --mint-authority "$MERCHANT" 2>/dev/null | awk '/Creating token/ {print $3}')"
[[ -n "$MINT" ]] || die "failed to create mint"

# ── (c) mint to the wallet ────────────────────────────────────────────────────
log "creating token account and minting $MINT_AMOUNT test tokens…"
spl-token create-account "$MINT" --url "$RPC_URL" --fee-payer "$WALLET" --owner "$MERCHANT" >/dev/null 2>&1 || true
spl-token mint "$MINT" "$MINT_AMOUNT" --url "$RPC_URL" --fee-payer "$WALLET" --mint-authority "$WALLET" >/dev/null

# ── (d) print paste-ready config ──────────────────────────────────────────────
cat <<EOF

✔ ProofKiosk test environment ready ($MODE)

Paste into your ZeroClaw config (values are TEST-ONLY, throwaway keys under .devnet/):

[plugins.kiosk-charge.config]
merchant_address = "$MERCHANT"
usdc_mint        = "$MINT"
price_list       = "cold_drink:1.5, snack:0.75"
max_amount_usdc  = "10"
label            = "Kiosk 01 (test)"

[plugins.kiosk-watch.config]
rpc_url          = "$RPC_URL"
merchant_address = "$MERCHANT"
usdc_mint        = "$MINT"
finality         = "confirmed"

Merchant keypair: $WALLET
EOF
