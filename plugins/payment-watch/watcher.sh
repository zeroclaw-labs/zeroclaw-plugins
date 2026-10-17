#!/bin/sh
# Economical background watcher for payment-watch — a reference shell cron job.
#
# One or two RPC calls per tick, ZERO LLM calls. Announces to Telegram only
# when a NEW incoming SOL payment lands at the watched wallet, deduped by a
# state file. Schedule it with a ZeroClaw shell cron (see README, "Background
# watching"):
#
#   [cron.payment_watcher]
#   job_type = "shell"
#   enabled  = true
#   command  = "sh watcher.sh"
#   [cron.payment_watcher.schedule]
#   kind = "every"
#   every_ms = 30000
#
# Inputs come from the environment, so no secrets sit in the command string:
#   WATCH_RECIPIENT  the wallet whose incoming payments to watch (public addr)
#   WATCH_RPC        RPC endpoint (default: a public mainnet node)
#   WATCH_CHAT       Telegram chat id to notify
#   the Telegram bot token the channel already uses (env var below)
#
# This watches native SOL — the common demo case. For SPL tokens or exact
# amount-matching, use the payment_watch tool on demand; it reuses the same
# vetted core with full token support.
RECIPIENT="${WATCH_RECIPIENT}"
RPC="${WATCH_RPC:-https://solana-rpc.publicnode.com}"
CHAT="${WATCH_CHAT}"
TOKEN="${ZEROCLAW_channels__telegram__default__bot_token}"
STATE="${WATCH_STATE:-.watch-last-sig}"

[ -z "$RECIPIENT" ] && exit 0
[ -z "$TOKEN" ] && exit 0
[ -z "$CHAT" ] && exit 0

# Newest signature touching the wallet (1 cheap RPC call).
newest=$(curl -s --max-time 12 "$RPC" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",\"params\":[\"$RECIPIENT\",{\"limit\":1}]}" \
  2>/dev/null | jq -r '.result[0].signature // empty' 2>/dev/null)
[ -z "$newest" ] && exit 0

# First run: record a baseline without announcing existing history.
if [ ! -f "$STATE" ]; then echo "$newest" > "$STATE"; exit 0; fi
last=$(cat "$STATE" 2>/dev/null)
[ "$newest" = "$last" ] && exit 0   # nothing new -> stop here (no 2nd call)

echo "$newest" > "$STATE"

# Only for a genuinely new signature: fetch it and measure the wallet's credit.
tx=$(curl -s --max-time 15 "$RPC" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"$newest\",{\"encoding\":\"jsonParsed\",\"maxSupportedTransactionVersion\":0}]}" 2>/dev/null)
lamports=$(printf '%s' "$tx" | jq -r --arg R "$RECIPIENT" '
  .result as $t
  | ($t.transaction.message.accountKeys | map(if type=="object" then .pubkey else . end) | index($R)) as $i
  | if ($i == null) or ($t.meta.err != null) then 0
    else ($t.meta.postBalances[$i] - $t.meta.preBalances[$i]) end' 2>/dev/null)

# Announce only a positive (incoming) credit; ignore outgoing transfers and fees.
case "$lamports" in ''|-*|0) exit 0 ;; esac
sol=$(awk "BEGIN{printf \"%.9g\", ${lamports}/1000000000}")
curl -s --max-time 12 "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  --data-urlencode "chat_id=${CHAT}" \
  --data-urlencode "text=✅ Payment received: ${sol} SOL
https://solscan.io/tx/${newest}" >/dev/null 2>&1
exit 0
