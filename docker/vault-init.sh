#!/usr/bin/env bash
# vault-init.sh — enable Vault transit engine, create the ed25519 session key,
# and print its base58 pubkey for the Solana plugins.
#
# Preconditions: docker/vault-dev-compose.yml is up (port 8200 reachable).
# Idempotent: safe to re-run; existing engine + key are left in place.
#
# Output (stdout): shell `export` lines. Usage:
#   eval "$(bash docker/vault-init.sh)"
#
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
VAULT_KEY_NAME="${VAULT_KEY_NAME:-solana-session}"

# ── Wait for Vault to accept requests ────────────────────────────────────────
# Dev server boots in ~1s; poll health for up to 30s.
for _ in $(seq 1 60); do
  if curl -sf "${VAULT_ADDR}/v1/sys/health" -o /dev/null; then
    break
  fi
  sleep 0.5
done
if ! curl -sf "${VAULT_ADDR}/v1/sys/health" -o /dev/null; then
  echo "ERROR: Vault at ${VAULT_ADDR} is not responding." \
       "Did you run: docker compose -f docker/vault-dev-compose.yml up -d" >&2
  exit 1
fi

Hdr=(-H "X-Vault-Token: ${VAULT_TOKEN}")

# ── Enable the transit secret engine (idempotent) ────────────────────────────
# 400 "path is already in use" is the expected no-op when re-running.
status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${Hdr[@]}" \
  -d '{"type":"transit","description":"ZeroClaw Solana session signing"}' \
  "${VAULT_ADDR}/v1/sys/mounts/transit")
case "${status}" in
  204|400) : ;;                                  # created, or already mounted
  *) echo "ERROR: enabling transit engine failed (HTTP ${status})" >&2; exit 1 ;;
esac

# ── Create the ed25519 key (idempotent) ──────────────────────────────────────
# 200 = created or already exists (newer Vault); 204 = created (older Vault);
# 400 = key already exists (older Vault). We do NOT export the private key —
# it stays in Vault transit forever.
status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${Hdr[@]}" \
  -d '{"type":"ed25519","exportable":false,"allow_plaintext_backup":false}' \
  "${VAULT_ADDR}/v1/transit/keys/${VAULT_KEY_NAME}")
case "${status}" in
  200|204|400) : ;;                              # created, or already exists
  *) echo "ERROR: creating transit key '${VAULT_KEY_NAME}' failed (HTTP ${status})" >&2; exit 1 ;;
esac

# ── Read the public key (base64-encoded 32-byte ed25519 pubkey) ──────────────
pubkey_b64=$(curl -sf "${Hdr[@]}" \
  "${VAULT_ADDR}/v1/transit/keys/${VAULT_KEY_NAME}" \
  | python3 -c '
import json, sys
doc = json.load(sys.stdin)
# Transit returns keys keyed by version number as strings.
keys = doc["data"]["keys"]
latest = sorted(keys.keys(), key=int)[-1]
print(keys[latest]["public_key"])
')

if [ -z "${pubkey_b64}" ]; then
  echo "ERROR: could not read public_key from Vault transit response" >&2
  exit 1
fi

# ── Convert the base64 ed25519 pubkey → Solana base58 ────────────────────────
# Python3 stdlib only (base64 is builtin; base58 is hand-rolled below —
# no pip install needed).
pubkey_b58=$(python3 -c '
import base64, sys
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = ALPHABET[r] + s
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + s
print(b58encode(base64.b64decode(sys.argv[1])))
' "${pubkey_b64}")

# ── Sanity: ed25519 pubkeys are 32 bytes → 43 or 44 base58 chars ─────────────
if [ ${#pubkey_b58} -lt 43 ] || [ ${#pubkey_b58} -gt 44 ]; then
  echo "WARNING: derived pubkey '${pubkey_b58}' is ${#pubkey_b58} base58 chars;" \
       "expected 43–44. Check the Vault key type." >&2
fi

# ── Emit export-ready output (stdout only, one var per line) ─────────────────
# Operators can `eval "$(bash docker/vault-init.sh)"` or read individual lines.
cat <<EOF
export VAULT_ADDR=${VAULT_ADDR}
export VAULT_TOKEN=${VAULT_TOKEN}
export VAULT_KEY_NAME=${VAULT_KEY_NAME}
export VAULT_PUBKEY=${pubkey_b58}
EOF
