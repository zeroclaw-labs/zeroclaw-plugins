# Session wallet setup

The Vault transit key created by [`vault-init.sh`](./vault-init.sh) is the
**session wallet** — the public key that `solana-build-tx` sets as fee-payer
and `solana-keychain-sign` signs for. This page covers the model and how to
fund it.

## The session-key model

```
  ┌──────────────────────────────────────┐
  │ HashiCorp Vault (transit engine)     │
  │  key: solana-session  type: ed25519  │
  │  ⟶ private key NEVER leaves Vault    │
  └────────────────┬─────────────────────┘
                   │ pubkey only
  ┌────────────────▼─────────────────────┐    small balance
  │ Session wallet  (on-chain account)   │ ◄───────────────
  │  - lamports for fees                 │
  │  - SPL token balances the agent      │
  │    is allowed to move                │
  └──────────────────────────────────────┘
```

**This is NOT your main wallet.** The session wallet holds only what the agent
is allowed to spend in a session:

- **SOL** — enough for transaction fees (~0.05 SOL covers hundreds of txs at
  2024 fee levels). The agent cannot move SOL itself unless the operator
  allows it via `mint_allowlist` + `per_call_outflow_cap` (SPL mints only;
  native SOL outflow is bounded by the fee-payer's balance + the
  `max_message_bytes` envelope guard).
- **SPL tokens** — only the mints in `solana-build-tx`'s `mint_allowlist`, and
  only up to `per_call_outflow_cap` per call. For a USDC agent: fund with the
  daily cap × expected calls per day.

The main wallet stays in cold storage / hardware wallet / Phantom. The user
**pre-approves** any delegation (`approve(tributary_pda, amount)`) from their
own wallet; the agent only ever calls `execute_payment` against the
pre-existing delegation. The agent never holds the `approve` capability.

**Risk surface:** if the ZeroClaw process is compromised, the attacker can
sign transactions up to the configured caps until the operator rotates the
Vault key. They cannot access the main wallet. Caps + allowlists bound the
blast radius; rotation stops the bleed.

## 1. Get the session pubkey

After `docker compose -f docker/vault-dev-compose.yml up -d`:

```bash
bash docker/vault-init.sh
# → VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=root
#   VAULT_KEY_NAME=solana-session VAULT_PUBKEY=<base58>
```

The `VAULT_PUBKEY` printed is the session wallet's on-chain address. Export
it for the next steps:

```bash
export VAULT_PUBKEY=<paste from vault-init.sh output>
```

## 2. Fund on devnet (free, for the Quickstart)

```bash
solana config set --url devnet
solana airdrop 2 "$VAULT_PUBKEY"          # 2 SOL, devnet rate-limited
solana balance "$VAULT_PUBKEY"            # confirm it landed
```

For SPL USDC on devnet, use the [Solana SPL token UI](https://spl-token-ui.com/)
or CLI to mint test tokens to the session wallet. The mint address goes into
`solana-build-tx`'s `mint_allowlist`.

> Devnet airdrops are rate-limited to ~1 SOL per hour per IP. If the airdrop
> fails, wait and retry, or use the [Solana web faucet](https://faucet.solana.com/).

## 3. Fund on mainnet (real value, for production)

```bash
solana config set --url mainnet-beta
# Transfer SOL for fees from your main wallet:
solana transfer "$VAULT_PUBKEY" 0.05 --from <main-wallet-keypair>

# Transfer SPL tokens (e.g., USDC) the agent may spend:
spl-token transfer <USDC_MINT> 100 "$VAULT_PUBKEY" \
    --from <main-wallet-keypair> \
    --owner <ATA-of-main-wallet>
```

Fund only what the agent needs for the operating window. **Never** fund the
session wallet from a hardware wallet with a large balance connected —
disconnect the hardware wallet immediately after the transfer.

## 4. Confirm build-tx and signer agree on the pubkey

Both plugins must reference the SAME session pubkey. Verify:

```bash
zeroclaw config get plugins.entries.solana-build-tx.config.signer_pubkey
zeroclaw config get plugins.entries.solana-keychain-sign.config.signer_pubkey
```

Both must print `$VAULT_PUBKEY`. If they differ, `solana-keychain-sign`'s
envelope guard will reject every message with `fee_payer mismatch` — that's
the defense-in-depth firing.

## 5. Top up when low

Monitor the session wallet balance. When it drops below a threshold, repeat
step 2 (devnet) or step 3 (mainnet). For a production deployment, wire a
ZeroClaw SOP trigger that alerts when the balance falls below
`expected_daily_spend × 2`.

## 6. Rotate the key (if compromised or on schedule)

```bash
# Create a new transit key in Vault:
vault write -f transit/keys/solana-session-v2 type=ed25519
# Read its pubkey:
vault read transit/keys/solana-session-v2
# Drain the old session wallet to a new one, then update both plugins' config:
zeroclaw config set plugins.entries.solana-build-tx.config.signer_pubkey <NEW_PUBKEY>
zeroclaw config set plugins.entries.solana-keychain-sign.config.signer_pubkey <NEW_PUBKEY>
zeroclaw config set plugins.entries.solana-keychain-sign.config.vault_key_name solana-session-v2
```

The old key remains in Vault for audit/recovery; remove it with
`vault delete transit/keys/solana-session` only after confirming no
outstanding transactions reference it.
