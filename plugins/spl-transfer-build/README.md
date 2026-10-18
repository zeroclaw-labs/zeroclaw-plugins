# spl-transfer-build

**Tier 1 (build-only, zero secrets)** tool plugin for ZeroClaw: build unsigned
SPL/SOL transfer transactions (base64) with ATA handling and memo — plus a
human-readable summary an approval gate can render before signing.

```
agent: spl-transfer-build(from=Treasury…, to=Vendor…, amount=25, mint=USDC,
                          decimals=6, memo="Invoice #412")
       → {"unsigned_tx_base64": "AQ==…", "summary": "Send 25 tokens…\nAttach memo…\nUNSIGNED — …",
          "needs_ata_creation": true, "recent_blockhash": "EkSn…"}
gate:  human reviews summary → signs in wallet / Squads → broadcast
```

## Custody tier: T1 — the agent proposes, a human disposes

The plugin **never sees, holds, or derives a private key**. Its outputs are an
unsigned transaction and a plain-language summary. Signing happens outside:
a wallet, a Squads multisig proposal, or the host approval gate. RPC usage is
read-only (`getLatestBlockhash`, `getAccountInfo` for ATA existence) — the only
possible secret is an RPC API key in the configured endpoint URL.

The best pattern from the bounty brief — *"the agent proposes, a Squads multisig
disposes"* — is exactly what this plugin implements: pipe `unsigned_tx_base64`
into a proposal, a human approves from their phone.

## What it does

- **SOL transfers**: system-program transfer (lamports)
- **SPL transfers**: `TransferChecked` with explicit decimals; source/destination
  ATAs derived as proper PDAs (real ed25519 off-curve check, bump 255→0)
- **ATA creation**: `CreateIdempotent` when the destination ATA is missing
  (existence checked via RPC; idempotent on-chain if it raced)
- **Memo**: Memo-program instruction for invoice reconciliation (pairs with
  `payment-watch`'s reference matching)
- **Summary**: every instruction rendered in plain English + `UNSIGNED` marker
- Hand-rolled legacy wire format (shortvec, account-meta ordering, header) —
  no `solana-sdk` dependency, wasm-friendly, fully deterministic

## Tool schema

| arg | type | required | notes |
|---|---|---|---|
| `from` | string | ✓ | sender (signs outside this plugin) |
| `to` | string | ✓ | recipient |
| `amount` | number | ✓ | ui amount |
| `mint` | string | | SPL mint; omit/`"SOL"` for native |
| `decimals` | integer | | SPL decimals (6 for USDC; default 9) |
| `memo` | string | | on-chain memo |
| `create_ata_if_missing` | bool | | default true |

Config: `rpc_url` (config_read).

## Permissions

`http_client` (read-only RPC), `config_read`. No signing, no sockets.

## Engineering notes

Pure core, zero wasm imports, host-tested (8 tests): base58 roundtrip, system
program = zero address, deterministic canonical ATA derivation (**verified
against live mainnet** — the derived ATA for a known owner/USDC pair resolves
to a real on-chain token account), unsigned wire-format decode (1 signature,
64 zero bytes, correct header), SPL+ATA-creation assembly, amount validation.
CI: `tools/ci/validate_components.sh spl-transfer-build` — clippy clean
(host + wasm), artifact `spl_transfer_build.wasm`.
