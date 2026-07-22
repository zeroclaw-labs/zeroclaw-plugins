# spl-transfer-build

**Custody tier: T1 — build only.** This plugin holds no key and cannot sign.
It returns bytes that stay inert until a wallet, a hardware device, or a Squads
multisig signs them. The `sender` in its config is a public key.

Turns "pay this invoice with 25 USDC" into an unsigned, already-simulated
transaction plus a summary a human can read on a phone — and refuses, inside
the plugin, anything outside the operator's spend caps.

```
> pay CTvcx7vZKfU86DmKUa8jG94Am7eK4L5JZXKJ3NQPMHTs 0.1 USDC for invoice 412

UNSIGNED TRANSFER — nothing has been signed or sent
send 0.1 EPjFWd…Dt1v
from GThUX1…hFMJ
to   CTvcx7…MHTs
memo "invoice 412"
validity: a recent blockhash
note: expires in about a minute: no durable nonce is configured, so this must be signed promptly
note: creates the recipient's token account, about 0.00204 SOL of rent paid by the sender
note: this token's issuer can freeze the recipient's account
simulated on-chain: succeeds, 35755 compute units
digest d436e60144ecf66cbecf2b7c662c6a5f187592c3b514565c2a117563b73f778c
^ your wallet must show this same digest before you approve

base64 transaction (unsigned):
AQAAAAAAAAAA…
```

That output is real: built by this plugin against mainnet-beta and simulated by
the cluster, which is where the 35 755 compute units came from.

## The security model in one paragraph

**The boundary is `config.toml`, not the conversation.** A per-mint spend cap
doubles as the allowlist, so a mint with no cap cannot be sent at all. There is
no tool argument that raises a cap, adds a mint, changes the sender, or disables
the simulation. An agent that has been talked into anything — by a poisoned web
page, a hostile email, a user who changed their mind — can still only ask for a
transfer that policy already allows. And whatever it asks for, a human still has
to sign it.

```toml
[[plugins.entries.spl-transfer-build]]
sender     = "GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ"
spend_caps = "SOL:0.5, EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v:100"
```

Default-deny falls out of the data structure rather than out of a flag someone
can forget to set: with no `spend_caps`, nothing is sendable at all.

### The transcript

From `tests/transfer.rs::an_amount_over_the_cap_is_refused_however_it_was_argued_for`:

```
agent call:  solana_build_transfer{recipient: "9pan9b…", amount: "1000", mint: "EPjFW…"}
config cap:  100 USDC

tool output: refused (over_cap): 1,000 exceeds this agent's per-transfer cap of
             100. The cap is set in the operator's config file and cannot be
             raised from a conversation.
```

A refusal returns `success: false` with a reason. The model can tell "policy
said no" apart from "the node was down" — which matters, because it must never
be able to read a timeout as an approval.

## What it refuses

| Code | Why |
|---|---|
| `no_sender` | the operator has not configured a sender wallet |
| `mint_not_allowlisted` | no spend cap exists for this asset |
| `over_cap` | the amount exceeds the per-transfer cap |
| `bad_amount` | not a plain decimal, or more precision than the mint has — never silently rounded |
| `recipient_is_not_a_wallet` | the recipient is a token account or a mint; the transfer would be unrecoverable |
| `self_transfer`, `recipient_is_system_program` | obvious mistakes an agent makes more often than a person |
| `source_missing`, `source_frozen`, `insufficient_balance` | the sender cannot actually pay |
| `non_transferable`, `paused`, `default_frozen` | the token cannot move, or the recipient could not spend it |
| `transfer_hook_armed` | this builder does not resolve a hook's extra accounts, so the transfer would fail on-chain |
| `transfer_fee_too_high` | the token withholds more than the operator allows |
| `nonce_invalid`, `nonce_authority_mismatch` | a nonce that would produce a transaction that can never land |
| `simulation_failed` | the cluster says it would fail; do not ask a human to approve it |
| `bad_memo` | the memo carries control characters or text aimed at a model, and would be written permanently to a public ledger |

Note what is **not** on that list. A permanent delegate and a freeze authority
are custody risks, not broken transfers, and they appear as warnings in the
summary instead. The operator allowlisted this mint; refusing to move an
allowlisted token would just push the payment somewhere with no guardrails at
all. Pair with [`token-risk-check`](../token-risk-check) to decide what belongs
in the allowlist in the first place.

## Blockhash expiry, and the fix

The structural problem with approval-gated agent payments: the plugin builds a
transaction, it lands in a Telegram approval queue, and the human is at lunch.
A `recent_blockhash` is valid for about 150 slots. By the time they tap approve,
it is dead — and they approved bytes that no longer exist.

Configure a durable nonce account and the transaction stops expiring:

```toml
nonce_account = "…"      # created once by the operator, not by the agent
```

```bash
solana-keygen new -o nonce.json
solana create-nonce-account nonce.json 0.0015 --nonce-authority <sender>
```

The builder then reads the nonce account, verifies its authority matches the
configured signer — a mismatch is refused, because it would produce a
transaction that can never land — puts `AdvanceNonceAccount` first, and uses the
stored nonce as the message's blockhash. Build it now, sign it tomorrow, and
replay is still impossible because advancing the nonce is part of the
transaction.

Without a nonce, the summary says so in plain words rather than pretending.

## The digest

A build-then-approve flow is only worth anything if the human approves the same
bytes the tool described. The `digest` line is the SHA-256 of the serialized
message: compare it against what the wallet shows before signing. If they
differ, something rewrote the transaction between here and there.

## Config

| Key | Default | Meaning |
|---|---|---|
| `sender` | — | **Required.** The signing wallet's public key |
| `spend_caps` | (empty) | `SOL:0.5, <mint>:100` — per-transfer ceilings, and the allowlist |
| `rpc_url` | `https://api.mainnet-beta.solana.com` | JSON-RPC endpoint; the API key never appears in output |
| `nonce_account` | — | Durable nonce account, so approvals can take their time |
| `nonce_authority` | `sender` | The key that advances the nonce |
| `priority_fee_micro_lamports` | — | Priority fee bid per compute unit |
| `max_transfer_fee_bps` | `100` | Refuse tokens withholding more than this |
| `simulate` | `true` | Simulate before returning |

A malformed value is dropped, never coerced into something permissive: a cap of
`100abc` is not a cap of 100, and a mint address with a typo is not an
allowlisted mint.

## Why there is no per-day cap

A daily limit needs state that survives a call. This plugin deliberately holds
none — no key, no counter, nothing to compromise. At T1 the rate limit is the
human: every transfer needs a signature, and a person who is asked to approve
six payments in an hour notices. A T2 plugin that signs on its own would need a
real per-day cap, and would need somewhere trustworthy to keep it.

## Cost

**At most four RPC round trips**: the mint, one batched read of the recipient
and both token accounts and the nonce, a blockhash (skipped entirely when a
durable nonce is configured), and the simulation.

## Build and test

```bash
cargo test                                    # 42 host tests, no wasm, no network
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release  # the component
```

## Install

```bash
zeroclaw plugin install spl-transfer-build
```

Or copy this directory, with the built `.wasm` next to its `manifest.toml`, into
your plugins dir.

## Built on

[`solana-wasi`](https://crates.io/crates/solana-wasi) — Solana primitives that
compile to `wasm32-wasip2`, including the unsigned v0 transaction construction
this plugin uses. That crate cannot sign either: it has no keypair type.

## License

MIT. See [LICENSE](LICENSE).
