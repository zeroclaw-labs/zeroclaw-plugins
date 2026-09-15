# solana-keychain-sign

The **T2 custody** ZeroClaw tool plugin: sign and submit a Solana versioned
transaction via a configured signing backend without the Ed25519 private key
ever entering the ZeroClaw process. Designed to consume the pre-validated
unsigned transactions produced by its sibling plugin
[`solana-build-tx`](../solana-build-tx/).

> **Status (v0 scaffold).** The crate layout, manifest, WIT component shim,
> and module seams are in place; the implementations land with descendant
> beans tracked under
> [milestone `zeroclaw-solana-bounty-jkjl`](../../README.md). Everything
> here compiles host-side and the wasm component builds against the vendored
> `wit/v0` `tool-plugin` world. See _Status_ below for the per-module map.

## Custody tier

| Tier                       | What the plugin holds                                                                                      | What it does                                                                                                                  | What it never sees                                                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **T2** — signs and submits | Backend credentials (Vault token / AWS keys / GCP OAuth2 token), RPC URL, operator pubkey, envelope limits | Re-fetches a fresh blockhash, posts message bytes to the backend, attaches the signature, submits via RPC, polls confirmation | The Ed25519 private key (lives only in Vault transit / KMS), transaction **content** validation (lives in `solana-build-tx` via simulation) |

The plugin enforces **envelope-only guards** (max message size, instruction
count, fee-payer match). All financial policy — mint allowlists, per-call
outflow caps, recipient allowlists, the hardcoded `approve` family blocklist
— is enforced by `solana-build-tx` against `simulateTransaction` output
before the unsigned tx ever reaches this signer.

## How it answers bounty Trap #1 (blockhash freshness)

A blockhash fetched at build time can expire during the human approval
window. The signer **re-fetches** a fresh blockhash immediately before
posting the message to the backend, re-assembles the V0 message with the
new blockhash, and only then signs. Build-time blockhash is never trusted.

This is wired in [`submit::execute`] (bean `zeroclaw-solana-bounty-s37c`),
which calls [`rpc::RpcClient::get_latest_blockhash`] as step 3 of its
10-step flow.

## Plugin args (the LLM-facing contract)

```jsonc
{
  "instructions_base64": "<base64-encoded unsigned versioned tx from solana-build-tx>",
}
```

The `__config` map is injected by the host (manifest declares
`permissions = ["config_read"]`). The keys the plugin reads from it are
finalized by `zeroclaw-solana-bounty-7p6z` (factory + config schema); a
non-exhaustive preview:

```toml
[plugins.entries.solana-keychain-sign.config]
backend         = "vault"          # vault | aws_kms | gcp_kms
vault_addr      = "https://vault.example:8200"
vault_token     = "<hidden>"       # redacted from Debug + logs + errors
vault_key_name  = "solana-session"
vault_pubkey    = "9XJ…base58…"    # operator-extracted; envelope fee_payer must match
rpc_url         = "https://api.mainnet-beta.solana.com"
signer_pubkey   = "9XJ…base58…"    # the backend's pubkey; envelope fee_payer must equal this
max_message_bytes    = 1024        # default 1 KiB
max_instructions     = 1           # default 1, locked for v0
confirm_timeout_secs = 30          # default 30s
```

## Result

On success the `ToolResult.output` JSON carries:

```json
{
  "signature":    "<base58 tx signature>",
  "explorer_url": "https://solscan.io/tx/<signature>",
  "slot":         <confirmed slot>
}
```

On any validation failure, RPC error, simulation revert, or confirmation
timeout, `ToolResult.success` is `false`, `error` carries the
operator-facing reason (no secrets), and the plugin emits a `log-record`
at `warn` with `action=Reject`.

## Backends

| Backend                                                                  | v0 status                                                          | Auth                                                                                      |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| **Vault transit** ([`src/backends/vault.rs`](src/backends/vault.rs))     | Stub now, **fully working** once `m4wx` lands                      | `X-Vault-Token` header                                                                    |
| **AWS KMS** ([`src/backends/aws_kms.rs`](src/backends/aws_kms.rs))       | Stub — returns `NotImplemented`, ships shape helpers + SigV4 plan  | SigV4 hand-roll (~300 LOC pure Rust, v1) — see module docs                                |
| **GCP Cloud KMS** ([`src/backends/gcp_kms.rs`](src/backends/gcp_kms.rs)) | Stub — returns `NotImplemented`, ships shape helpers + OAuth2 plan | v1: operator-pasted short-lived `access_token`; v2: service-account JWT — see module docs |

The `SignerBackend` trait + `SignerError` enum live in
[`src/backends/mod.rs`](src/backends/mod.rs). A factory `from_config`
(bean `zeroclaw-solana-bounty-7p6z`) selects one backend per session from
`cfg.backend`.

## Layout

```
Cargo.toml           standalone [workspace], cdylib + rlib, all signer deps
manifest.toml        name, version, wasm_path, capabilities, permissions
src/
  lib.rs             pub mod tree + #[cfg(wasm)] WIT component shim
  rpc.rs             DONE — waki JSON-RPC client (getLatestBlockhash /
                     sendTransaction / getSignatureStatuses) +
                     submit_and_confirm orchestrator (bean 4c1h)
  envelope.rs        STUB — EnvelopeConfig + check() (bean pptg)
  submit.rs          STUB — execute() sign+submit+confirm flow (bean s37c)
  backends/
    mod.rs           SignerBackend trait + SignerError (5ev1)
    aws_kms.rs       DONE — STUB + shape helpers + SigV4 plan (5ev1)
    vault.rs         STUB — VaultClient (bean m4wx owns full impl)
    gcp_kms.rs       STUB — GcpKmsClient (bean 88iq owns impl + OAuth2 plan)
tests/
  rpc.rs             DONE — full host suite vs mock transport (4c1h)
  aws_kms.rs         DONE — full host suite vs mock envelopes (5ev1)
  signer.rs          SCAFFOLD smoke test (this bean, 67ip)
                     full host suite lands with bean ylkw
README.md            this file
```

## Build and test

```bash
# Host tests — no wasm toolchain, no network. Every test fakes RPC / HTTP.
cargo test

# Wasm component build:
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/solana_keychain_sign.wasm solana_keychain_sign.wasm
```

## Install

```bash
zeroclaw plugin install solana-keychain-sign
```

or copy the directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir. The host must be built with a compiler backend
(`--features plugins-wasm,plugins-wasm-cranelift`) for the component to
load; for runtime-only hosts, precompile with a matching wasmtime
(`wasmtime compile --target <triple> solana_keychain_sign.wasm -o
solana_keychain_sign.cwasm`) and point `wasm_path` at the `.cwasm`.

## Threat model (summary)

- **Private key compromise**: out of scope by construction — the key never
  leaves the backend (Vault transit HSM in v0). Compromising the ZeroClaw
  process leaks the config (Vault token, RPC URL, pubkey) but not the key.
- **Prompt injection that asks the agent to sign a harmful tx**: blocked
  upstream by `solana-build-tx`'s simulation-based policy (mint allowlist,
  per-call outflow cap, recipient allowlist, hardcoded `approve` blocklist,
  Layer B token-account state-diff check). This plugin's envelope guards
  are defense-in-depth: a tx that does not pay from `signer_pubkey`, is too
  large, or carries > 1 instruction never reaches the backend.
- **Replay with a stale blockhash**: blocked by the fresh-blockhash re-fetch
  at sign time (Trap #1 fix in `submit.rs`).
- **Composite tx smuggling** (one approved instruction + one attacker
  instruction): blocked by the `max_instructions = 1` envelope guard,
  locked for v0.
- **Backend credential exfiltration via crafted error output**: blocked by
  the redacted `Debug` impls on every backend struct; `SignerError`
  variants are operator-facing strings and never carry secrets.

Full threat model + worked examples land with the milestone-level README
(bean `zeroclaw-solana-bounty-1kqp`).

## Status

Per-module ownership and v0 status (live ledger under
`.beans/zeroclaw-solana-bounty-*.md`):

| Module / file                                                                                                                                                                    | Bean               | Status       |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | ------------ |
| `Cargo.toml`, `manifest.toml`, `src/lib.rs`, `src/envelope.rs` (stub), `src/submit.rs` (stub), `src/backends/{vault,gcp_kms}.rs` (stubs), `tests/signer.rs` (smoke), `README.md` | `67ip` (this bean) | **scaffold** |
| `src/rpc.rs`, `tests/rpc.rs`                                                                                                                                                     | `4c1h`             | done         |
| `src/backends/aws_kms.rs`, `tests/aws_kms.rs`                                                                                                                                    | `5ev1`             | done         |
| `src/backends/mod.rs` (`SignerBackend` trait, `SignerError`)                                                                                                                     | `5ev1`             | done         |
| `src/backends/vault.rs` full impl                                                                                                                                                | `m4wx`             | todo         |
| `src/backends/gcp_kms.rs` shape helpers + tests                                                                                                                                  | `88iq`             | todo         |
| `src/envelope.rs` real guards                                                                                                                                                    | `pptg`             | todo         |
| `src/submit.rs` real flow                                                                                                                                                        | `s37c`             | todo         |
| `backends::from_config` factory                                                                                                                                                  | `7p6z`             | todo         |
| `tests/signer.rs` full suite                                                                                                                                                     | `ylkw`             | todo         |

## License

MIT — see the top-level `LICENSE` block in `Cargo.toml`. Matches every other
crate in this repo.
