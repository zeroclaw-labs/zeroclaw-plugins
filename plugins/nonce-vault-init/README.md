# nonce-vault-init

Part of **Aval**, an approval rail for transacting agents: the agent
proposes, the human co-signs on their own schedule, the chain settles. See
[`durable-tx-build`](../durable-tx-build/README.md) for the full rail.

## What it does

One-time setup: builds the unsigned transaction that creates and initializes
a **durable nonce account** — the "waiting room" every later payment sits in
while a human decides. Idempotent: if the vault already exists, it reports
the address instead of building a doomed transaction.

Two design decisions carry the safety story:

- **No second keypair, ever.** The account address is derived with
  `createAccountWithSeed` from the human authority itself, so the only
  signer in the whole system is the human wallet. The agent cannot leak a
  secret it never had.
- **Honest about its one weakness.** This is the only Aval transaction that
  uses a recent blockhash (a nonce cannot anchor its own creation), so the
  summary explicitly tells the human to sign promptly. Every transaction
  after this one is durable.

Distinct `seed` labels give one wallet several parallel vaults ("approval
lanes"), each an independent durable queue.

## Custody tier: T1, zero secrets

Returns an unsigned transaction; holds no key material. Rent for the 80-byte
nonce account (about 0.0015 SOL, fetched live from the RPC) is paid by the
authority and reclaimable by the authority at any time via
`solana nonce-account withdraw`.

## Config

```toml
rpc_url = "https://your-rpc.example.com"   # operator-supplied; never hardcoded
```

## Worked example

```json
{ "authority": "4Nd1mYvR3PLoKAxUWnvpbZBPeNSHnYuXK8Xw41k5vRW5", "seed": "aval-0" }
```

returns

```json
{
  "summary": "Setup transaction built: creates durable nonce vault 9WzD..AWWM for authority 4Nd1..vRW5 (seed \"aval-0\", rent 0.00144768 SOL, reclaimable by the authority). Sign promptly — this setup step is the only Aval transaction that expires; every payment built afterwards is durable.",
  "nonce_account": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
  "transaction_base64": "AAAA…"
}
```

## Threat model

| Threat | Outcome |
|---|---|
| Injection passes free text as the authority | Base58 validation; refused |
| Injection passes hostile seed (`../../etc`) | Seed charset restricted to `[A-Za-z0-9_-]`; refused |
| Injection smuggles extra argument fields | `deny_unknown_fields`; parse error |
| Vault address collision with a stranger's account | Existing account with a foreign nonce authority is a hard error, never adopted |
| Malicious RPC | Can only cause a refusal or an unsigned tx the wallet rejects; no key exists to steal |

The transcript-backed injection tests live in `tests/init.rs`
(`fails_closed_on_bad_input`).

## Build & test

```
cargo test                                     # host tests, mocked RPC
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release   # produces nonce_vault_init.wasm
cp target/wasm32-wasip2/release/nonce_vault_init.wasm nonce_vault_init.wasm
```

## Install

```bash
zeroclaw plugin install nonce-vault-init
```

or copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins:

```toml
[plugins]
enabled = true
```

Run the agent with a build that includes a compiler backend, e.g.
`--features plugins-wasm,plugins-wasm-cranelift`. For runtime-only hosts
(`--features plugins-wasm`), precompile with a matching wasmtime:
`wasmtime compile --target <triple> nonce_vault_init.wasm -o nonce_vault_init.cwasm` and point
`wasm_path` at the `.cwasm`.


Pure core in `src/init.rs`; wasm shim in `src/lib.rs`. Vendored substrate in `src/core/` (canonical source:
[aval-core](https://github.com/bryankwandou/aval-core), kept self-contained
here as the registry's per-plugin CI requires).

## What we'd build next / wasm32-wasip2 notes

Suite-level roadmap and the full write-up of what fought us on
wasm32-wasip2 live in [`durable-tx-build`](../durable-tx-build/README.md)
(sections "What we'd build next" and "What fought us on wasm32-wasip2").

## License

MIT — see [LICENSE](LICENSE).
