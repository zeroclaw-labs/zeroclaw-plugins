# solana-token-risk

`solana-token-risk` is a single-purpose ZeroClaw **WIT component tool** that
turns two Solana JSON-RPC read calls into a short, explicit token-mint summary.
It is designed for the practical first question an autonomous agent should ask
before it describes a token: **who can still change or freeze it, and how
concentrated are the largest token accounts?**

It is deliberately **T0 (read-only)**:

- no wallet SDK or private-key parsing;
- no transaction construction, signing, broadcasting, approval request, or
  Solana Pay URL;
- exactly two RPC methods: `getAccountInfo` and `getTokenLargestAccounts`;
- output is bounded and says what the data cannot prove.

The tool requests canonical base64 mint-account data from the configured RPC.
That keeps the decoder independent of display-oriented RPC parsing and lets it
recognize Token-2022 extension TLVs without guessing from UI labels.

## Why this is useful

Raw RPC responses are too large and too easy for an LLM to over-interpret. The
plugin reduces them to the facts an operator can act on without handing a model
custody:

- mint program, supply, and decimals;
- whether a mint authority can change supply;
- whether a freeze authority can freeze token accounts;
- Token-2022 extension flags, including transfer fees, permanent delegates,
  and transfer hooks when present;
- top-one and top-five **token-account** concentration; and
- explicit caveats that token accounts are not unique owners, and that pools or
  custody services may aggregate many users.

It does not label a token safe, legitimate, or investable. It reports only the
limited, live on-chain signals it can observe.

## Tool contract

Tool name: `solana_token_risk`

```json
{
  "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
}
```

`mint` must decode to a 32-byte base58 public key. The plugin rejects malformed
input before making a network call.

The result is plain text deliberately kept compact for an agent context. A
successful result always contains this statement:

> No transaction, signature, private key, or wallet access was requested or
> produced.

## Configuration

The default is Solana's public mainnet-beta RPC. Operators should normally
provide their own HTTPS RPC endpoint for dependable production use:

```toml
[plugins.solana-token-risk]
rpc_url = "https://your-rpc.example"
```

`rpc_url` is read only from this plugin's jailed config section. It must use
HTTPS, may not contain user credentials, and is never accepted from the LLM's
tool arguments. This prevents a prompt from redirecting the tool to arbitrary
destinations. The endpoint is a trusted operator configuration choice, as with
any RPC client.

## Permissions and custody tier

```toml
capabilities = ["tool"]
permissions = ["http_client", "config_read"]
```

`http_client` permits host-mediated HTTPS JSON-RPC reads. `config_read` gives
the component only its own flat configuration section. The component requests
neither signing nor wallet permissions, and it has no implementation of either.

### Threat model

| Threat | Mitigation / limit |
| --- | --- |
| Prompt-injected mint or endpoint | Mint must be a 32-byte base58 key. The endpoint comes only from operator config, never tool arguments. |
| Private-key or wallet theft | No key, signer, wallet, transaction, or approval code exists in the component. |
| RPC spoofing, staleness, or rate limits | HTTPS is required, but an RPC is still an external data source. Output calls this informational rather than a security verdict. |
| Misleading concentration claims | It reports token-account—not beneficial-owner—concentration and names custody/pool aggregation as a limit. |
| Token-context bloat | It reads two small RPC payloads and returns a bounded summary rather than raw account lists. |

## Build and test

From this plugin directory:

```bash
cargo test
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/solana_token_risk.wasm solana_token_risk.wasm
```

The host tests cover mint validation, base64 legacy and Token-2022 mint
metadata, authority states, extension-TLV rejection, concentration calculation,
malformed RPC responses, and the output's safety disclosures. They use fixtures
and make no live RPC calls.

## Example interpretation

If a mint authority is present, the plugin says that supply can change; it does
not guess who controls that authority or whether the control is trustworthy. If
the largest five token accounts hold 80% or more of the reported supply, it
marks that as a high concentration indicator while preserving the warning that
an LP, exchange, or custodian may represent many underlying holders.

## What this intentionally does not do

- estimate a token's price, liquidity, or financial value;
- identify a pool, exchange, or legal owner from a token-account address;
- declare a token free from risk;
- return a transaction, swap quote, or payment request; or
- send, sign, approve, or broadcast anything.

Those functions belong behind separate custody tiers and explicitly reviewed
permissions—not inside a read-only risk summary.

## Submission notes

**Custody tier and why:** T0. The component only reads public mint metadata and
largest token-account balances. The T0 boundary is enforced in both the
manifest (only `http_client` and `config_read`) and the implementation (no
wallet, signer, transaction, or approval dependency).

**What fought us:** the useful Solana client crates are not appropriate inside a
small `wasm32-wasip2` component. The component therefore uses only the host's
blocking `wasi:http` transport via `waki`, hand-shapes two JSON-RPC requests,
and keeps numeric parsing and risk interpretation in a host-testable pure core.
This avoids importing a native RPC stack or silently widening the sandbox.

**What to build next:** add a separate, opt-in T0 component for a bounded
transaction explanation, and only after that consider a T1 component that
constructs an unsigned transaction with explicit allowlists and a human approval
gate. Neither belongs in this plugin or shares its permission set.
