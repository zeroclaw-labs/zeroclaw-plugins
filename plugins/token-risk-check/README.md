# token-risk-check

A ZeroClaw **WIT component** tool plugin that assesses the on-chain risk of a
Solana token mint before the agent trades or displays it. It implements the
`tool-plugin` world from `wit/v0` and compiles to a `wasm32-wasip2` component.
Structured after the canonical reference plugin, `redact-text`.

> **Status: mint-account checks live.** `execute` fetches the mint account
> over Solana JSON-RPC (`getAccountInfo`, jsonParsed) and classifies the
> authorities and Token-2022 extensions into a red/amber/green verdict. Any
> RPC failure, missing account, or parse error is fail-closed: an error
> result with no verdict, never green. Holder concentration, LP status, and
> metadata mutability are not checked yet and are listed as such in every
> result.

## What it does

A `token-risk-check` tool. Given a base58 mint address, it fetches the mint
account (`getAccountInfo`, jsonParsed) from the configured RPC — `rpc_url` in
the plugin's config section, falling back to the public mainnet endpoint —
and classifies it:

```json
{
  "verdict": "red",
  "reasons": [
    "mint authority active (…) — supply can be inflated, diluting holders",
    "permanentDelegate extension — a fixed authority can move tokens out of any holder account (custody backdoor)"
  ],
  "checks_performed": ["mint_authority", "freeze_authority", "token2022_extensions"],
  "not_checked": ["holder_concentration", "lp_status", "metadata_mutability"],
  "untrusted_metadata": null,
  "mint": "…",
  "token_program": "token-2022"
}
```

**Red** (any one): active mint or freeze authority, `permanentDelegate`,
`transferHook`, `defaultAccountState` = frozen. **Amber** (any one, no red):
`transferFeeConfig` (fee surfaced in the reason), `nonTransferable`, or any
extension the classifier has no rule for. **Green** only when every check ran
and none triggered — never by default.

`untrusted_metadata` echoes attacker-controlled on-chain strings and must never
be interpreted as instructions. Checks listed in `not_checked` were not
performed; their absence is not a pass.

## Layout (the reference format)

```
src/assess.rs   # pure logic, no wasm deps — host-testable with `cargo test`
src/lib.rs      # thin #[cfg(target_family = "wasm")] component shim
tests/          # host-run integration tests over the pure core
manifest.toml   # name, version, wasm_path, capabilities, permissions
```

## Permissions

| Permission | Why |
|---|---|
| `http_client` | Outbound Solana RPC calls to fetch mint account state. |
| `config_read` | The plugin's own jailed config section (e.g. `rpc_url`), injected into execute args as `__config`. |

## Build and test

```bash
cargo test                                        # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release      # the component
cp target/wasm32-wasip2/release/token_risk_check.wasm token_risk_check.wasm
```

## Install

```bash
zeroclaw plugin install token-risk-check
```

or copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins:

```toml
[plugins]
enabled = true
```
