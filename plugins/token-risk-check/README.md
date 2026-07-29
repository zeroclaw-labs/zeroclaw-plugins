# token-risk-check

A ZeroClaw **WIT component** tool plugin that assesses the on-chain risk of a
Solana token mint before the agent trades or displays it. It implements the
`tool-plugin` world from `wit/v0` and compiles to a `wasm32-wasip2` component.
Structured after the canonical reference plugin, `redact-text`.

> **Status: fetch layer done, classification pending.** `execute` fetches the
> mint account over Solana JSON-RPC (`getAccountInfo`, jsonParsed) and returns
> the parsed facts with an explicit pre-classification `"unknown"` verdict.
> Any RPC failure, missing account, or parse error is fail-closed: an error
> result, never green. The red/yellow/green classifier lands next.

## What it does

A `token-risk-check` tool. Given a base58 mint address, it fetches the mint
account (`getAccountInfo`, jsonParsed) from the configured RPC — `rpc_url` in
the plugin's config section, falling back to the public mainnet endpoint —
and currently returns the parsed facts pre-classification:

```json
{
  "verdict": "unknown",
  "note": "pre-classification: mint account fetched and parsed; risk checks not yet implemented",
  "mint_account": {
    "owner_program": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    "mint_authority": null,
    "freeze_authority": null,
    "supply": "1000000000000000",
    "decimals": 9,
    "is_initialized": true,
    "extensions": [{"extension_type": "permanentDelegate", "state": {"delegate": "…"}}]
  }
}
```

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
