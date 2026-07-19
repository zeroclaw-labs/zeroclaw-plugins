# sol-get-balance

A read-only [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **WIT tool
plugin**. It implements the `tool-plugin` world from `wit/v0` and compiles to a
`wasm32-wasip2` component.

## What it does

Exposes one tool, **`sol_get_balance`**, that looks up the native balance of a
Solana account and returns it as both lamports and SOL. It calls the Solana
JSON-RPC [`getBalance`](https://solana.com/docs/rpc/http/getbalance) method over
`wasi:http`. Read-only: it holds no keys, signs nothing, and moves no funds.

### Input

```json
{ "address": "So11111111111111111111111111111111111111112" }
```

`address` is the account's base58-encoded public key. It is validated to decode
to exactly 32 bytes before any network call is made.

### Output

The tool's `output` is a compact JSON string:

```json
{
  "address": "So11111111111111111111111111111111111111112",
  "lamports": 58238313,
  "sol": 0.058238313,
  "rpc_url": "https://api.mainnet-beta.solana.com"
}
```

`lamports` is exact. `sol` is the human-readable conversion (`lamports / 1e9`);
for balances above 2^53 lamports treat it as approximate and rely on `lamports`.

Bad input (unparseable arguments, a non-base58 or wrong-length address) and
RPC/network errors come back as a `ToolResult` with `success: false` and an
`error` message — a normal tool response the model can react to — rather than
crashing the call.

## Config keys

Injected under `__config` only when the manifest declares `config_read`. Without
it, the plugin falls back to the public mainnet endpoint.

| Key | Default | Meaning |
|---|---|---|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | JSON-RPC endpoint to query. Point this at a private/paid RPC to avoid public rate limits. |

Set it per plugin name, e.g. `zeroclaw config set sol-get-balance.rpc_url <url>`.

## Permissions

- `http_client` — the tool POSTs to the RPC endpoint over `wasi:http`. Without
  it the component has no network surface at all.
- `config_read` — lets the host inject the `rpc_url` override.

## Layout (the reference format)

```
src/balance.rs   # pure logic, no wasm deps — host-testable with `cargo test`
src/lib.rs       # thin #[cfg(target_family = "wasm")] component shim
tests/balance.rs # host-run tests over the pure core + a live-RPC smoke check
manifest.toml    # name, version, wasm_path, capabilities, permissions
```

## Build and test

```bash
cargo test                                          # host tests (incl. live RPC smoke); no wasm needed
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2        # the component
cp target/wasm32-wasip2/release/sol_get_balance.wasm sol_get_balance.wasm
```

Validate the component:

```bash
wasm-tools validate --features all sol_get_balance.wasm
wasm-tools component wit sol_get_balance.wasm       # shows the exported tool interface
```

Run `cargo test -- --nocapture` to see the live balance printed by the smoke
test. That test soft-skips on transport/rate-limit errors so offline builds
still pass.

## Install

Copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir (default `~/.zeroclaw/plugins/`), or:

```bash
zeroclaw plugin install ./sol-get-balance/
zeroclaw config set plugins.enabled true
zeroclaw plugin list
```

Run the agent with a build that includes the plugin host and a compiler backend:
`cargo build --release --features plugins-wasm,plugins-wasm-cranelift`. The
prebuilt release binaries do **not** include the plugin host.
