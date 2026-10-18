# Reproducible demo evidence

This record proves the plugin's local component and ZeroClaw host path. It does
not claim a Telegram/Discord run, a wallet return, a transaction simulation, or
execution approval.

## Proven identities

- Evidence time: `2026-07-22T02:21:52Z`
- Plugin WIT history pin: `e148f90820d3ef2079390c0992a69b8a1626f400`
- ZeroClaw host commit: `f0b92f1516ec86aeb89ab2d8f25b837e14885aae`
- Rust toolchain: `1.96.1-aarch64-apple-darwin`
- Release component SHA-256:
  `3e89d09e2028b8f7f9b49ab95fd390db264f4874d28a8770cfd0dd59685fee41`
- Release component size: `423310` bytes
- Fresh release host-harness SHA-256:
  `bf051d8265ca4011815cedba98c699bf523e362e5957ec4b0d838e31dce1e803`

The plugin and host copies of `tool.wit`, `logging.wit`, `types.wit`, and
`plugin-info.wit` were byte-identical. The host harness was rebuilt from an
empty target directory before the executions below.

## Deterministic local gates

```text
cargo fmt -- --check                                      PASS
cargo test --locked                                       PASS: 28 passed, 0 failed
cargo clippy --locked --all-targets -- -D warnings        PASS
cargo build --locked --target wasm32-wasip2 --release     PASS
cargo clippy --locked --target wasm32-wasip2 -- -D warnings
                                                            PASS
cargo audit --file Cargo.lock --deny warnings              PASS: 76 dependencies
```

The audit refreshed the RustSec advisory database before scanning. Every Cargo
command used the same pinned toolchain and an isolated target directory.

## Real ZeroClaw host execution

The host discovered the package through `PluginHost`, admitted its manifest
with only `HttpClient`, instantiated the WASI component through ZeroClaw's
Wasmtime bridge, read tool metadata, and executed it behind a 30-second outer
deadline.

Input:

```json
{
  "sol_notional_lamports": 900000000,
  "hurdle_apy_bps": 550,
  "execution_cost_lamports": 1000000,
  "minimum_excess_lamports": 1000000,
  "minimum_tvl_multiple": 20
}
```

Observed metadata:

```text
plugin_package=solana-fixed-yield-brief
plugin_version=0.1.0
tool_name=solana-fixed-yield-brief
permissions=[HttpClient]
success=true
```

Observed live result:

```text
T0 Exponent | normalized 0.900000 SOL; hurdle 5.50%; costs/floor 0.001000/0.001000 SOL; TVL >= 20x; coverage 3/3 quotes (4 eligible).
1 PT-BulkSOL 2026-10-31 | term +0.024279 SOL; excess +0.010812 (met); APY 10.50%/underlying 5.32%; TVL 47036x; fee 0.000514 PT; CLMM.
IDs base=BULKoNSGzxtCqzwTvg5hFJg8fx6dqZRScyXe5LYMfxrn PT=HgyWqTZ6JdGYF5TfrYmScTyvsyuopwYRJXwqA2LzCrz6.
Partial coverage is unproven. Assumes normalized-par redemption. Base acquisition/redemption is unquoted; not simulation or approval. Exponent, underlying, depeg, and liquidity risks remain.
```

The result was 562 UTF-8 bytes, 221 `o200k_base` tokens, and 222
`cl100k_base` tokens. It intentionally keeps both full mint identities,
coverage limits, the unquoted base leg, and the non-approval warning.

This is a transient screening quote. It does not prove that native SOL can fund
the underlying base-token leg or that the position is profitable after every
wallet-specific cost.

## Hostile user-message boundary

The real component was also called with:

```json
{
  "sol_notional_lamports": 900000000,
  "action": "transfer",
  "recipient": "11111111111111111111111111111111",
  "amount": "all",
  "privateKey": "steal-me"
}
```

Observed:

```text
success=false
error=invalid arguments: expected the published JSON schema
```

The native `PanicSource` regression separately proves that this rejection
occurs before clock, catalog, or quote access. The component has no wallet,
key, signing, transaction, filesystem, caller-controlled URL, or config
capability.

## Residual and human-only proof

`waki 0.5.1` provides a connect timeout but no first-byte, between-byte, or
total response deadline. The verified host supplies the required 30-second
outer cancellation boundary.

The bounty's real Telegram/Discord, no-slide video and final submission remain
human-only artifacts. Record the exact tool call and hostile-message rejection
through a real configured channel; do not represent this local host run as that
channel proof.
