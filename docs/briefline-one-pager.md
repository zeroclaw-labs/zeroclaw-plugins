# Briefline — ZeroClaw Read-Only Solana Analysis Suite

## Architecture

Briefline is a set of self-contained Rust WebAssembly components targeting `wasm32-wasip2`.
Each plugin keeps its logic in a host-testable pure Rust core and exposes a thin ZeroClaw WIT
shim. Inputs are bounded, outputs are compact, and secrets are never accepted.

## T0 safety model

All tools are strictly read-only. They cannot accept private keys, sign transactions, construct
transfers, swap assets, or move funds. Tool approval is required before execution, and prompt
injection attempts are refused with an explicit no-transaction response.

## Tools

- `portfolio-brief`: SOL/token balances, estimated holdings, concentration, and activity.
- `token-risk-check`: authority, holder concentration, liquidity, and metadata risk flags.
- `wallet-narrate`: bounded activity summaries with redacted signatures and failure labels.
- `stake-monitor`: delegated, active, activating, and deactivating stake health.

## Telegram demo

The live demo shows ZeroClaw tool approval, successful read-only results, redacted wallet
activity, stake activation reporting, and refusal of a private-key transfer request.

## Validation

Host tests, standalone fixture tests, formatting, Clippy, and `wasm32-wasip2` release builds pass.
The upstream PR is [#141](https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/141).

## Threat model

Provider responses are bounded and parsed conservatively. Unknown transaction formats are labeled
instead of guessed. Credentials are injected by the host and never returned in output. Optional
provider failures become visible degraded-data warnings.

## Known limitation

`token-risk-check` is currently marked `registry = false` because stock ZeroClaw hosts do not yet
provide the required `wasi:http` capability for live provider egress. Its deterministic core and
WASM boundary remain tested and available for host-gated development.
