# SolSafe Implementation Plan

## Repository Findings

- The plugin registry is a collection of standalone crates under `plugins/*`; there is no root Cargo workspace.
- The canonical tool plugin is `plugins/redact-text`.
- Plugin crates use Rust 2021, `crate-type = ["cdylib", "rlib"]`, `wit-bindgen = "0.46"`, and build with `cargo build --target wasm32-wasip2 --release`.
- The current WIT is `wit/v0`, package `zeroclaw:plugin@0.1.0`.
- Tool plugins implement world `tool-plugin`, exporting `plugin-info` and `tool`, and importing `logging`.
- A tool returns `ToolResult { success, output, error }`.
- Configuration for tool plugins is injected by the host into execute arguments as a flat string map named `__config` when the manifest has `config_read`.
- Structured logging is the imported `zeroclaw::plugin::logging::log_record` function. Production plugin code must not use stdout/stderr.
- HTTP-enabled plugins use `waki` as a wasm-only dependency over host `wasi:http`; host tests keep pure logic free of HTTP.
- Manifest files are flat TOML with `name`, `version`, `description`, `author`, `wasm_path`, `capabilities`, and `permissions`.

## Architecture

- Add `plugins/solsafe-core` as a host-testable pure Rust crate with no WIT dependency.
- Add `plugins/solana-tx-audit` as one ZeroClaw tool component exposing `solana_tx_audit`.
- Add `plugins/jupiter-swap-build-safe` as one ZeroClaw tool component exposing `jupiter_swap_build_safe`.
- Keep all signing/submission/private-key functionality out of scope and out of the input schemas.
- Use mockable `RpcClient` and `JupiterClient` traits in the core; wasm shims adapt `waki` HTTP to those traits.

## Implementation Order

1. Implement policy/config parsing, bounded input validation, base58/base64 helpers, and URL redaction.
2. Implement defensive Solana transaction parsing for legacy and v0 static keys, required signer extraction, account index resolution, and address lookup table fail-closed handling.
3. Implement program labels and security-relevant instruction decoding for System, SPL Token, Token-2022, ATA, Compute Budget, Memo, ALT, and configured Jupiter programs.
4. Implement audit verdicts, findings, declared-intent comparison, blockhash/simulation hooks, compact output shaping, and truncation preserving critical findings.
5. Implement Jupiter guarded quote/swap workflow with exact decimal conversion, limits, route checks, endpoint/config precedence, and a mandatory transaction audit of the returned unsigned transaction.
6. Add WIT shims, manifests, READMEs, DEMO.md, PULL_REQUEST.md, and host-side tests with mock clients only.
7. Run formatting, tests, wasm builds, and security searches.

## Known Scope Boundaries

- Durable nonce replacement/mutation is not implemented; transactions are never mutated.
- Address lookup table transactions require configured RPC resolution. If lookup data is unavailable, audit returns RED.
- Token-2022 extension inspection is represented by explicit security signals when extension account evidence is supplied by RPC/mock data; unresolved extension behavior fails closed under strict policy.
