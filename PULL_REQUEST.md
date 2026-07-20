# feat(plugins): add SolSafe transaction audit and guarded Jupiter swap tools

## Summary

Adds SolSafe for ZeroClaw: two Solana-native ZeroClaw tool plugins plus a shared pure Rust core.

## Plugins Added

- `solana-tx-audit`
- `jupiter-swap-build-safe`
- shared crate: `solsafe-core`

## Custody Tiers

- `solana-tx-audit`: `T0 - Read`
- `jupiter-swap-build-safe`: `T1 - Build`

Neither plugin accepts private keys, seed phrases, secret keys, raw signing material, signing requests, or transaction submission requests.

## Safety Design

- Pure-core/thin-WASM-shim architecture.
- Strict JSON input parsing with bounded strings, payloads, arrays, and outputs.
- Defensive Solana transaction parser for legacy and v0 static-key transactions.
- Fail-closed handling for malformed transactions, unresolved lookup tables, unknown critical instructions, forbidden programs, unexpected transfers, unexpected recipients, unexpected signers, delegate approvals, authority changes, account closures, mint/burn operations, simulation failures, and expiry failures.
- Jupiter workflow validates quote data, route bounds, slippage, price impact, mint allowlists, amount caps, and then audits the actual returned unsigned transaction.

## Permissions Requested

- `config_read`: administrator policy injected as jailed `__config`.
- `http_client`: Solana RPC and Jupiter quote/swap requests.

No filesystem, socket, signing, or private-key permissions.

## Transaction Verification Behavior

The audit plugin decodes and labels:

- System Program
- SPL Token Program
- Token-2022 Program
- Associated Token Account Program
- Compute Budget Program
- Memo Program
- Address Lookup Table Program
- Jupiter Aggregator v6
- configured program IDs

Security-relevant instruction handling includes SOL transfers, account creation/assignment, SPL/Token-2022 transfers, approvals, revokes, authority changes, close account, mint, burn, freeze/thaw, sync native, ATA creation, compute budget, memo, and Token-2022 extension risk signals.

## Prompt-Injection Resistance

Policy is read from plugin config and enforced in Rust. Conversation text and ordinary execute arguments cannot:

- raise amount caps
- raise slippage
- add mints or programs
- permit unknown programs
- disable strict mode
- disable required simulation
- change configured endpoints

Tests include prompt attempts to weaken policy and amount caps.

## Verified Test Commands

```powershell
cd plugins\solsafe-core
cargo test
cd ..\solana-tx-audit
cargo test
cd ..\jupiter-swap-build-safe
cargo test
```

Results:

- `solsafe-core`: 35 passed, 0 failed, 0 ignored.
- `solana-tx-audit`: 2 passed, 0 failed, 0 ignored.
- `jupiter-swap-build-safe`: 2 passed, 0 failed, 0 ignored.

## Verified WASM Build Commands

```powershell
cd plugins\solana-tx-audit
cargo build --target wasm32-wasip2 --release
cd ..\jupiter-swap-build-safe
cargo build --target wasm32-wasip2 --release
```

Verified artifacts:

- `plugins/solana-tx-audit/target/wasm32-wasip2/release/solana_tx_audit.wasm`
- `plugins/jupiter-swap-build-safe/target/wasm32-wasip2/release/jupiter_swap_build_safe.wasm`

## Test Results

Verified on Windows 10 with Rust `1.97.1`, `wasm32-wasip2` installed:

```powershell
cargo fmt --all --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo check --target wasm32-wasip2 --release
cargo build --target wasm32-wasip2 --release
```

## Known Limitations

- Durable nonce support is not implemented.
- Address lookup tables require RPC; unresolved lookup table data fails closed.
- Token-2022 extension support is security-signal focused rather than a complete extension indexer.
- UI amount conversion requires Solana RPC token decimals.
- The plugins never mutate or refresh transactions.

## Demo Link

Placeholder: `<demo-video-url>`

## Reviewer Checklist

- [ ] Each plugin exports exactly one tool.
- [ ] WIT world is `tool-plugin` from `wit/v0`.
- [ ] Manifests request only `http_client` and `config_read`.
- [ ] No signing/submission/private-key path exists.
- [ ] Host tests use mock RPC/Jupiter clients only.
- [ ] Unknown critical behavior fails closed.
- [ ] README threat models match implemented behavior.
- [ ] WASM artifacts build for `wasm32-wasip2`.
