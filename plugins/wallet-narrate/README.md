# wallet-narrate

Read-only T0 activity narration with bounded input and signature redaction. It never accepts
keys, signs, transfers, or constructs transactions.

The tool accepts bounded `activity` fixtures or parsed `rpc_result` signature data. Provider
failures and unknown instruction types are reported without exposing raw instruction payloads.
Run `cargo test --locked` for host fixtures and build with `--target wasm32-wasip2`.
