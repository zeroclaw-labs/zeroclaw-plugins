# solana-core

Pure Rust Solana substrate for ZeroClaw wasm tool plugins. No wit-bindgen, waki, or solana-sdk.

Legacy Solana message encoding is implemented first because it keeps the wasip2 substrate simple and dependency-light. Versioned v0 messages can be added later if plugins need address lookup tables or newer transaction features.

Canonical source lives at repo-root `solana-core/`. Plugin vendor trees are kept in sync via `tools/sync-solana-core.sh`.

License: MIT (see `LICENSE`).
