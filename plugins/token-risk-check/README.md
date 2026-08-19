# token-risk-check

Read-only T0 risk scoring for bounded, provider-verified token signals. It never accepts keys,
constructs transactions, signs, transfers, or trades. The current component exposes the pure
scoring core through the ZeroClaw tool boundary; live RPC/DAS adapters are added only after
fixture coverage is complete.

Risk flags cover mint/freeze authorities, holder concentration, liquidity, and metadata
verification. `registry = false` is intentional until the stock host exposes the required HTTP
capability. Run `cargo test --locked` and the `wasm32-wasip2` release build locally.
