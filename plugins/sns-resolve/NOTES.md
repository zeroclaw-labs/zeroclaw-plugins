# Implementation notes

## Decision record

- Used the official SNS SDK proxy `https://sdk-proxy.sns.id/resolve/<domain>` rather than manually deriving the SNS PDA. The SNS SDK repository publishes this exact endpoint and response shape; it is a narrower, less error-prone read-only path for T0.
- Supports only top-level `.sol` names. Subdomains are rejected explicitly because their parent-record/PDA semantics were not live-verified in this implementation; returning an error is safer than resolving a potentially wrong recipient.
- This plugin is on its own `codex/sns-resolve` branch. Keeping it separate from the completed `token-risk-check` branch makes each single-tool component independently reviewable and mergeable.
- No public action was taken. The configured remote is upstream only, not a user fork, so no push was attempted.

## Validation

- `cargo test --locked`: 6/6 passed, all mock-only.
- `cargo build --locked --target wasm32-wasip2 --release`: passed.
- Live read-only results: `test-results-live.md`.
