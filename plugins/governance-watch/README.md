# governance-watch

A custody tier **T0 (read-only)** ZeroClaw WIT tool for monitoring
[Realms](https://realms.today/) governance proposals. It calls the official
Realms API, filters proposals locally, and returns a compact JSON summary that
is suitable for alerts and agent reasoning.

The tool never holds keys, signs transactions, submits transactions, follows a
proposal's `descriptionLink`, or performs an on-chain write.

## Tool

`governance_watch` accepts:

```json
{
  "realm": "4ct8XU5tKbMNRphWy4rePsS9kBqPhDdvZoGpmprPaug4",
  "states": ["voting", "succeeded"],
  "limit": 5,
  "since_unix": 1767225600
}
```

`states`, `limit`, and `since_unix` are optional. The default state set is
`signing_off,voting,succeeded,executing`. Vote weights are returned in their
original hexadecimal form and as decimal strings so large token values are not
silently rounded.

## Safety model

- Realm and proposal IDs must decode to exactly 32 bytes of base58 before any
  network call is made.
- Operator config caps the result count; tool arguments cannot raise it.
- API responses, option counts, text lengths, and final output are bounded.
- Proposal names and description links are marked as untrusted data. The tool
  never fetches linked content, so proposal text cannot expand its authority.
- The API base must be HTTPS and can only be changed by operator-owned jailed
  config, not by a tool caller.

## Config

```toml
[plugins.governance-watch]
api_base_url = "https://v2.realms.today/api/v1"
max_results = "10"
default_states = "signing_off,voting,succeeded,executing"
```

All keys are optional. `max_results` must be between 1 and 20.

## Build and test

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --target wasm32-wasip2 -- -D warnings
cargo build --locked --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/governance_watch.wasm governance_watch.wasm
```

Install the directory with `zeroclaw plugin install governance-watch` after
placing the built component next to `manifest.toml`.

## API provenance

Endpoint and state mappings follow the
[Realms governance API reference](https://github.com/Mythic-Project/realms-agent-docs/blob/main/governance/references/api.md).

## License

MIT
