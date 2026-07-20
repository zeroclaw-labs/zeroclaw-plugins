# governance-vote-build

A custody tier **T1 (build-only)** ZeroClaw WIT tool for preparing a Realms
governance vote. It verifies the proposal is open for voting, verifies the
wallet has deposited voting power, and asks the official Realms API to build
the unsigned transaction.

This plugin has no key, signing, RPC-send, or transaction-confirmation path.
Its output must be decoded, inspected, simulated, approved by a human, and
signed in an external wallet.

## Required fail-closed config

The plugin rejects every call unless the operator configures both allowlists:

```toml
[plugins.governance-vote-build]
allowed_realms = "4ct8XU5tKbMNRphWy4rePsS9kBqPhDdvZoGpmprPaug4"
allowed_vote_kinds = "approve,deny"
max_transactions = "2"
api_base_url = "https://v2.realms.today/api/v1"
```

`allowed_realms` and `allowed_vote_kinds` are comma-separated. Supported vote
kinds are `approve`, `deny`, `abstain`, and `veto`. `max_transactions` defaults
to 2 and cannot exceed 4.

## Tool

`governance_vote_build` accepts:

```json
{
  "realm": "4ct8XU5tKbMNRphWy4rePsS9kBqPhDdvZoGpmprPaug4",
  "proposal": "11111111111111111111111111111111",
  "wallet": "SysvarC1ock11111111111111111111111111111111",
  "vote": "approve"
}
```

The response contains base64 unsigned transaction bytes and a human-readable
summary. The tool always sends `createTokenOwnerRecord: false`; it will not
silently opt a wallet into the Realms API's 0.1 SOL first-time account-creation
fee. A wallet with no existing voting-power record must join through a separate,
explicit flow first.

## Safety model

- All three public keys are validated before network access.
- Realm and vote-kind policy comes only from jailed operator config. Arguments
  and proposal text cannot expand those allowlists.
- Only proposals in Realms state `2` (`Voting`) proceed.
- A community or council deposit greater than zero is required.
- Server-supplied signer key material is rejected without being copied into
  output or errors.
- Returned transaction count and size are bounded, base64 is decoded, and each
  serialized signature slot must be all zeroes. A pre-signed response fails.
- No tool path signs, sends, confirms, or retries an on-chain transaction.

## Build and test

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --target wasm32-wasip2 -- -D warnings
cargo build --locked --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/governance_vote_build.wasm governance_vote_build.wasm
```

Install the directory with `zeroclaw plugin install governance-vote-build`
after placing the built component next to `manifest.toml`.

## API provenance

The request shape, vote-kind mapping, membership response, unsigned transaction
contract, and fee behavior follow the
[Realms governance API reference](https://github.com/Mythic-Project/realms-agent-docs/blob/main/governance/references/api.md).

## License

MIT
