# account-rent

`account-rent` is a T0 read-only ZeroClaw tool for inspecting the storage and
rent state of a Solana account before an operator funds or integrates it.

Given one public account address, it reports:

- the owning program and executable flag;
- the account's data length and lamport balance;
- the current minimum balance for rent exemption;
- the exact surplus or deficit against that minimum; and
- a risk flag when the account is not rent exempt.

The plugin cannot create, resize, fund, close, sign for, or submit a transaction.
It makes exactly two bounded Solana RPC calls and fails closed on missing
accounts, invalid base64, malformed responses, invalid addresses, and RPC
errors.

## Install and configure

```bash
zeroclaw plugin install ./plugins/account-rent

cat >> ~/.zeroclaw/config.toml <<'TOML'
[plugins.account-rent]
rpc_url = "https://api.mainnet-beta.solana.com"
commitment = "finalized"
TOML
```

Only `rpc_url` and `commitment` are read from configuration. Non-loopback RPC
URLs must use HTTPS and may not contain embedded credentials.

## Real read-only demo

Inspect Solana's public rent sysvar account:

```text
Use account-rent with account_address
SysvarRent111111111111111111111111111111111 and report its owner, data size,
and exact rent-exemption surplus. Do not sign or submit anything.
```

The prompt can be issued through a ZeroClaw Telegram or Discord channel. The
tool returns compact JSON and never requests a wallet or private material.

## Verify

```bash
cargo test --manifest-path plugins/account-rent/Cargo.toml
cargo clippy --manifest-path plugins/account-rent/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/account-rent/Cargo.toml --target wasm32-wasip2 --release
```

## Safety level

T0 (read-only). The only task input is a public Solana address. The plugin
exposes no signer, wallet, key, transaction, funding, resize, or close
capability.
