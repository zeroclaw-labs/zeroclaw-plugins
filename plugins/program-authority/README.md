# program-authority

`program-authority` is a T0 read-only ZeroClaw tool for answering a narrow but
important Solana question: **who can still replace this program's code?**

Given one public program address, it reads the executable account and, for
upgradeable programs, its linked ProgramData account. It reports:

- loader type;
- ProgramData address;
- deployment slot;
- current upgrade authority, if present;
- whether the program is immutable; and
- an explicit risk flag when an upgrade authority remains.

It cannot build, sign, deploy, upgrade, close, or submit a transaction. The
plugin makes at most two `getAccountInfo` calls and fails closed on malformed
loader state, mismatched ownership, non-executable input, invalid base64, and
RPC errors.

## Install and configure

```bash
zeroclaw plugin install ./plugins/program-authority

cat >> ~/.zeroclaw/config.toml <<'TOML'
[plugins.program-authority]
rpc_url = "https://api.mainnet-beta.solana.com"
commitment = "finalized"
TOML
```

Only `rpc_url` and `commitment` are read from configuration. Non-loopback RPC
URLs must use HTTPS and may not contain embedded credentials.

## Real read-only demo

Inspect the Metaplex Token Metadata program:

```text
Use program-authority with program_id
metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s and explain whether an upgrade
authority is still present. Do not sign or submit anything.
```

The same prompt works from a ZeroClaw Telegram or Discord channel. The output
is compact JSON so the agent can explain the result without forwarding raw
account bytes into the conversation.

## Verify

```bash
cargo test --manifest-path plugins/program-authority/Cargo.toml
cargo clippy --manifest-path plugins/program-authority/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/program-authority/Cargo.toml --target wasm32-wasip2 --release
```

## Safety level

T0 (read-only). Inputs contain only a public Solana address. The plugin exposes
no signer, wallet, key, transaction, deployment, upgrade, or close capability.
