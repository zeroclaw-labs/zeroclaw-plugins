# QQ Official Bot

The bot supports the following QQ operations.

- OAuth app-access-token acquisition and expiry-aware refresh;
- gateway discovery over HTTPS;
- host-mediated WebSocket Identify/Resume and heartbeat frames;
- C2C and group-at text dispatch with message deduplication;
- markdown text sends to `user:<openid>` and `group:<openid>` recipients.

## Install and configure

Build the source-only package from its directory and bind the channel on ZeroClaw v0.9.0.

```sh
cargo build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/qq.wasm .
zeroclaw plugin install "$PWD"
zeroclaw plugin bind qq --channel-alias qq-bot --egress declared
zeroclaw plugin info qq
```

Copy the config entry key printed by `plugin info` into the shell variable `key`. The commands for secrets prompt without echo. Grant the gateway hostname returned by QQ in addition to the declared token and REST hosts (`bots.qq.com` and `api.sgroup.qq.com`).

```sh
zeroclaw config set "plugins.entries.$key.config.app_id" 'APP_ID'
zeroclaw config set "plugins.entries.$key.config.app_secret"
```

Enable `plugins.enabled`, route `plugin.qq-bot` to an enabled agent, and authorize senders in the alias’s peer group.

The plugin handles text. Media uploads, downloads, voice transcription and a per-channel proxy are outside this implementation.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
```
