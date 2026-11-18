# DingTalk

DingTalk Stream Mode channel. The plugin registers the bot over HTTPS, opens the returned WebSocket, acknowledges callbacks and sends replies through the session webhook supplied by DingTalk.

## Install and configure

Build the source-only package from its directory and bind the channel on ZeroClaw v0.9.0.

```sh
cargo build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/dingtalk.wasm .
zeroclaw plugin install "$PWD"
zeroclaw plugin bind dingtalk --channel-alias dingtalk-bot --egress declared
zeroclaw plugin info dingtalk
```

Copy the config entry key printed by `plugin info` into the shell variable `key`. The commands for secrets prompt without echo. The declared host is `api.dingtalk.com` for registration. Also grant the hosts from your DingTalk gateway WebSocket URL and session webhook URL on this instance’s `egress_hosts`. Keep the registration host when updating the list.

```sh
zeroclaw config set "plugins.entries.$key.config.client_id" 'APP_KEY'
zeroclaw config set "plugins.entries.$key.config.client_secret"
```

Enable `plugins.enabled`, route `plugin.dingtalk-bot` to an enabled agent, and authorize senders in the alias’s peer group.

Outbound messages require a prior inbound message for that chat because
DingTalk creates the session reply URL dynamically.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
```
