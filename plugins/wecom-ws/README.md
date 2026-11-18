# WeCom AI Bot

The WeCom AI Bot channel subscribes to callbacks over a host-managed WebSocket. It receives direct and group text, acknowledges subscriptions, sends replies and reconnects after a disconnect.

## Install and configure

Build the source-only package from its directory and bind the channel on ZeroClaw v0.9.0.

```sh
cargo build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/wecom_ws.wasm .
zeroclaw plugin install "$PWD"
zeroclaw plugin bind wecom-ws --channel-alias wecom-bot --egress declared
zeroclaw plugin info wecom-ws
```

Copy the config entry key printed by `plugin info` into the shell variable `key`. The commands for secrets prompt without echo. The declaration grants `openws.work.weixin.qq.com` when selected at bind time.

```sh
zeroclaw config set "plugins.entries.$key.config.bot_id" 'BOT_ID'
zeroclaw config set "plugins.entries.$key.config.secret"
zeroclaw config set "plugins.entries.$key.config.allowed_users" '["operator-userid"]'
zeroclaw config set "plugins.entries.$key.config.allowed_groups" '["approved-chatid"]'
```

Enable `plugins.enabled`, route `plugin.wecom-bot` to an enabled agent, and authorize senders in the alias’s peer group.

Empty `allowed_users` and `allowed_groups` deny all inbound callbacks. A `"*"`
entry allows every identifier in that list; all other identifiers are matched
exactly. `bot_name` supplies the self handle and `@mention` metadata.

ZeroClaw's generic plugin-channel authorizer also checks the callback sender
user ID against the alias's live `peer_groups` external peers. Consequently,
an `allowed_groups` entry does not bypass the host sender gate; group users must
also be present there (or the peer group must contain `"*"`).

## Supported behavior

- Connect to `wss://openws.work.weixin.qq.com` and send `aibot_subscribe`.
- Correlate the subscribe acknowledgement by `headers.req_id` without waiting
  or sleeping inside `poll-message`.
- Drain text frames in bounded batches and return immediately on an idle socket.
- Decode direct and group `aibot_msg_callback` text messages, including quoted
  text, and preserve the callback request ID for active-session replies.
- Suppress replayed message IDs with a bounded 4096-entry session cache.
- Reply with final or progressive `aibot_respond_msg` stream frames.
- Send proactive markdown with `aibot_send_msg` to `user--<userid>` and
  `group--<chatid>` recipients, using UTF-8-safe chunks.
- Send WeCom application ping frames every 30 seconds and reconnect with bounded
  exponential backoff on closure, transport failure, subscribe timeout, or a
  `disconnected_event`.

## Current limits

Only the protocol text path is implemented. Voice, image, file, and mixed
callbacks are ignored; media download, AES decryption, reactions, welcome-card
events, and typing indicators are not available. `proxy_url`, file retention,
and file-size config are native media/transport concerns and are not consumed by
this component. WebSocket command acknowledgements arrive asynchronously, so a
successful `send` confirms host-buffer acceptance rather than remote delivery.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
```
