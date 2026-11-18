# line — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin for
[LINE](https://developers.line.biz/). LINE has no inbound poll API — it POSTs
signed webhooks — so this plugin serves the host's `/plugin/line` route: it
verifies the `X-Line-Signature` HMAC-SHA256 over the raw body (secret from its
own config; the host stays crypto-agnostic), decodes text events into inbound
messages, and replies via the Messaging API **push** endpoint. A
`wasm32-wasip2` component; no native build.

> **Host requirement.** Inbound needs the host **webhook-ingress** capability
> (zeroclaw#8862): the gateway mounts `/plugin/line` and hands each request to
> the plugin's `parse-webhook`. Point your LINE channel's webhook URL at
> `https://<your-gateway>/plugin/line`.

## Install locally on ZeroClaw v0.9.0

From this plugin directory, build and bind the source-only package:

```sh
cargo build --release --locked --target wasm32-wasip2
mkdir -p target/package
cp manifest.toml target/wasm32-wasip2/release/line.wasm target/package/
zeroclaw plugin install ./target/package --channel-alias line --egress declared
zeroclaw plugin info line
```

Use the channel instance key printed by `zeroclaw plugin info line`. Store each setting under `plugins.entries.<instance-key>.config`. Set secret fields using `zeroclaw config set plugins.entries.<instance-key>.config.channel_secret` and enter the value at the prompt.

Enable plugins, route `plugin.line` to an agent and configure the permitted senders in its peer group. Restart or reload the daemon. Each binding claims the fixed callback path `/plugin/line`, so use one active binding for that path.

The default API hostname is declared in the manifest. If you change the API origin, grant the new trusted hostname in `plugins.entries.<instance-key>.egress_hosts`.

## Configuration

The binding accepts these settings:

- `channel_access_token` (required) — Messaging API bearer token (send).
- `channel_secret` (required) — verifies the `X-Line-Signature` webhook HMAC.
- `api_base_url` — API origin; defaults to `https://api.line.me`. Override for a
  proxy or a test mock.

## Permissions

- `http_client` — outbound push to the Messaging API (TLS host-side).
- `config_read` — read the token + secret above.

## What's covered

`src/line.rs` holds the pure logic — config parsing, HMAC-SHA256 signature
verification, webhook-event → inbound decoding (text only; group/room replies
target the conversation), push-body building, chunking — with host `cargo test`
coverage. `src/lib.rs` is the component shim (webhook exports + `waki` HTTP).

Text messages (send + receive, 1:1 and group) are supported today. Stickers,
images, audio, and the reply-token optimization are future work; replies use
Push (robust for an async agent) rather than the ~30 s reply token.

## Build

```bash
rustup target add wasm32-wasip2
cargo test                                   # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
