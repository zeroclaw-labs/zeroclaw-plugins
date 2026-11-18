# slack — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to Slack via the **Events API webhook**. The host serves the
inbound webhook at `/plugin/slack`; this plugin verifies each request's Slack
signature, answers the URL-verification handshake, and decodes message events —
then sends the agent's replies with `chat.postMessage`. It runs entirely inside
a sandboxed `wasm32-wasip2` WIT component, with no native build.


## Install locally on ZeroClaw v0.9.0

From this plugin directory, build and bind the source-only package:

```sh
cargo build --release --locked --target wasm32-wasip2
mkdir -p target/package
cp manifest.toml target/wasm32-wasip2/release/slack.wasm target/package/
zeroclaw plugin install ./target/package --channel-alias slack --egress declared
zeroclaw plugin info slack
```

Use the channel instance key printed by `zeroclaw plugin info slack`. Store each setting under `plugins.entries.<instance-key>.config`. Set secret fields using `zeroclaw config set plugins.entries.<instance-key>.config.signing_secret` and enter the value at the prompt.

Enable plugins, route `plugin.slack` to an agent and configure the permitted senders in its peer group. Restart or reload the daemon. Each binding claims the fixed callback path `/plugin/slack`, so use one active binding for that path.

The default API hostname is declared in the manifest. If you change the API origin, grant the new trusted hostname in `plugins.entries.<instance-key>.egress_hosts`.

## Configuration

The binding accepts these settings:

- `bot_token` (required) — the Slack bot OAuth token (`xoxb-…`), sent as
  `Authorization: Bearer <token>` on every `chat.postMessage`.
- `signing_secret` (required) — the app **signing secret** (Slack app *Basic
  Information → App Credentials*). Used to verify the `X-Slack-Signature` HMAC
  over each inbound webhook body. Without it, every webhook is rejected.
- `api_base_url` — Web API base, default `https://slack.com/api`. Override for a
  proxy or a test double. A trailing slash is trimmed.

The built-in channel additionally supports **Socket Mode** (`app_token`); this
plugin implements the **Events API webhook** path instead.

## How it works

- **Inbound (webhook).** The host serves `GET`+`POST` on `/plugin/slack` and
  hands each request to the plugin. The plugin **owns its authenticity check**:
  it verifies `X-Slack-Signature = v0=<hex(HMAC-SHA256(signing_secret,
  "v0:" + X-Slack-Request-Timestamp + ":" + raw_body))>` and rejects a request
  whose timestamp is outside a 5-minute replay window or whose signature does
  not match. Those failures return the typed unauthorized rejection (HTTP 401)
  and enqueue nothing.
  - A `url_verification` request echoes its `challenge` back in the HTTP
    response body (the verification handshake).
  - An `event_callback` with a plain user message (`event.type == "message"`,
    non-empty `text`, and **no** `bot_id`/`subtype`) is delivered as an inbound
    message: `sender = event.user`, `reply_target = event.channel`,
    `content = event.text`.
- **Outbound.** `send` posts `{ "channel": <reply_target>, "text": <chunk> }` to
  `POST {api_base}/chat.postMessage`; text over ~40 000 characters is split into
  multiple messages.

## Scope (v0.2.0)

Text messages only. **Deferred:** attachments/media, reactions, pins, threads
(replies post to the channel root), draft/streaming updates, and interactive
approvals — all exported as WIT stubs. Bot-authored and subtyped messages are
skipped, which doubles as the self-loop guard.

## Layout

- `src/slack.rs` — the pure core (config, signature verify, payload decode,
  send-body build, chunking). No wasm/http/net deps; covered by `cargo test`.
- `src/lib.rs` — the `wasm32-wasip2` component shim (waki HTTP client, WIT
  `Channel` impl).

## Build & test

```bash
cargo test --lib                        # pure-core host tests
cargo build --target wasm32-wasip2 --release
```
