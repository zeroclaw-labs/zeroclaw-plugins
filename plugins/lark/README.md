# lark — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to **Lark** (International) or **Feishu** (China) through the
Open Platform **event webhook** + `im/v1/messages` API — all from a sandboxed
`wasm32-wasip2` WIT component, with no native build.

```bash
zeroclaw plugin install lark \
  --registry https://raw.githubusercontent.com/JordanTheJet/zeroclaw-plugins/main/registry.json
```

## How it works

A Lark bot receives events by **webhook**, not by polling, so this plugin never
opens its own listener. The host serves `GET`/`POST` on `/plugin/lark` and hands
each request to the plugin's `parse-webhook`. The plugin:

- **Owns its authenticity check.** Lark stamps the operator-set *verification
  token* into the URL-verification body and into every event's `header.token`.
  The plugin verifies it against the configured `verification_token`; a
  mismatch returns the typed unauthorized rejection (HTTP 401, nothing queued).
- **Answers the verification handshake inline.** On the first
  `{"type":"url_verification","challenge":X,"token":T}` POST it echoes the
  `{"challenge":X}` JSON Lark expects — via the host's reserved
  `__webhook_reply__` convention (200 with that exact body, nothing enqueued).
- **Decodes text messages.** `im.message.receive_v1` text events become inbound
  messages (`reply_target` = `chat_id`; `sender` = `chat_id`, or the sender's
  `open_id` when `per_user_session` is set).

Replies go out through `im/v1/messages`: the plugin exchanges its
`app_id`/`app_secret` for a short-lived `tenant_access_token` (cached, refreshed
automatically on the `99991663` expiry code) and `POST`s a plain **text**
message, chunking long turns. All HTTP goes through the host's `wasi:http`
client (TLS host-side).

Because it is push-only, `poll-message` always returns `none`; the advertised
capabilities are `HEALTH_CHECK | WEBHOOK_INGRESS`.

## Configuration

Settings come from the plugin's config section (requires the `config_read`
permission). Field names mirror the native `LarkConfig`, so a
`[channels.lark.<alias>]` section is fed to the plugin verbatim.

- `app_id` / `app_secret` — from the Lark/Feishu developer console. Required to
  **send** (the `tenant_access_token` exchange); inbound decode works without
  them.
- `verification_token` — webhook verification token. Set it so inbound payloads
  are authenticated; a mismatch is rejected. (Optional, but recommended.)
- `encrypt_key` — **plaintext mode only in v0.1.0.** If encryption is enabled in
  the Lark event-subscription settings, Lark sends `{"encrypt":"…"}` (AES-256-CBC)
  bodies; the plugin detects and cleanly rejects those. Turn encryption **off**
  in the console to use this plugin. Encrypted transport is a planned follow-up.
- `api_base_url` — explicit API origin override (e.g. a test mock). When unset,
  the endpoint is chosen by `use_feishu`.
- `use_feishu` — use the Feishu (China) endpoint (`open.feishu.cn`) instead of
  Lark International (`open.larksuite.com`, the default). Mirrors the native
  field; ignored when `api_base_url` is set.
- `per_user_session` — key group-chat sessions on the sender's `open_id` instead
  of the shared `chat_id`. Mirrors the native field.
- `enabled` and the other native keys (`mention_only`, `receive_mode`, `port`,
  proxy/streaming/reaction tuning, …) are accepted for native-section parity;
  the sandboxed plugin does not act on them.

On a host with the `provides` feature this plugin **mirrors** the built-in
`lark` channel and reads `[channels.lark.<alias>]`; on older hosts it loads as a
novel channel configured from `[[plugins.entries.lark]].config`.

### Webhook setup

Point the bot's **Event Subscription** request URL at your host's
`/plugin/lark` route and complete the URL-verification handshake. Subscribe to
`im.message.receive_v1`. Disable encryption (see `encrypt_key` above).

## Permissions

- `http_client` — outbound calls to the Lark/Feishu Open Platform (TLS
  host-side).
- `config_read` — read the settings above.

## What's covered / limitations

`src/lark.rs` holds the pure logic — config + endpoint resolution, the webhook
dispatch (verification handshake vs. event vs. rejected/encrypted body), the
event → inbound decode, `tenant_access_token` request/response shaping, the
send-body build, and text chunking — with host `cargo test` coverage in its
`#[cfg(test)]` module. `src/lib.rs` is the thin component shim that does the HTTP
via the blocking [`waki`](https://crates.io/crates/waki) `wasi:http` client.

Scope is **text messages, send + receive**. Deferred to follow-ups: encrypted
webhook transport (`encrypt_key`), rich `post`/image/audio/file messages,
interactive cards + Markdown rendering (the native channel renders Markdown via
Card 2.0; this plugin sends plain text), reactions, and approval/choice cards.

## Build

```bash
rustup target add wasm32-wasip2
cargo test --lib                             # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
