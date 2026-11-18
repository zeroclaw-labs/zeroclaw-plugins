# wati — ZeroClaw channel plugin

A WASM (`wasm32-wasip2`) channel plugin mirroring the built-in **WATI**
(WhatsApp Business API) channel.

## Install locally on ZeroClaw v0.9.0

From this plugin directory, build and bind the source-only package:

```sh
cargo build --release --locked --target wasm32-wasip2
mkdir -p target/package
cp manifest.toml target/wasm32-wasip2/release/wati.wasm target/package/
zeroclaw plugin install ./target/package --channel-alias wati --egress declared
zeroclaw plugin info wati
```

Use the channel instance key printed by `zeroclaw plugin info wati`. Store each setting under `plugins.entries.<instance-key>.config`. Set secret fields using `zeroclaw config set plugins.entries.<instance-key>.config.api_token` and enter the value at the prompt.

Enable plugins, route `plugin.wati` to an agent and configure the permitted senders in its peer group. Restart or reload the daemon. Each binding claims the fixed callback path `/plugin/wati`, so use one active binding for that path.

The default API hostname is declared in the manifest. If you change the API origin, grant the new trusted hostname in `plugins.entries.<instance-key>.egress_hosts`.

## How it works

WATI delivers messages by POSTing webhooks, so this is a **webhook** channel, not
a poller. The host serves `GET` + `POST` on `/plugin/wati`:

- **GET** — WATI's verification handshake (`?hub.challenge=…`). The plugin echoes
  the `hub.challenge` back verbatim. This only confirms the callback URL.
- **POST** — a message event. The plugin decodes WATI's variable-shape payload
  (`waId`/`wa_id`/`from`, top-level `text` or `message.text`/`message.body`,
  `fromMe`/`owner`) into inbound text messages.

Replies are sent via `POST <api_url>/api/ext/v3/conversations/messages/text`
(Bearer `api_token`) over the host's `wasi:http`.

## Configuration

- `api_token` — WATI API token (Bearer auth), required to send.
- `api_url` — API base (default `https://live-mt-server.wati.io`).
- `tenant_id` — optional; prefixes the send `target` as `<tenant>:<msisdn>`.

## Security

This adapter does not verify provider signatures on WATI events. Run it behind an ingress that authenticates the WATI source and blocks direct access to the gateway route. A peer group authorizes the claimed sender after ingress and cannot establish where an HTTP request came from. [WATI webhook documentation](https://docs.wati.io/reference/introduction-1)

## Scope / deferrals

- **Text only** (send + receive). Inbound media and WATI's voice-note
  transcription are **not** ported (the native channel downloads media and runs a
  transcription provider host-side; that is out of scope for a text v0.2.0
  plugin). Non-text events yield no message.
- Typing indicators are no-ops (the WATI API has none), matching the native
  channel.

## Build

```bash
cargo test --lib
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```
