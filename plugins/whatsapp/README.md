# whatsapp — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to **WhatsApp** through the official **Meta Graph Cloud
API**. It receives messages as signed webhooks and sends the agent's replies
with `POST /<phone_number_id>/messages` — all from a sandboxed
`wasm32-wasip2` WIT component, with no native build.


## Install locally on ZeroClaw v0.9.0

From this plugin directory, build and bind the source-only package:

```sh
cargo build --release --locked --target wasm32-wasip2
mkdir -p target/package
cp manifest.toml target/wasm32-wasip2/release/whatsapp.wasm target/package/
zeroclaw plugin install ./target/package --channel-alias whatsapp --egress declared
zeroclaw plugin info whatsapp
```

Use the channel instance key printed by `zeroclaw plugin info whatsapp`. Store each setting under `plugins.entries.<instance-key>.config`. Set secret fields using `zeroclaw config set plugins.entries.<instance-key>.config.app_secret` and enter the value at the prompt.

Enable plugins, route `plugin.whatsapp` to an agent and configure the permitted senders in its peer group. Restart or reload the daemon. Each binding claims the fixed callback path `/plugin/whatsapp`, so use one active binding for that path.

The default API hostname is declared in the manifest. If you change the API origin, grant the new trusted hostname in `plugins.entries.<instance-key>.egress_hosts`.

## How it works

WhatsApp Cloud is **push-based**: Meta calls a webhook. This plugin is a
webhook channel — it never polls. The host mounts it at `/plugin/whatsapp` and
serves both:

- **`GET /plugin/whatsapp`** — Meta's one-time verification handshake. Meta
  sends `?hub.mode=subscribe&hub.verify_token=<yours>&hub.challenge=<random>`.
  When the token matches your configured `verify_token`, the plugin echoes the
  `hub.challenge` back verbatim (the host replies `200` with that body).
- **`POST /plugin/whatsapp`** — message events. The plugin verifies the
  `X-Hub-Signature-256` header (`sha256=` + HMAC-SHA256 of the raw body keyed
  with your `app_secret`); a bad or missing signature is rejected with `401`.
  Valid `text` messages become inbound agent turns.

Point your Meta app's webhook (WhatsApp product → Configuration) at
`https://<your-gateway-host>/plugin/whatsapp`, use the same **verify token** you
put in config, and subscribe to the `messages` field.

## Configuration

Set these keys on the bound plugin instance.

| key               | required | meaning                                                                                 |
| ----------------- | :------: | --------------------------------------------------------------------------------------- |
| `access_token`    |   yes    | Graph API access token (Bearer) used to send replies.                                   |
| `phone_number_id` |   yes    | The WhatsApp phone-number ID the send endpoint is scoped to.                            |
| `verify_token`    |   yes    | The token you invent and paste into Meta's webhook setup; echoed during GET verification. |
| `app_secret`      | for POST | Meta **App Secret**, used to verify `X-Hub-Signature-256` on inbound POSTs.  |
| `api_base_url`    |    no    | Override the Graph origin. Default `https://graph.facebook.com/v20.0`.                   |

The binding requires `app_secret` to verify every inbound POST. The GET handshake requires `verify_token`.



## Scope

- **Text only.** Inbound media, reactions, and status updates are skipped;
  outbound is always a `text` message. Media/reactions/threads are deferred.
- Inbound `sender` and `reply_target` are the peer's MSISDN (`from`); outbound
  strips a leading `+` before calling the Graph API.
- Timestamps are converted from WhatsApp's unix-seconds to the WIT
  milliseconds contract.

## Development

The interesting logic (config parse, signature verify, verification handshake,
payload → inbound decode, send-body/URL build) lives in the pure, I/O-free
`whatsapp` core module and is covered by host unit tests:

```bash
cargo test --lib                              # pure core, on the host
cargo build --target wasm32-wasip2 --release  # the component
```
