# nextcloud — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to [Nextcloud Talk](https://nextcloud.com/talk/) as a Talk
**bot**. It receives messages over the Talk bot **webhook** (HMAC-verified) and
sends the agent's replies back through the OCS chat API — all from a sandboxed
`wasm32-wasip2` WIT component, with no native build.

```bash
zeroclaw plugin install nextcloud \
  --registry https://raw.githubusercontent.com/JordanTheJet/zeroclaw-plugins/main/registry.json
```

## How it works

Nextcloud Talk delivers each message to a registered bot by `POST`-ing an
[Activity Streams 2.0](https://www.w3.org/TR/activitystreams-core/) `Create`
event to the bot's webhook URL. A channel plugin can't open a listener inside
the WASI sandbox, so the host mounts this plugin's route at **`/plugin/nextcloud`**
(from the exported `webhook-path`) and hands each raw `POST` to `parse-webhook`.

The plugin **owns its authenticity check**. Talk signs each request as:

```text
X-Nextcloud-Talk-Signature = hex( HMAC-SHA256( secret, X-Nextcloud-Talk-Random ++ raw_body ) )
```

`parse-webhook` recomputes that over the exact received bytes using the
configured `webhook_secret` and rejects a mismatch by returning `err(...)`, which
makes the gateway reply `401`/`400` and enqueue nothing (constant-time compare).
It then decodes the payload into an inbound message:

- **sender** = `actor.id` with the `users/` / `bots/` prefix stripped,
- **reply target** = `target.id` (the conversation token),
- **content** = the `message` field decoded from the JSON-encoded `object.content`.

Bot-authored events (`actor.type = "Application"`, a `bots/` id prefix, or a name
matching your `bot_name`/the built-in `zeroclaw`) are dropped to prevent feedback
loops. This is a webhook channel, so `poll-message` always returns nothing.

Replies are sent with:

```text
POST {base_url}/ocs/v2.php/apps/spreed/api/v1/chat/{token}?format=json
Authorization: Bearer <app_token>
OCS-APIRequest: true
Accept: application/json

{"message": "<reply text>"}
```

Text longer than 32 000 characters (the OCS limit) is truncated on a character
boundary.

## Configuration

Config comes from the plugin's own section (requires the `config_read`
permission). Field names match the built-in `nextcloud` channel, so a mirror
install reads `[channels.nextcloud_talk.<alias>]` directly. Fields used by this
plugin:

- `base_url` (required) — the Nextcloud origin, e.g.
  `https://cloud.example.com`. A trailing slash is trimmed.
- `app_token` (required for sending) — the bot app token, sent as
  `Authorization: Bearer <app_token>` on OCS calls.
- `webhook_secret` — the Talk bot shared secret used to verify inbound webhook
  signatures. **When set, unsigned or mis-signed requests are rejected. When
  empty, webhooks are accepted unsigned** (mirroring the built-in channel, which
  only verifies when a secret is configured). Setting it is strongly recommended.
- `bot_name` — the bot's display name, used to drop the bot's own messages.

Point your Talk bot's webhook at `https://<your-gateway>/plugin/nextcloud`.

## Scope (v0.1.0)

Text messages, send + receive. Deferred for now:

- **Media / attachments, reactions, message edits (draft streaming), pins,
  redactions** — stubbed to the WIT defaults.
- **User allowlist / authorization** — the built-in channel filters inbound
  actors against the host's peer groups (`external_peers`), which live outside
  this channel's config section; the plugin emits every non-bot message and
  leaves authorization to the host.
- **Legacy `type: "message"` payloads** are also decoded (in addition to the
  real AS2 `Create` format), but only the comment/chat shape.

## Development

```bash
# Pure core (host) — no wasm, no network:
cargo test --lib
cargo test

# Component build:
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

The interesting logic (config parse, signature verify, payload decode, send-body
build, truncation) is pure and lives in `src/nextcloud.rs`; `src/lib.rs` is the
thin `wasm32-wasip2` shim that wires it to the `channel-plugin` WIT world with
the blocking `waki` HTTP client.
