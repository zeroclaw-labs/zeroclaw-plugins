# webhook — ZeroClaw channel plugin

A WASM (`wasm32-wasip2`) channel plugin mirroring the built-in generic
**webhook** channel — the "universal adapter" for any system that speaks HTTP.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info webhook` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install webhook --channel-alias main
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry. `zeroclaw plugin bind` binds an already installed
package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["webhook","channel","<alias>"]`.

Set the public settings and the credentials, then enable the plugin system:

```bash
# Public settings (typed through config.get).
zeroclaw config set --no-interactive plugins.entries.<instance-key>.config.send_url https://example.com/callback
zeroclaw config set --no-interactive plugins.entries.<instance-key>.config.send_method POST
# Credentials (each secret prompts without echo and is stored encrypted).
zeroclaw config set plugins.entries.<instance-key>.config.secret
zeroclaw config set plugins.entries.<instance-key>.config.auth_header
zeroclaw config set plugins.enabled true
```

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.webhook.<alias>]` or an older `[[plugins.entries]]`
record named `webhook`. Bind an instance and set the values again under its key,
the credentials through the secret prompt.

## Configuration

Set each non-secret value with
`zeroclaw config set --no-interactive plugins.entries.<instance-key>.config.<key> <value>`;
without `--no-interactive` the command prompts for the value instead. Set a
credential without a value, so the command prompts for it without echo.
The schema rejects keys it does not list.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `send_url` | string |  | Outbound reply endpoint (optional; no-op when unset). |
| `send_method` | string | `POST` | `POST` or `PUT`. |
| `auth_header` | string, required as secret |  | `Authorization` header value for outbound (via `secrets.get`). |
| `secret` | string, required as secret |  | HMAC-SHA256 signing secret for inbound verification (via `secrets.get`). |

## How it works

The host serves `POST /plugin/webhook`. On each request the plugin:

1. **Verifies** the signature when a `secret` is configured: the request must
   carry `X-Webhook-Signature: [sha256=]<hex(HMAC-SHA256(secret, body))>`. A bad
   or missing signature is rejected with `401`. When no secret is set, all inbound
   is accepted (matching the native channel).
2. **Decodes** the JSON body `{sender, content, thread_id?}` into an inbound
   message. Empty `content` (or invalid JSON) is a `400`. `reply_target` is the
   `thread_id` when present, else the `sender`.

Replies are sent to `send_url` as `{content, thread_id?, recipient?}` via `POST`
(or `PUT` when `send_method = "PUT"`), with the `auth_header` secret sent
as `Authorization` when set. When `send_url` is unset, outbound is a no-op.

The native `port` / `listen_path` fields are **ignored**: as a plugin, inbound
arrives on the host's `/plugin/webhook` route (the host owns the listener), not a
private port. They are accepted for config compatibility.

## Scope / deferrals

- **Text only.** No attachments.
- No sender allowlist in the plugin; the host gates senders via `peer_groups`.
- **Outbound retry/backoff is deferred.** The native channel retries transient
  failures (429/5xx, `Retry-After`, exponential backoff with jitter). This plugin
  performs a **single** outbound attempt and returns `Err` on a non-2xx, letting
  the host's own send-error handling take over. Signature verification and the
  inbound/outbound payload shapes are fully faithful.

## Build

```bash
cargo test --lib
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```
