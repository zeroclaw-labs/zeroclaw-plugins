# gmail_push — ZeroClaw channel plugin

A WASM (`wasm32-wasip2`) channel plugin mirroring the built-in **Gmail Pub/Sub
push** channel.

## Install locally on ZeroClaw v0.9.0

From this plugin directory, build and bind the source-only package:

```sh
cargo build --release --locked --target wasm32-wasip2
mkdir -p target/package
cp manifest.toml target/wasm32-wasip2/release/gmail_push.wasm target/package/
zeroclaw plugin install ./target/package --channel-alias gmail_push --egress declared
zeroclaw plugin info gmail_push
```

Use the channel instance key printed by `zeroclaw plugin info gmail_push`. Store each setting under `plugins.entries.<instance-key>.config`. Set secret fields using `zeroclaw config set plugins.entries.<instance-key>.config.webhook_secret` and enter the value at the prompt.

Enable plugins, route `plugin.gmail_push` to an agent and configure the permitted senders in its peer group. Restart or reload the daemon. Each binding claims the fixed callback path `/plugin/gmail_push`, so use one active binding for that path.

## How it works

Gmail delivers change notifications via Google Cloud **Pub/Sub push** (an
HTTP `POST`), so this is a **webhook** channel, not a poller. The host serves
`POST /plugin/gmail_push`. On each notification the plugin:

1. Authenticates the request using the configured `webhook_secret` in its Bearer header. Configure a trusted HTTPS ingress to verify Pub/Sub’s signed OIDC JWT (issuer, audience and service account), replace the incoming authorization header with the shared secret and block direct access to the plugin route. [Google Pub/Sub authentication](https://docs.cloud.google.com/pubsub/docs/authenticate-push-subscriptions)
2. **Decodes** the Pub/Sub envelope. The base64 `message.data` decodes to
   `{emailAddress, historyId}` — the push carries **only a `historyId`, never the
   message body**.
3. **Fetches** the actual messages: it calls the Gmail **History** API since the
   last-seen `historyId`, then **`messages.get`** for each new message, using the
   configured `oauth_token`. The From/Subject/plain-text-body are returned as
   inbound messages (`content` = `"Subject: …\n\n<body>"`).

The **first** notification only records the `historyId` and returns nothing (it
establishes the cursor), matching the native channel. The `historyId` cursor is
stored in binding-scoped durable state with compare-and-swap revisions. Use a separate binding when switching mailboxes.

Replies are sent via the Gmail `messages.send` API (RFC 2822 message, URL-safe
base64), with CRLF-sanitized headers.

## Configuration

- `oauth_token` — Gmail API OAuth bearer (required to fetch + send).
- `topic` — Pub/Sub topic for `users.watch` registration.
- `label_filter` — Gmail labels to watch (default `["INBOX"]`).
- `webhook_secret` — required ingress shared secret for the inbound `Authorization`
  header.
- `webhook_url` — informational (the push subscription's endpoint).

## Watch registration and renewal

With `oauth_token` and `topic` configured, the running listener registers a Gmail watch and renews it daily. A failed registration is retried after five minutes. To manage registration outside ZeroClaw, leave `topic` unset. An authenticated Pub/Sub push subscription is required in both cases.

## Security / scope

- No sender allowlist is applied in the plugin; the host gates senders via
  `peer_groups`.
- **Text only.** Attachments are ignored; the plain-text body (or HTML-stripped
  `text/html`, or the snippet) is used. Deferred: attachments, threading beyond
  `thread_ts`, richer MIME.
- The History + `messages.get` orchestration runs inside `parse_webhook` over
  `wasi:http`; on a transient fetch failure the plugin returns `Err`, so Pub/Sub
  redelivers (the `historyId` cursor is only advanced on success).

## Build

```bash
cargo test --lib
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```
