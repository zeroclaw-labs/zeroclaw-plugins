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

Google Cloud Pub/Sub sends Gmail change notifications to `POST /plugin/gmail_push`.
The webhook and the supervised listener share a durable cursor.

1. Authenticates the request using the configured `webhook_secret` in its Bearer header. Configure a trusted HTTPS ingress to verify Pub/Sub’s signed OIDC JWT (issuer, audience and service account), replace the incoming authorization header with the shared secret and block direct access to the plugin route. [Google Pub/Sub authentication](https://docs.cloud.google.com/pubsub/docs/authenticate-push-subscriptions)
2. **Decodes** the Pub/Sub envelope. The base64 `message.data` decodes to
   `{emailAddress, historyId}` — the push carries **only a `historyId`, never the
   message body**.
3. **Persists the highest notification ID** for this binding before acknowledging the push. The first notification establishes a starting point. Repeated or out-of-order notifications cannot move it backwards.
4. **Delivers mail through the running listener.** The listener queries Gmail history in increasing order and fetches each added message. It hands the From, Subject and plain-text body to the host. A notification can arrive while an earlier record is still waiting for delivery.

The instance records both the newest announced change and the last history record handed to the host. It advances the delivery position on the next poll after handing off the record's messages. A restart can replay the last unfinished record, using the same Gmail message IDs. Use a separate binding when switching mailboxes.

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
- Gmail read failures leave the delivery position intact. The listener retries after five seconds. A message deleted before `messages.get` is skipped. If Gmail reports that the starting history ID has expired, reconcile the mailbox before seeding a fresh binding. [Gmail history recovery](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.history/list)

## Build

```bash
cargo test --lib
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```
