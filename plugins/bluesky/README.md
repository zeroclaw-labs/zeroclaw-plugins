# bluesky — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to [Bluesky](https://bsky.app) over the AT Protocol. It
polls the account's notifications for incoming **mentions and replies** and
sends the agent's responses back as **threaded posts** — all from a sandboxed
`wasm32-wasip2` WIT component, with no native build.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info bluesky` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install bluesky --channel-alias main --egress declared
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry, and `--egress declared` grants the hosts the manifest
declares: `bsky.social`. `--egress none` binds with no network reach instead,
and `zeroclaw plugin bind` binds an already installed package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["bluesky","channel","<alias>"]`; for `main` it is:

`zpi1_WyJibHVlc2t5IiwiY2hhbm5lbCIsIm1haW4iXQ`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJibHVlc2t5IiwiY2hhbm5lbCIsIm1haW4iXQ.config.app_password
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJibHVlc2t5IiwiY2hhbm5lbCIsIm1haW4iXQ.config.handle mybot.bsky.social
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit the senders it may answer:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.bluesky_main]
channel = "plugin.main"
external_peers = ["<sender>"]
```

Restart the daemon. Do not also run the built-in channel with the same
credentials, or both answer.

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.bluesky.<alias>]` or an older `[[plugins.entries]]`
record named `bluesky`. Bind an instance and set the values again under its key,
the credentials through the secret prompt.

## Configuration

Set each non-secret value with
`zeroclaw config set --no-interactive plugins.entries.<instance-key>.config.<key> <value>`;
without `--no-interactive` the command prompts for the value instead. Set a
credential without a value, so the command prompts for it without echo.
Strings are written as is; booleans, integers, and lists as JSON text, for
example `'["a","b"]'`. The schema rejects keys it does not list.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `handle` | string, required |  | The account handle, for example `mybot.bsky.social`. Sent as the `identifier` to `createSession`. |
| `app_password` | string, secret, required |  | An **app password** from Bluesky Settings → App Passwords, not the account password. |
| `service` | URL | `https://bsky.social` | PDS origin. Override for a self-hosted PDS or a test mock, and grant that host. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Permissions

- `http_client` — outbound XRPC calls to the PDS (TLS is performed host-side).
- `config_read` — read the typed config through `config.get`; the credentials
  arrive only through `secrets.get`.

## What's covered

`src/bluesky.rs` holds the pure AT-Protocol logic — notification → message
mapping (mentions/replies only, unread, self-loop guard), the `createSession` /
`createRecord` / `updateSeen` payload builders, the reply-threading strong-ref
encode/decode, the 300-char post clamp, and dependency-free RFC-3339 ⇄
Unix-millis conversion — with host `cargo test` coverage in `tests/`.
`src/lib.rs` is the thin component shim that does the HTTP via the blocking
[`waki`](https://crates.io/crates/waki) `wasi:http` client, caches the session
JWT (re-authenticating on a 401), and tracks the notification cursor.

Text posts are supported today; media embeds, rich facets (link/mention
cards), and interactive approvals are future work.

## Build

```bash
rustup target add wasm32-wasip2
cargo test                                   # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
