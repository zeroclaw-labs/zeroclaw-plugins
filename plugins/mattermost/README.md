# mattermost — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to Mattermost. It polls a channel's posts via the v4 REST
API and sends the agent's replies back — all from a sandboxed `wasm32-wasip2`
WIT component, with no native build.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info mattermost` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install mattermost --channel-alias main
# The server is your own, so grant its host yourself:
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJtYXR0ZXJtb3N0IiwiY2hhbm5lbCIsIm1haW4iXQ.egress_hosts 'mattermost.example.com'
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry. The manifest declares no hosts, because the server is
the operator's own, so the instance has no network reach until its host is
granted. `zeroclaw plugin bind` binds an already installed package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["mattermost","channel","<alias>"]`; for `main` it is:

`zpi1_WyJtYXR0ZXJtb3N0IiwiY2hhbm5lbCIsIm1haW4iXQ`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJtYXR0ZXJtb3N0IiwiY2hhbm5lbCIsIm1haW4iXQ.config.bot_token
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJtYXR0ZXJtb3N0IiwiY2hhbm5lbCIsIm1haW4iXQ.config.url https://mattermost.example.com
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJtYXR0ZXJtb3N0IiwiY2hhbm5lbCIsIm1haW4iXQ.config.channel_ids '["YOUR_CHANNEL_ID"]'
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit the senders it may answer:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.mattermost_main]
channel = "plugin.main"
external_peers = ["<sender>"]
```

Restart the daemon. Do not also run the built-in channel with the same
credentials, or both answer.

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.mattermost.<alias>]` or an older `[[plugins.entries]]`
record named `mattermost`. Bind an instance and set the values again under its
key, the credentials through the secret prompt.

## Configuration

Set each non-secret value with
`zeroclaw config set --no-interactive plugins.entries.<instance-key>.config.<key> <value>`;
without `--no-interactive` the command prompts for the value instead. Set a
credential without a value, so the command prompts for it without echo.
Strings are written as is; booleans, integers, and lists as JSON text, for
example `'["a","b"]'`. The schema rejects keys it does not list.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `url` | URL, required |  | The server origin, for example `https://mattermost.example.com`. A trailing slash is trimmed. |
| `bot_token` | string, secret, required |  | A personal access or bot token, sent as `Authorization: Bearer <token>`. |
| `channel_ids` | list of strings | none (inert) | The channel the bot serves: this release uses the first explicit entry. An empty list or `["*"]` leaves the plugin inert. |
| `thread_replies` | boolean | `true` | Thread top-level replies on the original post; `false` replies at the channel root. Existing threads always stay threaded. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Permissions

- `http_client` — outbound calls to the Mattermost REST API (TLS is performed
  host-side).
- `config_read` — read the typed config through `config.get`; the credentials
  arrive only through `secrets.get`.

## What's covered

`src/mattermost.rs` holds the pure v4 REST logic (post → message mapping,
`createPost` body building, self-identity parsing, reply-target routing, config
parsing) with host `cargo test` coverage in `tests/`. `src/lib.rs` is the thin
component shim that does the HTTP via the blocking
[`waki`](https://crates.io/crates/waki) `wasi:http` client.

Inbound polling drains an internal buffer first, then makes one short
`GET /channels/{id}/posts?since=<create_at_ms>` request, maps each new post
(skipping the bot's own posts and empty bodies), advances the cursor to the max
`create_at`, and returns one message at a time. Text messages are supported
today; attachments, transcription, `mention_only` gating, and multi-channel /
auto-discovery are future work.

## Build

```bash
rustup target add wasm32-wasip2
cargo test                                   # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
