# mochat — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to a self-hosted [Mochat](https://mochat.io) customer-service
server. It polls the Mochat REST API for incoming messages and sends the agent's
replies back — all from a sandboxed `wasm32-wasip2` WIT component, with no native
build.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info mochat` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install mochat --channel-alias main
# The server is your own, so grant its host yourself:
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJtb2NoYXQiLCJjaGFubmVsIiwibWFpbiJd.egress_hosts 'mochat.example.com'
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry. The manifest declares no hosts, because the server is
the operator's own, so the instance has no network reach until its host is
granted. `zeroclaw plugin bind` binds an already installed package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["mochat","channel","<alias>"]`; for `main` it is:

`zpi1_WyJtb2NoYXQiLCJjaGFubmVsIiwibWFpbiJd`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJtb2NoYXQiLCJjaGFubmVsIiwibWFpbiJd.config.api_token
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJtb2NoYXQiLCJjaGFubmVsIiwibWFpbiJd.config.api_url https://mochat.example.com
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit the senders it may answer:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.mochat_main]
channel = "plugin.main"
external_peers = ["<sender>"]
```

Restart the daemon. Do not also run the built-in channel with the same
credentials, or both answer.

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.mochat.<alias>]` or an older `[[plugins.entries]]`
record named `mochat`. Bind an instance and set the values again under its key,
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
| `api_url` | URL, required |  | Base URL of your self-hosted Mochat server. A trailing slash is trimmed. |
| `api_token` | string, secret, required |  | API token, sent as `Authorization: Bearer <token>`. |
| `poll_interval_secs` | integer | `5` | Receive-poll interval in seconds. |
| `enabled` | boolean |  | Accepted for compatibility; the plugin does not act on it. |
| `excluded_tools` | list of strings |  | Accepted for compatibility; the plugin does not act on it. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Endpoints

All relative to the configured `api_url`, matching the native channel:

- `GET  /api/message/receive[?since_id=<id>]` — poll for new messages.
- `POST /api/message/send` — send a text reply
  (`{ "toUserId", "msgType": "text", "content": { "text" } }`).
- `GET  /api/health` — reachability probe for `health_check`.

Inbound messages map `fromUserId`/`sender` → sender, `content.text` (or a bare
`content` string) → text, and `messageId`/`id` → the dedup + `since_id` cursor.

## Permissions

- `http_client` — outbound calls to your Mochat server (TLS is performed
  host-side).
- `config_read` — read the typed config through `config.get`; the credentials
  arrive only through `secrets.get`.

## What's covered

`src/mochat.rs` holds the pure REST logic (message → inbound mapping, send-body
building, response-code checks, URL building, dedup) with host `cargo test`
coverage in `tests/`. `src/lib.rs` is the thin component shim that does the HTTP
via the blocking [`waki`](https://crates.io/crates/waki) `wasi:http` client.

Text messages are supported today; media and typing indicators are future work
(the Mochat REST API exposes no typing endpoint).

## Build

```bash
rustup target add wasm32-wasip2
cargo test                                   # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
