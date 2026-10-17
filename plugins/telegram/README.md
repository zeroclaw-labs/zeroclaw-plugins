# telegram — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to Telegram. It long-polls the Bot API for incoming
messages and sends the agent's replies back — all from a sandboxed
`wasm32-wasip2` WIT component, with no native build.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info telegram` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install telegram --channel-alias main --egress declared
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry, and `--egress declared` grants the hosts the manifest
declares: `api.telegram.org`. `--egress none` binds with no network reach
instead, and `zeroclaw plugin bind` binds an already installed package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["telegram","channel","<alias>"]`; for `main` it is:

`zpi1_WyJ0ZWxlZ3JhbSIsImNoYW5uZWwiLCJtYWluIl0`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJ0ZWxlZ3JhbSIsImNoYW5uZWwiLCJtYWluIl0.config.bot_token
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit the senders it may answer:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.telegram_main]
channel = "plugin.main"
external_peers = ["<sender>"]
```

Restart the daemon. Do not also run the built-in channel with the same
credentials, or both answer.

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.telegram.<alias>]` or an older `[[plugins.entries]]`
record named `telegram`. Bind an instance and set the values again under its
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
| `bot_token` | string, secret, required |  | The token from [@BotFather](https://t.me/BotFather). |
| `api_base_url` | URL | `https://api.telegram.org` | API origin. Override for a self-hosted Bot API server or a test mock, and grant that host. |
| `parse_mode` | string | plain text | Telegram `parse_mode` (`HTML`, `MarkdownV2`, …). |
| `allowed_users` | list of strings | no plugin-level gating | Usernames or numeric ids. `["*"]` allows anyone. Matching strips a leading `@` and ignores case. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Permissions

- `http_client` — outbound calls to the Bot API (TLS is performed host-side).
- `config_read` — read the typed config through `config.get`; the credentials
  arrive only through `secrets.get`.

## What's covered

`src/telegram.rs` holds the pure Bot-API logic (update → message mapping,
`sendMessage` payload building, allow-list, chunking) with host `cargo test`
coverage in `tests/`. `src/lib.rs` is the thin component shim that does the
HTTP via the blocking [`waki`](https://crates.io/crates/waki) `wasi:http`
client.

Text messages are supported today; rich formatting, media, and inline-keyboard
approvals are future work.

## Build

```bash
rustup target add wasm32-wasip2
cargo test                                   # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
