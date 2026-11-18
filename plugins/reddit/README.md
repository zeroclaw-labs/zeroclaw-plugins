# reddit — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to Reddit as an OAuth2 bot. It long-polls the inbox for
unread mentions, DMs, and comment replies and posts the agent's replies back —
all from a sandboxed `wasm32-wasip2` WIT component, with no native build.

## How it works

- **Auth** — `POST https://www.reddit.com/api/v1/access_token` with HTTP Basic
  (`client_id:client_secret`) and `grant_type=refresh_token`. The access token is
  cached and re-fetched on a `401`.
- **Inbound** — `GET https://oauth.reddit.com/message/unread?limit=25`. Each
  unread item is mapped to an inbound message (`id = reddit_<fullname>`,
  `sender = author`, `content = body`); the batch is then acknowledged with
  `POST /api/read_message` so items are never re-delivered.
- **Outbound** — a fullname recipient (`t1_`/`t3_`/`t4_`) is a threaded comment
  reply via `POST /api/comment` (`thing_id`, `text`); any other recipient is a DM
  via `POST /api/compose` (`to`, `subject`, `text`).

Every request carries the required `User-Agent`. A single short poll per
`poll_message` keeps the client within Reddit's 60 requests/minute cap.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info reddit` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install reddit --channel-alias main --egress declared
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry, and `--egress declared` grants the hosts the manifest
declares: `oauth.reddit.com`, `www.reddit.com`. `--egress none` binds with no
network reach instead, and `zeroclaw plugin bind` binds an already installed
package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["reddit","channel","<alias>"]`; for `main` it is:

`zpi1_WyJyZWRkaXQiLCJjaGFubmVsIiwibWFpbiJd`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJyZWRkaXQiLCJjaGFubmVsIiwibWFpbiJd.config.client_secret
zeroclaw config set plugins.entries.zpi1_WyJyZWRkaXQiLCJjaGFubmVsIiwibWFpbiJd.config.refresh_token
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJyZWRkaXQiLCJjaGFubmVsIiwibWFpbiJd.config.client_id YOUR_CLIENT_ID
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJyZWRkaXQiLCJjaGFubmVsIiwibWFpbiJd.config.username YOUR_BOT_USERNAME
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit the senders it may answer:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.reddit_main]
channel = "plugin.main"
external_peers = ["<sender>"]
```

Restart the daemon. Do not also run the built-in channel with the same
credentials, or both answer.

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.reddit.<alias>]` or an older `[[plugins.entries]]`
record named `reddit`. Bind an instance and set the values again under its key,
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
| `client_id` | string, required |  | Reddit OAuth2 app client id. |
| `client_secret` | string, secret, required |  | Reddit OAuth2 app client secret, sent with `client_id` as HTTP Basic auth to the token endpoint. |
| `refresh_token` | string, secret, required |  | OAuth2 refresh token. It is exchanged for a short-lived access token, which is cached and refreshed on a `401`. |
| `username` | string, required |  | The bot's username without `u/`, used for the self-loop guard and as the bot's handle. |
| `subreddits` | list of strings | any | Allow-list without `r/`. Direct messages always pass. Matching ignores case. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Permissions

- `http_client` — outbound calls to `oauth.reddit.com` and `www.reddit.com` (TLS
  is performed host-side).
- `config_read` — read the typed config through `config.get`; the credentials
  arrive only through `secrets.get`.

## What's covered

`src/reddit.rs` holds the pure OAuth2/REST logic (inbox item → message mapping,
subreddit allow-list, recipient classification, base64/HTTP-Basic header, token
parsing) with host `cargo test` coverage in `tests/`. `src/lib.rs` is the thin
component shim that does the HTTP via the blocking
[`waki`](https://crates.io/crates/waki) `wasi:http` client.

Text comments and DMs are supported today; media and rich formatting are future
work.

## Build

```bash
rustup target add wasm32-wasip2
cargo test                                   # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
