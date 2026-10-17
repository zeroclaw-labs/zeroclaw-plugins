# twitter — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to X/Twitter. It polls the API v2 mentions timeline for
incoming mentions and posts the agent's replies back — all from a sandboxed
`wasm32-wasip2` WIT component, with no native build.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info twitter` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install twitter --channel-alias main --egress declared
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry, and `--egress declared` grants the hosts the manifest
declares: `api.x.com`. `--egress none` binds with no network reach instead, and
`zeroclaw plugin bind` binds an already installed package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["twitter","channel","<alias>"]`; for `main` it is:

`zpi1_WyJ0d2l0dGVyIiwiY2hhbm5lbCIsIm1haW4iXQ`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJ0d2l0dGVyIiwiY2hhbm5lbCIsIm1haW4iXQ.config.bearer_token
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit the senders it may answer:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.twitter_main]
channel = "plugin.main"
external_peers = ["<sender>"]
```

Restart the daemon. Do not also run the built-in channel with the same
credentials, or both answer.

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.twitter.<alias>]` or an older `[[plugins.entries]]`
record named `twitter`. Bind an instance and set the values again under its key,
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
| `bearer_token` | string, secret, required |  | The X API v2 OAuth 2.0 Bearer Token. |
| `api_base_url` | URL | `https://api.x.com/2` | API origin. Override for a test mock, and grant that host. |
| `allowed_users` | list of strings | no plugin-level gating | Author ids or usernames. `["*"]` allows anyone. Matching strips a leading `@` and ignores case. |
| `enabled` | boolean |  | Accepted for compatibility; the plugin does not act on it. |
| `excluded_tools` | list of strings |  | Accepted for compatibility; the plugin does not act on it. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Permissions

- `http_client` — outbound calls to `api.x.com` (TLS is performed host-side).
- `config_read` — read the typed config through `config.get`; the credentials
  arrive only through `secrets.get`.

## Endpoints

- `GET /2/users/me` — resolve + cache the bot's own user id and `@handle`.
- `GET /2/users/{id}/mentions?tweet.fields=author_id,created_at` — short poll for
  new mentions, paginating with `since_id` from the previous batch's
  `meta.newest_id`.
- `POST /2/tweets` — reply with `{ text, reply: { in_reply_to_tweet_id } }`;
  long replies thread as a self-reply chain (280-char tweets).

All requests carry `Authorization: Bearer {bearer_token}`.

## What's covered

`src/twitter.rs` holds the pure API-v2 logic (mention → message mapping, poll
URL + cursor advance, `POST /tweets` payload building, allow-list, 280-char
chunking) with host `cargo test` coverage in `tests/`. `src/lib.rs` is the thin
component shim that does the HTTP via the blocking
[`waki`](https://crates.io/crates/waki) `wasi:http` client.

Text mentions and reply tweets are supported today; DMs, media, and reactions
are future work. The mentions endpoint is heavily rate-limited, so each
`poll_message` issues a single short request rather than a long-poll.

## Build

```bash
rustup target add wasm32-wasip2
cargo test                                   # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
