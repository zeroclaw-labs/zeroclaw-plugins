# Gitea / Forgejo channel plugin

A ZeroClaw `wasm32-wasip2` **channel** plugin that lets the agent converse
through a [Gitea](https://gitea.io) or [Forgejo](https://forgejo.org) instance's
issue and pull-request **comments**, over the forge's REST API — no webhook, no
inbound network exposure.

It maps inbound comments to the same shape as the built-in `git` channel's
Gitea/Forgejo provider (`sender` = author login,
`reply_target` = `owner/repo#number`, id = `ghc_<comment_id>`, content = the
comment body), so the plugin and the native channel are interchangeable.

## How it works

- **Receive** — polls unread notifications (`GET /notifications`, a short
  request so it never stalls `send`), follows each issue/PR thread's
  `latest_comment_url`, and delivers new comments to the agent. A per-instance
  cursor over the notification `updated_at` time (seeded to "now" at startup, so
  the backlog is ignored) plus a delivered-comment-id dedup set keep each comment
  delivered once.
- **Send** — posts the agent's reply as an issue/PR comment
  (`POST /repos/{owner}/{repo}/issues/{number}/comments`). Replies longer than
  ~60k characters are chunked into several comments.
- **Auth** — every request carries the personal access token as
  `Authorization: token <token>`; TLS is performed host-side by `wasi:http`.

The bot never re-ingests its own comments, ignores other bot accounts (unless
`listen_to_bots`), and — under `mention_only` (the default) — only reacts to
comments that `@`-mention its own login.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info gitea` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install gitea --channel-alias main
# The server is your own, so grant its host yourself:
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJnaXRlYSIsImNoYW5uZWwiLCJtYWluIl0.egress_hosts 'git.example.org'
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry. The manifest declares no hosts, because the server is
the operator's own, so the instance has no network reach until its host is
granted. `zeroclaw plugin bind` binds an already installed package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["gitea","channel","<alias>"]`; for `main` it is:

`zpi1_WyJnaXRlYSIsImNoYW5uZWwiLCJtYWluIl0`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJnaXRlYSIsImNoYW5uZWwiLCJtYWluIl0.config.access_token
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJnaXRlYSIsImNoYW5uZWwiLCJtYWluIl0.config.provider gitea
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJnaXRlYSIsImNoYW5uZWwiLCJtYWluIl0.config.api_base_url https://git.example.org/api/v1
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit the senders it may answer:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.gitea_main]
channel = "plugin.main"
external_peers = ["<sender>"]
```

Restart the daemon. Do not also run the built-in channel with the same
credentials, or both answer.

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.git.<alias>]` or an older `[[plugins.entries]]` record
named `gitea`. Bind an instance and set the values again under its key, the
credentials through the secret prompt.

## Configuration

Set each non-secret value with
`zeroclaw config set --no-interactive plugins.entries.<instance-key>.config.<key> <value>`;
without `--no-interactive` the command prompts for the value instead. Set a
credential without a value, so the command prompts for it without echo.
Strings are written as is; booleans, integers, and lists as JSON text, for
example `'["a","b"]'`. The schema rejects keys it does not list.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `provider` | string, required |  | `gitea` or `forgejo`. The plugin acts only for these providers. |
| `api_base_url` | URL, required |  | Instance API base **including `/api/v1`**, for example `https://git.example.org/api/v1`. The token is only ever sent here. |
| `access_token` | string, secret, required |  | Personal access token with repository read and issue/PR comment write. |
| `mention_only` | boolean | `true` | Deliver only comments that `@`-mention the bot. |
| `listen_to_bots` | boolean | `false` | Also deliver other bots' comments. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Build & test

```sh
rustup target add wasm32-wasip2
cargo test --lib                              # pure-core host tests
cargo build --target wasm32-wasip2 --release  # → target/wasm32-wasip2/release/gitea.wasm
```

## Scope

This release handles **text issue/PR conversation comments** only. Deferred:
inline PR review comments, opening-post bodies that have no comment yet,
reactions, media/attachments, repo enumeration, and per-event routing.
Notification-fetch failures on a tick drop that comment (best-effort delivery).
