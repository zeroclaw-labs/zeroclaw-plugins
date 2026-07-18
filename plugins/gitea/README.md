# Gitea / Forgejo channel plugin

A ZeroClaw `wasm32-wasip2` **channel** plugin that lets the agent converse
through a [Gitea](https://gitea.io) or [Forgejo](https://forgejo.org) instance's
issue and pull-request **comments**, over the forge's REST API — no webhook, no
inbound network exposure.

It mirrors the built-in `git` channel's Gitea/Forgejo provider: it declares
`provides = "git"`, reads the same `[channels.git.<alias>]` section, and maps
inbound comments to the exact same shape (`sender` = author login,
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

## Configuration

As a mirror of the native `git` channel, configure it under
`[channels.git.<alias>]`. The plugin activates only when `provider` is `gitea`
or `forgejo`; a GitHub-provider section is left untouched.

| Field           | Meaning                                                             |
| --------------- | ------------------------------------------------------------------- |
| `provider`      | `"gitea"` or `"forgejo"` (required for this plugin to act)          |
| `api_base_url`  | Instance API base **including `/api/v1`**, e.g. `https://git.example.org/api/v1` |
| `access_token`  | Personal access token (repo read + issue/PR comment write)          |
| `mention_only`  | Only deliver comments that `@`-mention the bot (default `true`)     |
| `listen_to_bots`| Also deliver other bots' comments (default `false`)                 |

There is no default host: the token is only ever sent to the `api_base_url` the
operator names.

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
