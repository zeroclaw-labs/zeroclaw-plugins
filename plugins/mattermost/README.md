# mattermost — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to Mattermost. It polls a channel's posts via the v4 REST
API and sends the agent's replies back — all from a sandboxed `wasm32-wasip2`
WIT component, with no native build.

```bash
zeroclaw plugin install mattermost \
  --registry https://raw.githubusercontent.com/JordanTheJet/zeroclaw-plugins/main/registry.json
```

## Configuration

The server URL, token, and channel come from the plugin's config section
(requires the `config_read` permission). Field names match the built-in
`mattermost` channel so a mirror install reads `[channels.mattermost.<alias>]`
directly. Fields used by this plugin:

- `url` (required) — the Mattermost server origin, e.g.
  `https://mattermost.example.com`. A trailing slash is trimmed.
- `bot_token` (required) — a personal access / bot token, sent as
  `Authorization: Bearer <token>`. (The native `login_id` + `password` login
  flow is not implemented here; use a static token.)
- `channel_ids` — the channel(s) the bot serves. **This release operates on a single
  channel: the first explicit entry.** An empty list or a `["*"]` wildcard
  (native auto-discovery) leaves the plugin inert.
- `thread_replies` — when `true` (default), top-level replies thread on the
  original post; when `false`, they go to the channel root. Existing threads
  always stay threaded.

Other native fields (`login_id`, `password`, `team_ids`, `discover_dms`,
`mention_only`, pacing, …) are accepted and ignored.

On a host with the `provides` feature this plugin **mirrors** the built-in
`mattermost` channel and reads `[channels.mattermost.<alias>]`; on older hosts
it loads as a novel channel configured from `[[plugins.entries.mattermost]]`.

## Permissions

- `http_client` — outbound calls to the Mattermost REST API (TLS is performed
  host-side).
- `config_read` — read the server URL, token, and channel above.

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
