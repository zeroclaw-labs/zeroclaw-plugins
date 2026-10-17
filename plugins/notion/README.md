# notion — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
turns a Notion database into an agent task queue. It polls the database for rows
whose status is `pending`, hands each row's input to the agent, and writes the
agent's answer back into a result property while flipping the row to `done` —
all from a sandboxed `wasm32-wasip2` WIT component, with no native build.

Unlike the chat channels, Notion is a **task queue**: inbound "messages" are
pending rows and an outbound reply is a page update, not a chat post.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info notion` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install notion --channel-alias main --egress declared
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry, and `--egress declared` grants the hosts the manifest
declares: `api.notion.com`. `--egress none` binds with no network reach instead,
and `zeroclaw plugin bind` binds an already installed package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["notion","channel","<alias>"]`; for `main` it is:

`zpi1_WyJub3Rpb24iLCJjaGFubmVsIiwibWFpbiJd`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJub3Rpb24iLCJjaGFubmVsIiwibWFpbiJd.config.api_key
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJub3Rpb24iLCJjaGFubmVsIiwibWFpbiJd.config.database_id YOUR_DATABASE_ID
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit the senders it may answer:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.notion_main]
channel = "plugin.main"
external_peers = ["<sender>"]
```

Restart the daemon.

Upgrading from an earlier version: this version reads only its instance's config
entry, never an older `[[plugins.entries]]` record named `notion`. Bind an
instance and set the values again under its key, the credentials through the
secret prompt.

## Configuration

Set each non-secret value with
`zeroclaw config set --no-interactive plugins.entries.<instance-key>.config.<key> <value>`;
without `--no-interactive` the command prompts for the value instead. Set a
credential without a value, so the command prompts for it without echo.
Strings are written as is; booleans, integers, and lists as JSON text, for
example `'["a","b"]'`. The schema rejects keys it does not list.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `api_key` | string, secret, required |  | A Notion internal-integration token, sent as `Authorization: Bearer`. |
| `database_id` | string, required |  | The database whose rows form the queue. Share the integration with this database. |
| `status_property` | string | `Status` | The `select` or `status` property that holds the task state (`pending`, `running`, `done`). The plugin detects which kind it is. |
| `input_property` | string | `Input` | The `title` or `rich_text` property that holds the task prompt. |
| `result_property` | string | `Result` | The `rich_text` property the answer is written back into. |
| `poll_interval_secs` | integer | `5` | Poll cadence in seconds. |
| `max_concurrent` | integer | `4` | Most rows claimed (flipped to `running`) per poll. |
| `recover_stale` | boolean | `true` | On load, reset rows a crash left in `running` back to `pending`. |
| `api_base_url` | URL | `https://api.notion.com` | API origin. Override for a test mock, and grant that host. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Permissions

- `http_client` — outbound calls to `api.notion.com` (TLS is performed
  host-side).
- `config_read` — read the typed config through `config.get`; the credentials
  arrive only through `secrets.get`.

## Endpoints

- Poll: `POST https://api.notion.com/v1/databases/{database_id}/query` with a
  filter on the status property equal to `pending`.
- Schema probe: `GET https://api.notion.com/v1/databases/{database_id}` (to
  detect `select` vs `status`).
- Claim / complete / recover: `PATCH https://api.notion.com/v1/pages/{page_id}`
  (status → `running`, then result + status → `done`; recovery → `pending`).

All requests carry `Authorization: Bearer <api_key>` and
`Notion-Version: 2022-06-28`.

## What's covered

`src/notion.rs` holds the pure logic (config parsing, schema probing,
pending-row → inbound mapping, and the query/claim/complete/recover payloads)
with host `cargo test` coverage in `tests/`. `src/lib.rs` is the thin component
shim that does the HTTP via the blocking
[`waki`](https://crates.io/crates/waki) `wasi:http` client.

## Build

```bash
rustup target add wasm32-wasip2
cargo test                                   # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
