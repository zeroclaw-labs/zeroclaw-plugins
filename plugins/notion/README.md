# notion — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
turns a Notion database into an agent task queue. It polls the database for rows
whose status is `pending`, hands each row's input to the agent, and writes the
agent's answer back into a result property while flipping the row to `done` —
all from a sandboxed `wasm32-wasip2` WIT component, with no native build.

Unlike the chat channels, Notion is a **task queue**: inbound "messages" are
pending rows and an outbound reply is a page update, not a chat post.

```bash
zeroclaw plugin install notion \
  --registry https://raw.githubusercontent.com/JordanTheJet/zeroclaw-plugins/main/registry.json
```

## Configuration

The token and settings come from the `[[plugins.entries]]` record named
`notion` (requires the `config_read` permission). Fields are snake_case:

- `api_key` (required) — a Notion internal-integration token. Sent as
  `Authorization: Bearer`.
- `database_id` (required) — the database whose rows form the queue. The
  integration must be shared with this database.
- `status_property` — name of the `select`/`status` property holding the task
  state (`pending` / `running` / `done`). Default `Status`. The plugin probes
  the database schema to detect whether it is a `select` or `status` property
  and adapts its filters and updates accordingly.
- `input_property` — name of the `title`/`rich_text` property holding the task
  prompt. Default `Input`.
- `result_property` — name of the `rich_text` property the answer is written
  back into. Default `Result`.
- `poll_interval_secs` — poll cadence in seconds. Default `5`.
- `max_concurrent` — maximum rows claimed (flipped to `running`) per poll tick.
  Default `4`.
- `recover_stale` — on load, reset rows stranded in `running` by a prior crash
  back to `pending`. Default `true`.
Notion is a novel channel because current ZeroClaw has no canonical
`channels.notion` config family. Configure it under
`[[plugins.entries]].config` and bind `plugin.notion` to the owning agent; the
package intentionally omits `provides` so the host does not reject it as an
unknown mirror.

## Permissions

- `http_client` — outbound calls to `api.notion.com` (TLS is performed
  host-side).
- `config_read` — read the token, database id, and property names above.

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
