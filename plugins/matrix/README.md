# Matrix text-only channel plugin

Matrix 0.3.0 binds `wit/v0`, the plugin contract first released in ZeroClaw v0.8.6, with `plugins-wit-v0`. It needs ZeroClaw v0.8.6 or later; earlier hosts refuse it. Matrix 0.1.0 and 0.2.0 do not install on v0.8.6 and are withdrawn from the registry through `registry-retirements.json`; their release assets remain.

The interface is still experimental and unfrozen: a later contract change in `wit/v0` requires a new Matrix version, and published versions are never rebuilt.

Use an explicit `channels.plugin.<alias>` instance with this package and the host's supported plugin configuration surface. `provides = "matrix"` describes the channel; it does not activate a native mirror or read `channels.matrix.*`. Retain native Matrix for encrypted rooms, recovery, password login, media and durable sessions.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. The homeserver is your own, so the manifest declares no destinations: grant its host after binding. For an instance named `main`, whose config entry key is `zpi1_WyJtYXRyaXgiLCJjaGFubmVsIiwibWFpbiJd`:

```bash
zeroclaw plugin install matrix --channel-alias main
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJtYXRyaXgiLCJjaGFubmVsIiwibWFpbiJd.egress_hosts 'matrix.example.org'
# The secret prompts without echo; it is never passed on the command line.
zeroclaw config set plugins.entries.zpi1_WyJtYXRyaXgiLCJjaGFubmVsIiwibWFpbiJd.config.access_token
zeroclaw config set --no-interactive plugins.entries.zpi1_WyJtYXRyaXgiLCJjaGFubmVsIiwibWFpbiJd.config.homeserver https://matrix.example.org
zeroclaw config set plugins.enabled true
```

Route `plugin.main` to an agent and admit senders by exact Matrix user ID in a peer group bound to `plugin.main`, then restart the daemon. `zeroclaw plugin info matrix` repeats the install-time load check and lists any configuration still missing.

## Configuration

The closed schema requires `homeserver` and `access_token`. Set the token through the host's secret-aware configuration surface. Its `x-secret` designation removes it from `config.get`; the component obtains it only through scoped `secrets.get("access_token")`. Public configuration rejects credentials and unknown keys.

| Public property | Meaning |
| --- | --- |
| `homeserver` | Trusted HTTP or HTTPS base URL, optionally with a base path; no userinfo, query or fragment. Grant only this destination through host egress policy. |
| `user_id` | Optional assertion against authenticated `/account/whoami`; never an authentication fallback. |
| `allowed_rooms` | Exact room IDs for inbound filtering; empty or absent accepts joined rooms. Host sender authorization remains authoritative. |
| `mention_only` | Default false; in group rooms require a body or structured mention of the authenticated account. Direct-room metadata exempts direct rooms. |
| `reply_in_thread` | Default true; use top-level events as outbound thread anchors. Existing thread roots retain their identity even when this setting is false. |

Operational calls resolve current public config and secrets, then authenticate before delivery or sending. Same-account token rotation takes effect on the next call. Only an authenticated public self identity, its homeserver provenance, transaction sequence, retry state, sync cursor, bounded server-owned room metadata and pending event metadata survive calls. No credential or live policy snapshot is retained. Unreadable config or secrets blocks delivery. Changing homeserver or authenticated account discards the cursor, pending messages and room metadata and requires fresh configuration, even if the previous binding is restored.

## Text and lifecycle

- Startup establishes a volatile `/sync` cursor and learns bounded room metadata while suppressing initial and advancing catch-up timelines, including limited timelines. An unchanged valid incremental cursor ends bootstrap; that response's events are also suppressed. Subsequent polls deliver new unencrypted `m.text` events in joined rooms and reject limited timelines. Restarting loses the cursor and repeats bootstrap. Messages arriving during bootstrap may be suppressed.
- This cutoff is experimental, not a universal freshness guarantee. Busy or unrelated streams can prevent an unchanged cursor indefinitely, leaving the channel unready. Synapse worker catch-up timeouts can also return an unchanged cursor, so this does not establish multi-worker restart safety or durable replay. The integration proof uses a pinned single-process Synapse.
- Server-owned `m.direct` membership and summary member counts survive sync responses that omit them. Each `m.direct` event replaces the previous direct-room set, including an empty replacement. Summary count fields update when present; an omitted field leaves the prior count unchanged. A leave clears that room's metadata and pending messages. These are account/homeserver-bound protocol facts, not cached configuration policy.
- Current room policy excludes disallowed rooms before queue counting. Pending events retain room, direct-room and mention provenance. Current room, mention and reply policy also applies when they leave the queue. Self echoes, encrypted events, media and edits are ignored.
- Thread replies preserve their genuine root as `interruption_scope_id`. A top-level event used as a new outbound reply anchor has no interruption scope.
- Authentication failure never falls back to a configured identity. Poll failures emit scrubbed structured logs and make health unhealthy until a successful sync. A successful whoami health probe alone does not clear a poll failure. Initial health stays unhealthy until bootstrap completes.
- Polling retries at most once per call, with exponential delay from one to thirty seconds. Batch admission commits the cursor, queue and room metadata together. Queue or metadata overflow, malformed timeline structure, and a limited incremental timeline in a currently allowed room reject the batch without advancing any of those states or clearing sync failure. If a timeline is present, it must be an object with an events array and any `limited` field must be boolean. Sustained overflow or a timeline gap requires operator attention; the plugin does not fetch history or silently skip missing events.

## Deliberately unencrypted rooms only

Before returning an inbound plaintext message to the host, every poll performs a fresh authenticated encryption-state GET for that candidate's room. Both freshly synced and queued messages use the same admission operation. Only the exact `404`/`M_NOT_FOUND` absence response permits delivery. A successful encryption-state object, including empty content or an unknown algorithm, discards that candidate normally and leaves later candidates for subsequent polls. This does not trigger failure backoff or mark the channel unhealthy.

Uncertain state, including malformed responses, authentication denial and transport or deadline errors, refuses delivery through the existing poll-failure path. The candidate retains its room/mention provenance and moves to the queue tail for a later fresh check, allowing other rooms to progress after the existing bounded backoff. Current room and mention policy is reapplied before checking. Polls check at most one eligible candidate. After a failure, the next retry refreshes sync while preserving the pending queue so new messages and room departures can be admitted; ordinary queued delivery does not require another sync. If the refresh exceeds queue capacity, one retained candidate can still pass the same fresh admission check and free a slot. The failed refresh leaves its cursor uncommitted and retains its failure/backoff state. Other sync failures do not use this fallback. Backoff resets only after sync and candidate admission finish without error. No room-encryption permission is cached.

Every send resolves a room alias first, if present, then performs a fresh authenticated GET of that resolved room's `m.room.encryption` state immediately before the text PUT. Any existing encryption event is refused, including empty content or an unknown algorithm. Only `404` with valid JSON `errcode = "M_NOT_FOUND"` from that exact endpoint establishes absence. Generic 404, malformed responses, authentication or access denial, redirect, network refusal and deadline failure stop before any send PUT. Unencrypted-room permission is never cached.

These preflights are **not atomic**. Encryption may be enabled after the state GET and before host admission or the send PUT. Use the plugin only in intentionally unencrypted rooms whose operators accept that race. Use native Matrix for encrypted messaging. A send transport failure can leave delivery uncertain; the plugin does not automatically retry sends.

## Bounds and validation

Send and poll share an aggregate HTTP deadline of 25 seconds per call across authentication, alias resolution, state lookup, send and response handling. Configure and health use seven seconds, within the host doctor's ten-second limit. WASI requests also carry two-second connect, three-second first-byte and one-second between-byte limits. Timer pollables bound nonblocking request writes and response reads. Total transferred body bytes are capped at 1 MiB per call; sync responses at 512 KiB; identity, alias, state and send responses at 16 KiB each. The queue holds at most 64 events and each text/send body is at most 64 KiB. Retained room metadata covers at most 256 distinct room IDs across direct membership and member counts; overflow fails closed. Errors contain only local classes or numeric HTTP status, never bodies, content, credentials or URLs.

Typing, reactions, approvals, media, progressive drafts, password login, E2EE and durable cursors are not implemented. Their capability flags remain unset and their required exports use the WIT defaults.

Focused host tests cover parsing, current-policy admission and delivery, retained protocol metadata, atomic batch refusal, lifecycle invalidation, thread isolation, backlog suppression and encryption refusal decisions. WASM-target lint and a release build check the component bindings and transport code. Real-host admission, deadline behavior, token rotation, zero-PUT refusal and disposable Synapse delivery require separate integration proof. Local pure tests and compilation cannot establish those integration boundaries. Repository CI commands and immutable-component rules are defined in `docs/ci.md`; do not install a new Rust target implicitly.
