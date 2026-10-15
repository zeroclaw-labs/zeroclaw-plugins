# Matrix text-only channel plugin

Matrix 0.3.0 is an opt-in current-host compatibility candidate. It binds the experimental `wit/current` contract with `plugins-wit-v0` and is excluded from registry publication by `registry = false`. Build it with the host revision pinned in `wit/CURRENT_REF`; this unfrozen interface does not promise compatibility with released hosts. Published Matrix 0.1.0 and 0.2.0 packages remain unchanged.

Registry publication requires a matching plugin-capable host release and install, alias-binding and real-host Matrix checks against its downloaded artifact. The current pin is preparation evidence, not a released-host guarantee. Matrix is the only guest admitted to publish against this contract; the shared CI policy preserves unrelated package identities and requires a new Matrix version after any subsequently published contract changes.

Use an explicit `channels.plugin.<alias>` instance with this package and the host's supported plugin configuration surface. `provides = "matrix"` describes the channel; it does not activate a native mirror or read `channels.matrix.*`. Retain native Matrix for encrypted rooms, recovery, password login, media and durable sessions.

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

Every send resolves a room alias first, if present, then performs a fresh authenticated GET of that resolved room's `m.room.encryption` state immediately before the text PUT. Any existing encryption event is refused, including empty content or an unknown algorithm. Only `404` with valid JSON `errcode = "M_NOT_FOUND"` from that exact endpoint establishes absence. Generic 404, malformed responses, authentication or access denial, redirect, network refusal and deadline failure stop before any send PUT. Unencrypted-room permission is never cached.

This preflight is **not atomic**. Encryption may be enabled between the state GET and the send PUT. Use the plugin only in intentionally unencrypted rooms whose operators accept that race. Use native Matrix for encrypted messaging. A send transport failure can leave delivery uncertain; the plugin does not automatically retry sends.

## Bounds and validation

Send and poll share an aggregate HTTP deadline of 25 seconds per call across authentication, alias resolution, state lookup, send and response handling. Configure and health use seven seconds, within the host doctor's ten-second limit. WASI requests also carry two-second connect, three-second first-byte and one-second between-byte limits. Timer pollables bound nonblocking request writes and response reads. Total transferred body bytes are capped at 1 MiB per call; sync responses at 512 KiB; identity, alias, state and send responses at 16 KiB each. The queue holds at most 64 events and each text/send body is at most 64 KiB. Retained room metadata covers at most 256 distinct room IDs across direct membership and member counts; overflow fails closed. Errors contain only local classes or numeric HTTP status, never bodies, content, credentials or URLs.

Typing, reactions, approvals, media, progressive drafts, password login, E2EE and durable cursors are not implemented. Their capability flags remain unset and their required exports use the WIT defaults.

Focused host tests cover parsing, current-policy admission and delivery, retained protocol metadata, atomic batch refusal, lifecycle invalidation, thread isolation, backlog suppression and encryption refusal decisions. WASM-target lint and a release build check the component bindings and transport code. Real-host admission, deadline behavior, token rotation, zero-PUT refusal and disposable Synapse delivery require separate integration proof. Local pure tests and compilation cannot establish those integration boundaries. Repository CI commands and immutable-component rules are defined in `docs/ci.md`; do not install a new Rust target implicitly.
