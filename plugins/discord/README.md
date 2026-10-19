# discord: ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects an agent to Discord. It runs the Discord Gateway protocol (discovery,
IDENTIFY, heartbeats, RESUME, and `MESSAGE_CREATE` dispatch) over the host's
`websocket` resource, and posts replies with the REST API through `wasi:http`,
from a sandboxed `wasm32-wasip2` component.

## Host requirement

The plugin binds the host contract with the `websocket` connection resource,
typed config, and point-of-use secrets. ZeroClaw v0.8.6 is the first release
that carries it; v0.8.5 and earlier do not. The host also needs the Cranelift
backend, which compiles `.wasm` components. A source build enables it with:

```bash
cargo build --release --features plugins-wasm-cranelift
```

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info discord` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. Build the
component, stage it beside the manifest, and install the directory:

```bash
cargo build --release --target wasm32-wasip2
mkdir -p stage/discord
cp manifest.toml stage/discord/
cp target/wasm32-wasip2/release/discord.wasm stage/discord/
zeroclaw plugin install ./stage/discord --channel-alias main --egress declared
```

On a host with the channel binding ceremony, `--channel-alias` writes the
`[channels.plugin.main]` binding and creates the instance's config row, and
`--egress declared` grants the hosts the manifest declares, `discord.com` and
`*.discord.gg`. `--egress none` binds with no network reach instead.
`zeroclaw plugin bind discord --channel-alias main --egress declared` binds an
installed package.

On a host without the ceremony, install without the flags and write both by
hand. The instance key is `zpi1_` followed by the unpadded base64url of the
JSON array `["discord","channel","<alias>"]`; for the alias `main`:

```toml
[channels.plugin.main]
package = "discord"

[[plugins.entries]]
name = "zpi1_WyJkaXNjb3JkIiwiY2hhbm5lbCIsIm1haW4iXQ"
egress_hosts = ["discord.com", "*.discord.gg"]
```

Then, on either host:

```bash
# The token prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJkaXNjb3JkIiwiY2hhbm5lbCIsIm1haW4iXQ.config.bot_token
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit senders by their numeric Discord user
id. A plugin channel matches senders exactly, so list ids, not usernames:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.discord_main]
channel = "plugin.main"
external_peers = ["111111111111111111"]
```

Restart the daemon. Do not also run the built-in Discord channel, or a second
alias, with the same token: Discord delivers every event to each connection,
so each would answer every message.

## Configuration

Set each value with
`zeroclaw config set plugins.entries.<instance-key>.config.<key> <value>`.
Strings are written as is; booleans, integers, and lists as JSON text, for
example `'["123456789012345678"]'`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bot_token` | string, secret, required | | The bot token from the Discord Developer Portal. Read only through `secrets.get`. |
| `guild_ids` | list of id strings | all | Servers to listen in. Direct messages always pass this filter. |
| `channel_ids` | list of id strings | all | Channels to listen in, matched directly (a thread does not inherit its parent's entry). The first entry is also the target of a reply that has no recipient. |
| `listen_to_bots` | boolean | `false` | Accept messages from other bots and webhooks. The bot's own messages are always dropped. |
| `mention_only` | boolean | `false` | In servers, answer only messages that mention the bot. Direct messages are exempt. |
| `intents_mask` | integer | `37376` | Gateway intents, used verbatim. The default is guild and direct messages with their content. |
| `api_base` | URL | `https://discord.com/api/v10` | REST and discovery base. It receives the token: grant only a host you trust. |
| `gateway_url` | URL | discovered | A gateway to dial instead of discovering one. A session's resume URL still wins on a resume. |

The plugin reads its config and token inside each call that uses them and keeps
neither, so an edit applies without a restart: the filters on the next message,
`api_base` on the next discovery or reply, `gateway_url` on the next dial,
`intents_mask` on the next IDENTIFY, and a new token on its next use. The bot's
id, decoded from the token when the instance starts, is the one value it keeps;
changing to a different bot takes a restart.

The default intents leave out `GUILDS`, which the built-in channel requests
(37377). The plugin never reads guild topology, and a large server's
`GUILD_CREATE` can exceed the host's WebSocket frame limit.

## Behavior

- **One network step per poll.** Discovery (`GET /gateway/bot`) and the
  gateway dial never share a `poll-message` call, and a channel check shares
  one only with reading the gateway. Nothing touches the network in
  `configure`.
- **Bounded requests.** Every REST request carries a 3 s connect timeout, 5 s
  to the first response byte, and 2 s between bytes, and reads at most 2 s of
  body. Discovery and each reply part therefore finish in about 12 s. A
  response is judged by its status: a reply Discord accepted counts as
  delivered even if its body stalls.
- **Sessions.** A dropped connection resumes at the session's resume URL.
  Heartbeats start at a random point in the first interval; a heartbeat that is
  not acknowledged by the next one, with every queued event read, marks the
  connection dead and resumes it. A connection that sends no Hello within 20 s,
  or establishes no session within 60 s of its Hello, is dropped and retried; a
  resume that never completes is not retried. A server request to reconnect
  (op 7) or a resumable invalid session (op 9) reconnects at once when the
  session had lasted 10 s, and backs off otherwise.
- **Close codes.** 4004 (bad token) and 4010 to 4014 (sharding, API version,
  intents) stop the instance; 4014 logs which privileged intent to enable in the
  Developer Portal. 4007 and 4009 start a new session. Anything else, including
  a close without a frame, resumes. A close that races a send is still read and
  classified by its code.
- **Backoff and the IDENTIFY budget.** Reconnects wait 1 s, doubling to 60 s,
  reset once a session has lasted 10 s. IDENTIFYs are at least 5 s apart and at
  most 40 in any hour (960 a day, under Discord's 1,000), with or without
  `gateway_url`. Once discovery reports 100 or fewer session starts left today
  they are 5 minutes apart, and none are sent while discovery reports none left
  until its reset time. A resume spends no IDENTIFY and is never held.
- **Stopped instances.** A stopped instance probes after 60 s, doubling to 30
  minutes: through discovery, or by dialing `gateway_url` when one is set. It
  dials again once a probe succeeds. A rejected token (401) keeps it stopped
  without spending an IDENTIFY.
- **Oversized events.** An event larger than the host's frame limit ends the
  session (a resume would replay it), waits at least 30 s, and after three such
  events stops the instance with a hint to narrow `intents_mask`.
- **Refused connections.** A gateway host outside the grant is logged and
  retried every minute, so a grant added later applies without a restart. A
  refused resume host falls back to discovery.
- **No plaintext downgrade.** The token travels in the gateway handshake, so a
  `ws://` gateway is used only when the connection that announced it was
  plaintext too: a `ws://` resume URL from a `wss://` session, or a `ws://`
  gateway from an `https` `api_base`, is ignored.
- **Unreadable config.** When the host cannot serve the config (for example
  after an edit it rejects), there is nothing to filter messages by: the plugin
  logs once, reports unhealthy, and pauses. Discord may end the session
  meanwhile; once the config is readable again the plugin resumes or
  reconnects.
- **Replies.** A reply is split at 2,000 characters (after a newline when one is
  at least half way in, otherwise after a space) and posted in order 500 ms
  apart. A part rate limited for 2 s or less is retried once. No part starts
  more than 15 s into a send, so a long reply ends inside the host's default
  call deadline and reports how many parts were delivered. Errors carry the
  status and Discord's error code and message, nothing else from the response.
- **Channel checks.** Discord sends no events from a channel the bot cannot
  view, so such a `channel_ids` entry would stay silent. After READY, the plugin
  checks each entry once with `GET /channels/{id}`: one entry per call, at least
  1 s apart, only in a call that read every queued gateway event and has no
  message waiting for the host, and with the health check's shorter timeouts. A
  403 logs a warning naming the channel and the fix (View Channel for the bot's
  role or member, or adding the bot to the server); a 404 or a 400 logs that
  Discord knows no such channel. A rate-limited check waits as long as Discord
  asks. A check that gets no response or a 5xx is tried twice more, 30 s and
  then 60 s later; if it still fails, or fails any other way, an info record
  says the entry is checked again in the next session. A resume continues the
  checks, a new session starts them over (keeping any pending wait), and an
  entry added by an edit is checked on a later call.
- **Health.** Unhealthy while stopped, refused, or unable to read config.
  Healthy while a session is established. Before that, the check asks Discord
  whether the token works (`GET /users/@me`), as the built-in channel does, so
  `zeroclaw channel doctor` reports a rejected token.
- **Logging.** State changes only: configuration, discovery, dials, handshakes,
  sessions, disconnects with their close code, stops with their hint,
  configured channels the bot cannot use or could not check, and send
  failures. Never the token, a payload, or message content.

## Limits

- The host caps a WebSocket frame at 256 KiB and a message at 1 MiB.
- Each call runs under the host's deadline (`plugins.limits.call_timeout_ms`,
  default 30 s). The host also gives a gateway dial up to 30 s, so a dial that
  hangs that long is cut off by the call deadline first: the instance is
  discarded and starts over with a new IDENTIFY. Lowering
  `call_timeout_ms` below about 30 s cuts replies and discovery short too.
- The limits above (backoff, the IDENTIFY budget, probe delays, oversize
  strikes) live in the instance, so a restart or a rebuilt instance starts them
  over.
- On shutdown the host closes the socket without a close frame, so Discord
  keeps the session resumable until its own timeout.

## Not supported

Attachments, threads (a reply goes to the channel a message came from, without
resolving a thread's parent), slash commands and other interactions, reactions,
message archive and search, tool approvals, typing indicators and streamed
replies, and sharding.

## Build and test

```bash
rustup target add wasm32-wasip2
cargo test                                    # the pure core and state machine, on the host
cargo build --release --target wasm32-wasip2  # the component
```

`src/discord.rs` holds the pure logic: config parsing, frame parsing, payload
builders, the `MESSAGE_CREATE` filter, chunking, REST classification, the reply
delivery rules, and the `Gateway` state machine. `src/lib.rs` is the component
shim that performs the gateway and `wasi:http` I/O they ask for.
`tests/gateway_lifecycle.rs` scripts a whole session through the state machine.
