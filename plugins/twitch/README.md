# twitch

A Twitch chat channel plugin for ZeroClaw. It connects to Twitch chat
(`irc.chat.twitch.tv:6697`) over TLS through the host's socket capability,
authenticates the bot account, joins the configured channels, and answers in
chat.

It replaces the Twitch channel that was compiled into ZeroClaw. Installing it
needs no rebuild of ZeroClaw.

Requires ZeroClaw v0.8.6 or later.

## Install and bind

```bash
zeroclaw plugin install twitch
zeroclaw plugin bind twitch --channel-alias stream --egress declared
```

`--egress declared` grants the one host the package declares,
`irc.chat.twitch.tv`. Then set the config, enable the plugin system, and route
the channel to an agent:

```toml
[plugins]
enabled = true

[channels.plugin.stream]
package = "twitch"
enabled = true

[agents.assistant]
channels = ["plugin.stream"]

[peer_groups.stream_viewers]
channel = "plugin.stream"
external_peers = ["zeroclaw_user"]
```

`zeroclaw plugin info twitch` lists the required config keys and whether each
is set. `oauth_token` is stored encrypted, and `zeroclaw config set` prompts
for it without echo.

## Configuration

| Key | Type | Default | Purpose |
|---|---|---|---|
| `bot_username` | string | required | The bot account's Twitch login. |
| `oauth_token` | secret | required | A user access token for the bot account. |
| `channels` | array of strings | `[]` | Channels to join by login, with or without `#`, e.g. `["zeroclaw_channel"]`. |
| `mention_only` | boolean | `false` | Answer only messages that mention `bot_username`. |

- **Token.** Use a user access token for the bot account with the
  [`chat:read` and `chat:edit`](https://dev.twitch.tv/docs/chat/irc/#authenticating-with-the-twitch-irc-server)
  scopes. With the [Twitch CLI](https://dev.twitch.tv/docs/cli/token-command/)
  configured, generate one while signed in as the bot account with
  `twitch token -u -s 'chat:read chat:edit'`. The value is trimmed, and the
  `oauth:` prefix is added when omitted. A rotated token applies on the next
  connection.
- **Names.** `bot_username` and channel names are lowercased; `#` is added to
  channel names when missing.

## Who may talk to the bot

The host delivers a message only when its sender is in a peer group for this
channel (`external_peers`). An empty peer set answers no one, and `["*"]`
answers anyone. The sender is the viewer's lowercase Twitch login, so **write
`external_peers` entries in lowercase.** Twitch authenticates logins, so a
sender cannot be spoofed.

## Behavior

- **Replies.** Channel messages are answered in the same channel. When
  ZeroClaw replies in a message's thread, the reply carries Twitch's
  reply-parent tag. The agent sees each message as `<Display Name> text`,
  after a short instruction to answer in plain text.
- **Whispers.** Twitch does not deliver whispers over chat, and a non-channel
  message is ignored.
- **Formatting.** Replies are plain text, split at newlines and at the IRC
  line limit, at UTF-8 boundaries. Markdown is not rendered.
- **Rate limits.** There is no Twitch-specific send limiter: each reply line
  is one chat message. Keep the agent's posting cadence within Twitch's chat
  limits and throttle bursty workflows at their source.
- **Reconnects.** A lost connection is retried with exponential backoff from
  1 to 60 seconds, and a `RECONNECT` from Twitch is honored. Six minutes
  without traffic from Twitch counts as a lost connection. If the host refuses
  the destination, the plugin waits a minute between attempts. If Twitch
  rejects the token or the required capabilities, it waits 15 minutes.
- **Health.** The channel reports healthy while it is authenticated and has
  joined its channels.

Not supported: media attachments (the text of a message that carries some is
still sent), typing indicators, reactions, moderation commands, and EventSub.

## Migrating from the built-in Twitch channel

ZeroClaw no longer builds a Twitch channel in. A `[channels.twitch.<alias>]`
section is removed from the config with a notice. To move an instance:

| Built-in `[channels.twitch.<alias>]` | Plugin |
|---|---|
| `bot_username`, `channels`, `mention_only` | Same keys. |
| `oauth_token` | Same secret key. |
| peer group `channel = "twitch.<alias>"` | `channel = "plugin.<alias>"`, entries lowercase. |
| agent `channels = ["twitch.<alias>"]` | `channels = ["plugin.<alias>"]`. |

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo clippy --target wasm32-wasip2 -- -D warnings
cargo build --target wasm32-wasip2 --release
```

`src/twitch.rs` holds the protocol logic and is tested on the host by
`tests/twitch.rs`. `src/lib.rs` is the component shim that performs the socket
I/O.
