# twitch - ZeroClaw Twitch IRC channel plugin

This plugin mirrors the native `[channels.twitch.<alias>]` channel through
`provides = "twitch"`. The host injects that resolved section into `configure`;
there is no plugin-specific copy of the channel configuration.

The implementation connects to `irc.chat.twitch.tv:6697` through the host's
TLS socket capability, authenticates with `PASS`/`NICK`, requests the
`twitch.tv/tags` and `twitch.tv/commands` capabilities, and joins every
configured channel after Twitch acknowledges both capabilities and sends the
welcome numeric. Socket receive calls are nonblocking and bounded per poll.

## Configuration

The fields are the native `TwitchConfig` fields:

```toml
[channels.twitch.default]
enabled = true
bot_username = "zeroclaw_bot"
oauth_token = "oauth:replace_with_user_access_token"
channels = ["mychannel", "#anotherchannel"]
mention_only = false
```

`bot_username` and channel names are normalized to lowercase. The `oauth:`
prefix is added when omitted. The access token needs Twitch's `chat:read` and
`chat:edit` scopes. Sender identity uses the normalized lowercase Twitch login
from the IRC prefix.

## Supported behavior

- Host-mediated TLS connection with bounded exponential reconnect backoff.
- Twitch IRC capability negotiation, OAuth registration, and channel JOIN.
- Fragmented/coalesced TCP frame reassembly and IRCv3 tag unescaping.
- Immediate PING/PONG keepalive handling.
- Inbound PRIVMSG parsing with tagged message ID, display name, server
  timestamp, and reply-thread parent metadata.
- Channel routing through the PRIVMSG target and optional mention-only filter.
- Outbound text PRIVMSG splitting at UTF-8 and IRC wire boundaries.
- Tagged Twitch replies when ZeroClaw supplies `thread_ts`.

## Host gate and limits

`registry = false` remains intentional: the `socket_client` host capability is
not available on upstream ZeroClaw master yet. The component can be built and
tested now, but a stock host cannot instantiate its socket import.

This version supports Twitch IRC chat text only. It does not implement media,
typing indicators, draft edits, reactions, moderation commands, EventSub, or an
application-level Twitch send-rate scheduler. Twitch may throttle or disconnect
clients that exceed its chat limits. No live credentialed Twitch test is part
of the repository test suite.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
```
