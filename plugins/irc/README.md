# irc

An IRC channel plugin for ZeroClaw. It connects to one IRC server over TLS
through the host's socket capability, registers with IRCv3 capability
negotiation, joins the configured channels, and answers channel and direct
messages in plain text.

It replaces the IRC channel that was compiled into ZeroClaw. Installing it
needs no rebuild of ZeroClaw.

Requires ZeroClaw v0.8.6 or later.

## Install and bind

```bash
zeroclaw plugin install irc
zeroclaw plugin bind irc --channel-alias libera
```

The package declares no egress destinations, because the IRC server is yours
to choose, so the binding starts with no network reach. Grant the server on
the instance's `egress_hosts`: `zeroclaw plugin info irc` prints the
`zeroclaw config set` command for that row with the value left empty; append
your server's hostname and run it. Then set the config, enable the plugin
system, and route the channel to an agent:

```toml
[plugins]
enabled = true

[channels.plugin.libera]
package = "irc"
enabled = true

[agents.assistant]
channels = ["plugin.libera"]

[peer_groups.libera_users]
channel = "plugin.libera"
external_peers = ["alice", "bob"]
```

`zeroclaw plugin info irc` lists the required config keys and whether each is
set. The secrets (`server_password`, `nickserv_password`, `sasl_password`,
and the TLS material) are stored encrypted, and `zeroclaw config set` prompts
for them without echo.

## Configuration

| Key | Type | Default | Purpose |
|---|---|---|---|
| `server` | string | required | Server hostname. Grant the same host in `egress_hosts`. |
| `port` | integer | `6697` | TLS port. Plaintext IRC is not supported. |
| `nickname` | string | required | Bot nickname. |
| `username` | string | nickname | The `USER` ident. |
| `channels` | array of strings | `[]` | Channels joined after every registration, e.g. `["#zeroclaw"]`. |
| `mention_only` | boolean | `false` | Answer channel messages only when they mention the nickname. Direct messages are always answered. |
| `sasl_mechanism` | `"plain"` or `"external"` | none | SASL during registration. See [Authentication](#authentication). |
| `sasl_username` | string | nickname | The services account SASL PLAIN authenticates as. |
| `tls_profile` | string | none | A TLS profile on this instance, for a private CA or a client certificate. |
| `sender_identity` | `"nick"` or `"account"` | `"nick"` | What the sender of an inbound message is. See [Who may talk to the bot](#who-may-talk-to-the-bot). |
| `server_password` | secret | none | Sent as `PASS`, e.g. for a ZNC bouncer. |
| `nickserv_password` | secret | none | Sent as `IDENTIFY` to NickServ after registration. |
| `sasl_password` | secret | none | The SASL PLAIN password. |
| `tls_ca_pem` | secret | none | PEM CA certificates, referenced by a TLS profile. |
| `tls_client_certificate_pem` | secret | none | PEM client certificate chain, referenced by a TLS profile. |
| `tls_client_key_pem` | secret | none | PEM client private key, referenced by a TLS profile. |

The plugin reads the config and each password at the moment it uses them, so
an edited password applies on the next connection. Joined channels change on
the next connection. The nickname the host reports as the bot's own handle is
read once, when the channel starts.

## Authentication

- **SASL PLAIN.** Set `sasl_mechanism = "plain"` and the `sasl_password`
  secret. The plugin authenticates as `sasl_username`, or as the configured
  nickname, before registration completes.
- **SASL EXTERNAL (CertFP).** Set `sasl_mechanism = "external"` and
  `tls_profile` to a profile that presents a client certificate, as shown
  below. Register the certificate's fingerprint with the network's services
  first.
- **NickServ.** Set the `nickserv_password` secret. The plugin sends
  `IDENTIFY` after registration. Prefer SASL where the network supports it:
  SASL authenticates before the bot joins anything.
- **Server password.** Set the `server_password` secret, e.g. for a bouncer.

A configured SASL mechanism that fails disconnects the bot rather than
continuing unauthenticated. The plugin then waits 15 minutes before trying
again, so a wrong password cannot get the host banned for reconnect flooding.

## TLS profiles

Certificate verification is always on. The old built-in channel's
`verify_tls = false` has no equivalent. For a server whose certificate chains
to a private CA, or to present a client certificate, add a TLS profile to the
instance's `plugins.entries` row and name it in `tls_profile`:

```toml
[[plugins.entries]]
name = "zpi1_…"                       # the instance key from `plugin info`
egress_hosts = ["irc.example.net"]

[[plugins.entries.tls_profiles]]
name = "certfp"
hosts = ["irc.example.net"]
system_roots = true
client_certificate_secret = "tls_client_certificate_pem"
client_private_key_secret = "tls_client_key_pem"
```

Store the PEM material in the matching secrets with `zeroclaw config set`.
For a private CA, set `custom_ca_secret = "tls_ca_pem"` and, to trust only
that CA, `system_roots = false`. The host loads the material when it builds
the connection; the plugin itself can never read it.

## Who may talk to the bot

The host delivers a message only when its sender is in a peer group for this
channel (`external_peers`); an empty peer set answers no one, and `["*"]`
answers anyone. The host compares senders exactly. IRC identities are
case-insensitive, so the plugin reports every sender in lowercase: **write
`external_peers` entries in lowercase.**

By default the sender is the nickname. Anyone can use a nickname nobody has
registered, so on a network with services, consider
`sender_identity = "account"`. The plugin then requests the IRCv3
`account-tag` capability, reports the sender's services account, and drops
messages from users who are not logged in. It refuses to connect to a server
that does not offer the capability.

## Behavior

- **Replies.** A channel message is answered in the channel; a direct message
  is answered to the sender. The agent sees channel messages as
  `<nick> text`, after a short instruction to answer in plain text.
- **Inbound filtering.** NickServ and ChanServ, CTCP queries such as
  `VERSION`, and the bot's own messages are ignored. A CTCP `ACTION`
  (`/me waves`) arrives as `* nick waves`. mIRC colour and formatting codes
  are removed.
- **Outbound.** Replies are split at newlines and wrapped at word boundaries
  to fit the 512-byte line limit. Blank lines are dropped. CTCP delimiters
  are removed, so a reply can never send a CTCP request.
- **Flood control.** Replies are paced like irssi's defaults: a burst of five
  lines, then one line every two seconds. Long replies keep sending across
  later polls. A reply that would make more than 256 lines wait is refused.
- **Liveness.** After two minutes without traffic the plugin sends `PING`,
  and reconnects if no answer arrives within a minute. Registration must
  finish within a minute.
- **Reconnects.** A lost connection is retried with exponential backoff from
  2 seconds to 5 minutes, with jitter. If the host refuses the destination or
  the TLS profile, the plugin waits a minute between attempts and logs what to
  fix. If the server rejects the credentials or the configuration, it waits
  15 minutes.
- **Nick collisions.** During registration a taken nickname is retried with
  `_` appended, up to three times.
- **Health.** The channel reports healthy while it is registered on the
  server.

Not supported: media attachments (the text of a message that carries some is
still sent), DCC, typing indicators, reactions, and plaintext or STARTTLS
connections.

## Migrating from the built-in IRC channel

ZeroClaw no longer builds an IRC channel in. A `[channels.irc.<alias>]`
section is removed from the config with a notice. To move an instance:

| Built-in `[channels.irc.<alias>]` | Plugin |
|---|---|
| `server`, `port`, `nickname`, `username`, `channels`, `mention_only` | Same keys. |
| `server_password`, `nickserv_password` | Same secret keys. |
| `sasl_password` | Same secret key, plus `sasl_mechanism = "plain"`. SASL now authenticates as the configured nickname or `sasl_username`, never a collision-renamed nick. |
| `verify_tls = false` | Removed. Trust the server's CA with a TLS profile. |
| `excluded_tools` | Not a plugin key. |
| peer group `channel = "irc.<alias>"` | `channel = "plugin.<alias>"`, entries lowercase. |
| agent `channels = ["irc.<alias>"]` | `channels = ["plugin.<alias>"]`. |

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo clippy --target wasm32-wasip2 -- -D warnings
cargo build --target wasm32-wasip2 --release
```

`src/irc.rs` holds the protocol logic and is tested on the host by
`tests/irc.rs`. `src/lib.rs` is the component shim that performs the socket
I/O.
