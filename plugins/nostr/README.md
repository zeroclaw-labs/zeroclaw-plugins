# Nostr channel plugin

A ZeroClaw `wasm32-wasip2` channel plugin for private Nostr conversations. The
host owns each WebSocket and TLS connection through `ws-client`; the component
owns the Nostr relay protocol and cryptography.

The manifest declares `provides = "nostr"`, so the host injects the canonical
`[channels.nostr.<alias>]` section. There is no plugin-specific config or sender
allowlist. ZeroClaw applies the live `peer_groups` authorization gate to the
decrypted sender pubkey after the component returns an inbound message. The
plugin emits canonical 64-character lowercase hex pubkeys and declares exact
sender matching, so peer entries for this plugin must use that wire form.
An empty resolved peer set denies every inbound sender; `"*"` is the explicit
operator opt-in for accepting any valid Nostr pubkey.

## Behavior

- Subscribes to NIP-04 kind 4 and NIP-17/NIP-59 kind 1059 events addressed to
  the configured key.
- Verifies each outer event signature and ID before decrypting it.
- Decrypts legacy NIP-04 AES-256-CBC messages.
- Validates and unwraps NIP-17 rumor, seal, and gift-wrap layers using
  authenticated NIP-44 v2 encryption.
- Replies with the protocol most recently used by that sender. Unsolicited
  outbound messages default to NIP-17.
- Fans out subscriptions and publishes across every configured relay, suppresses
  duplicate events, reconnects dropped sockets, and retains a bounded in-memory
  publish queue until relay acknowledgements arrive.
- Handles NIP-42 relay authentication challenges with signed kind 22242 events,
  then re-subscribes and retries pending publishes after authentication.
- Reports healthy only while at least one host-owned relay connection is live.

The cryptographic implementation uses pure-Rust RustCrypto primitives so the
component builds reproducibly for WASI Preview 2. NIP-44 follows the current
32-byte nonce and extended-length format, verifies HMAC-SHA256 in constant time
before decrypting, and is tested against the official vector.

## Configuration

```toml
[channels.nostr.default]
enabled = true
private_key = "nsec1..." # 64-character hex is also accepted
relays = [
  "wss://relay.damus.io",
  "wss://nos.lol",
]
```

`private_key` and `relays` are the only channel fields consumed by the plugin.
The host's canonical Nostr config supplies its default relay set when `relays`
is omitted. An explicitly empty list remains empty, makes the health check fail,
and opens no network connections. Outbound recipients may be 64-character hex
pubkeys or `npub1...`.

## Host gate and limits

`registry = false` remains required until ZeroClaw's `websocket_client` host
capability reaches upstream master. The source and component are functional on
a host that provides that import, but stock upstream cannot instantiate it yet.

- Text private messages only; NIP-17 file messages, reactions, edits, deletes,
  group-chat fan-out, and attachments are not implemented.
- The plugin uses the configured relay set. NIP-65/NIP-17 preferred-relay
  discovery is not implemented.
- Outbound success means at least one host socket accepted the frame. Relay
  acknowledgements and authentication retries are tracked asynchronously by
  subsequent polls; pending state is bounded and not persisted across restart.
- New chat messages are capped at 64 KiB. Decryption is bounded at 1 MiB to
  reject oversized relay payloads before excessive allocation.
- NIP-04 is supported only for compatibility and remains deprecated by Nostr.

## Build and test

```sh
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
```
