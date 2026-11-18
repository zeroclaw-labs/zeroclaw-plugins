# Nostr channels

Subscribe to public notes from a Nostr relay. The plugin verifies the event ID and BIP-340 signature before reporting the author as the inbound sender. The host checks the author against the peer group for this binding.

## Install and configure

Build the source-only package from its directory and bind the channel on ZeroClaw v0.9.0.

```sh
cargo build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/nostr.wasm .
zeroclaw plugin install "$PWD"
zeroclaw plugin bind nostr --channel-alias relay --egress none
zeroclaw plugin info nostr
```

Copy the config entry key printed by `plugin info` into the shell variable `key`. The commands for secrets prompt without echo. Grant the host of the selected relay. Public notes require no private key.

```sh
zeroclaw config set "plugins.entries.$key.egress_hosts" 'relay.example.com'
zeroclaw config set "plugins.entries.$key.config.relays" '["wss://relay.example.com"]'
```

Enable `plugins.enabled`, route `plugin.relay` to an enabled agent, and authorize senders in the alias’s peer group.

## Feed settings

The plugin opens the first configured relay. Set `pubkey` to your own lowercase hexadecimal public key for mentions, `allowed_pubkeys` for an additional author filter, and `kinds` for the public event kinds to receive (default 1). Set `limit` to control the initial backlog. The public feed excludes encrypted direct messages, seals and gift wraps (kinds 4, 13 and 1059).

The instance stores its last delivered timestamp using the state resource. Resubscription starts at that second so distinct notes with the same timestamp can still arrive. The current instance suppresses duplicate IDs. A restart can replay notes in the boundary second.

This public feed is receive-only. For a relay using a private CA, select an instance TLS profile with `tls_profile` and reference the `tls_ca` secret in the profile. The plugin does not read private keys for public subscriptions.

## Private messages

Set `mode` to `direct_messages` to receive and reply to NIP-04 and NIP-17 private messages. Public notes remain the default, including on an existing binding that has a private key configured. In direct-message mode the plugin requests the `private_key` secret from the host and uses the `relays` array for publish and subscribe. The key can be a 64-character hex scalar or an `nsec` key. Peer entries use the sender’s lowercase hex public key, and outbound recipients accept hex or `npub`.

```sh
zeroclaw config set "plugins.entries.$key.config.mode" 'direct_messages'
zeroclaw config set "plugins.entries.$key.config.private_key"
zeroclaw config set "plugins.entries.$key.config.relays" '["wss://relay.example.com"]'
zeroclaw config set "plugins.entries.$key.egress_hosts" 'relay.example.com'
```

A private-message binding verifies the outer signature and the NIP-17 seal and rumor before delivery. It remembers how each sender last contacted it and replies using the same protocol. New conversations use NIP-17. It fans out to the configured relays, answers NIP-42 challenges and tracks acknowledgements within the running instance. A successful send means at least one host WebSocket accepted the frame. Configure an explicit empty relay list to disable networking in this mode. An omitted relay list uses the core defaults and still requires an egress grant for each destination.

Private messages support text. Attachments, group fan-out, durable outbound queues and preferred-relay discovery are outside this implementation.

## Validation

```sh
cargo test --locked
cargo build --locked --target wasm32-wasip2 --release
```
