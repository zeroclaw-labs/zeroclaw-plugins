# MQTT

The plugin implements MQTT 3.1.1 over ZeroClaw's host-mediated raw socket transport:

1. resolve `mqtt://` or `mqtts://` from the injected channel configuration;
2. open host-owned TCP/TLS and send a clean-session `CONNECT`;
3. subscribe to every configured topic after `CONNACK`;
4. reassemble arbitrary TCP chunks into bounded MQTT packets;
5. map each inbound publish topic to both `sender` and `reply_target`;
6. publish outbound text to the topic in `SendMessage.recipient`;
7. drive QoS acknowledgements, keepalive pings, and capped reconnect backoff.

MQTT topic names are case-sensitive. The manifest therefore uses
`sender_match = "exact"`, matching the native MQTT topic matcher and ensuring
that peer-group entries authorize the exact topic delivered by the broker.

## Install and configure

Build the source-only package from its directory and bind the channel on ZeroClaw v0.9.0.

```sh
cargo build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/mqtt.wasm .
zeroclaw plugin install "$PWD"
zeroclaw plugin bind mqtt --channel-alias broker --egress none
zeroclaw plugin info mqtt
```

Copy the config entry key printed by `plugin info` into the shell variable `key`. The commands for secrets prompt without echo. Grant the hostname in the broker URL.

```sh
zeroclaw config set "plugins.entries.$key.egress_hosts" 'broker.example.com'
zeroclaw config set "plugins.entries.$key.config.broker_url" 'mqtts://broker.example.com:8883'
zeroclaw config set "plugins.entries.$key.config.client_id" 'zeroclaw-agent'
zeroclaw config set "plugins.entries.$key.config.topics" '["sensors/#"]'
zeroclaw config set "plugins.entries.$key.config.qos" '1'
zeroclaw config set "plugins.entries.$key.config.use_tls" 'true'
zeroclaw config set "plugins.entries.$key.config.username" 'broker-user'
zeroclaw config set "plugins.entries.$key.config.password"
```

Enable `plugins.enabled`, route `plugin.broker` to an enabled agent, and authorize senders in the alias’s peer group.

`use_tls` must agree with the URL scheme. Ports default to 1883 for `mqtt://`
and 8883 for `mqtts://`. QoS 0, 1, and 2 are supported for subscriptions,
inbound acknowledgements, and outbound publishes. TLS certificate validation
and SNI belong to the host socket implementation.

## Limits

- MQTT 5 properties, WebSockets, Last Will, retained outbound publishes, and
  persistent sessions are not implemented.
- Clean-session reconnects do not durably retransmit outbound QoS 1/2 messages
  that were in flight when the socket failed.
- WIT channel content is text, so non-UTF-8 MQTT payloads are converted with
  UTF-8 replacement characters.
- Packets larger than 1 MiB are rejected to bound guest memory use.
## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
```
