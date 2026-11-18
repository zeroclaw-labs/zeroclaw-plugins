# AMQP

AMQP 0-9-1 channel for RabbitMQ-compatible brokers. The guest implements the
application protocol; the ZeroClaw host owns TCP, DNS, and optional TLS through
the `zeroclaw:plugin/sockets` WIT import.

## Install and configure

Build the source-only package from its directory and bind the channel on ZeroClaw v0.9.0.

```sh
cargo build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/amqp.wasm .
zeroclaw plugin install "$PWD"
zeroclaw plugin bind amqp --channel-alias events --egress none
zeroclaw plugin info amqp
```

Copy the config entry key printed by `plugin info` into the shell variable `key`. The commands for secrets prompt without echo. Grant the hostname in the broker URL. Supply the full AMQP URI (including any credentials) at the secret prompt.

```sh
zeroclaw config set "plugins.entries.$key.egress_hosts" 'broker.example.com'
zeroclaw config set "plugins.entries.$key.config.amqp_url"
zeroclaw config set "plugins.entries.$key.config.exchange" 'events.topic'
zeroclaw config set "plugins.entries.$key.config.routing_keys" '["release.#"]'
zeroclaw config set "plugins.entries.$key.config.sender_label" 'release-bus'
```

Enable `plugins.enabled`, route `plugin.events` to an enabled agent, and authorize senders in the alias’s peer group.

The configured exchange must already exist. The plugin declares the configured
queue (or an anonymous exclusive auto-delete queue), binds every routing key,
sets a bounded prefetch for durable acknowledgements, and starts one consumer.
A named queue uses the native channel's non-exclusive, non-auto-delete,
non-durable declaration flags.

`sender_label` is emitted verbatim as the inbound sender and is authorized by
the host with case-sensitive exact matching. It is an external source identity,
not the plugin's self handle. JSON bodies can be mapped with `content_template`;
dotted placeholders and `thread_id_field` are supported. Non-JSON bodies are
delivered as lossy UTF-8 text.

With `durable_ack = true`, a delivery is acknowledged on the poll call after it
was returned across the channel WIT boundary. The host does not poll again until
the previous message has completed its authorization and queue handoff, so a
crash before handoff leaves the broker delivery unacked for redelivery. With
`false`, `basic.consume` uses `no-ack` (at-most-once).

## Publishing

`send` publishes UTF-8 message content to the configured exchange, using the
WIT `recipient` as the AMQP routing key. Messages are marked persistent and use
`text/plain; charset=utf-8`; `subject` maps to the AMQP `type` property and
`in_reply_to` (or `thread_ts`) maps to `correlation-id`. Large bodies are split
at the negotiated `frame-max`.

The call succeeds when bytes are accepted by the host socket queue. Publisher
confirms are not enabled, so it does not prove broker acceptance.

## Connection behavior

- AMQP protocol header and 0-9-1 `connection.start` / `tune` / `open` handshake
- SASL PLAIN authentication and `en_US` locale
- channel 1 open, queue declare, queue bind, QoS, and basic consume
- arbitrary TCP chunk reassembly and multi-frame delivery-body assembly
- individual durable acknowledgements
- negotiated heartbeats (30-second client ceiling) and receive timeout
- bounded nonblocking receive drains and exponential reconnect (1 to 60 seconds)
- 16 MiB hard limits for individual frames and message bodies

## Explicit limits

- Only AMQP 0-9-1 and SASL PLAIN are implemented. AMQP 1.0, challenge-response
  SASL mechanisms, and URI query parameters are unsupported.
- `dispatch = "sop"` and `"sop_and_agent_loop"` are rejected because the
  channel WIT cannot call the host SOP engine.
- `amqps://` uses the host trust roots by default. Select a host-managed TLS profile with `tls_profile` for a private CA or mutual TLS. Reference the instance secrets for the CA, client certificate and private key (tls_ca_pem, tls_client_certificate_pem and tls_client_key_pem) in that profile.
- The plugin does not create or redeclare exchanges and cannot configure queue
  arguments, quorum queues, dead-lettering, priorities, or consumer arguments.
- Publisher confirms, transactions, mandatory returns, alternate exchanges,
  and broker failover URL lists are unsupported.
- WIT binary attachments are rejected. AMQP header tables and inbound basic
  properties are not surfaced as channel-message fields.

## Build and test

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
```

Host tests use encoded broker frames and do not require a live broker. Live
RabbitMQ interoperability and custom network policy remain deployment tests.
