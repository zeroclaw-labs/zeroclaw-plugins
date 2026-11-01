# Iris Chat channel

[Iris Chat](https://irischat.org) brings Signal-like messaging over Nostr Double Ratchet to ZeroClaw, without phone numbers or signup.

```sh
zeroclaw plugin install iris-chat
```

The registry command becomes available after this plugin is accepted and published. Until then, use the local component package from [iris-chat-channels releases](https://github.com/irislib/iris-chat-channels/releases).

This component also needs the separately installed Iris CLI and Python loopback bridge. Follow the short [setup guide](https://github.com/irislib/iris-chat-channels/tree/main/zeroclaw). The bridge owns the ratchet state; the component never reads keys or runs commands.

Operator configuration selects one approved contact, grants `127.0.0.1` in both `egress_hosts` and `egress_allow_private`, admits the same contact in a ZeroClaw peer group, and assigns the channel to an existing agent. No contacts or tool permissions are opened automatically. Keep the bridge and ZeroClaw in one trusted network namespace; never publish port 8765. The host's loopback grant covers all ports on that host.

Text replies, seen receipts, typing, and interruption recovery are supported. No groups, attachments, or interactive approval dialogs. Keep normal host approval policy. Decrypted messages reach the selected agent and its model provider. One bridge/profile serves one channel instance.

## Build and test

```sh
cargo test --locked
cargo build --locked --target wasm32-wasip2 --release
```

Tested with Rust 1.99.0, ZeroClaw 0.8.7, and the released `wit/v0` contract pinned in the registry's `wit/UPSTREAM_REF`. The component exports `channel-plugin`; the pure core tests need no WASM runtime. Do not edit the vendored WIT. Build output is `iris_chat.wasm`; its SHA-256 and the exact source commit must accompany distribution. Follow ZeroClaw's manifest-signing process when publishing for strict installations.

Real-host tests use throwaway Iris identities, a local Nostr relay, a deterministic model, and a real file tool inside a network-disabled container. See [test instructions](https://github.com/irislib/iris-chat-channels/blob/main/tests/README.md).
