# Live read-only SNS resolution

Date: 2026-07-18. Each case used `GET https://sdk-proxy.sns.id/resolve/<domain>` and then passed the actual JSON to `cargo run --example resolve_proxy`. No credentials, signing, or write request was used.

## `bonfida.sol`

Proxy response: `{"s":"ok","result":"Fw1ETanDZafof7xEULsnq9UY6o71Tpds89tNwPkWLb1v"}`

```text
SNS resolved
Domain: bonfida.sol
Wallet: Fw1ETanDZafof7xEULsnq9UY6o71Tpds89tNwPkWLb1v
Read-only lookup; verify recipient before any separate action.
```

Output: 16 whitespace tokens.

## `jupiter.sol`

Proxy response: `{"s":"ok","result":"BB1uSL6TUUWk3EQwiGFc4ZaBfy1ZKd4AHMefr1qT7AYq"}`

```text
SNS resolved
Domain: jupiter.sol
Wallet: BB1uSL6TUUWk3EQwiGFc4ZaBfy1ZKd4AHMefr1qT7AYq
Read-only lookup; verify recipient before any separate action.
```

Output: 16 whitespace tokens.

## `does-not-exist-zeroclaw-bounty-2026.sol`

Proxy response: `{"s":"error","result":"Domain not found"}`

Core result: `SNS resolution failed: SNS domain not found or has no resolvable wallet address`.

The failure is intentional and does not emit a fabricated address.
