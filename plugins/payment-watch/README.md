# payment-watch

`payment-watch` is a **T0 (Read)**, stateless ZeroClaw tool. An agent or SOP
invokes it with an expected recipient, exact amount, mint, decimal precision,
and Solana Pay reference. The component reads recent transactions for the
recipient's associated token account and returns either `waiting` or a
structured `payment-received` event.

It has no private key and cannot sign, submit, or alter a transaction.

## Configuration

| Key | Default | Purpose |
| --- | --- | --- |
| `rpc_url` | `https://api.devnet.solana.com/` | JSON-RPC endpoint used for read-only transaction lookups. |

The only permissions are `http_client` and `config_read`. The RPC URL is read
from the component's jailed configuration section; no endpoint key is in code.

## SOP use

Run this tool from an agent turn or a live SOP source after issuing a Solana
Pay request. When the output has `status: "paid"`, send `event.message` to the
relevant chat or trigger the next workflow step. The WIT tool world is
stateless, so the host SOP—not the component—owns the schedule and notification
delivery. In the current ZeroClaw runtime, manual, MQTT, filesystem, and AMQP
SOP sources are live; cron triggers are defined but not yet wired to a live
event source.

```json
{
  "recipient": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
  "amount": "25.0",
  "decimals": 6,
  "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "reference": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
}
```

## Safety and threat model

All five expected payment values must match: recipient owner, mint, exact base
unit amount, decimals, and reference account. A transaction with the right
amount but no reference returns `waiting`; it does not produce a payment event.
Invalid input is rejected before any RPC call. The host-run prompt-injection
test uses an RPC implementation that panics if malformed reference data reaches
the network seam.

The plugin watches only the latest 20 transactions per invocation. An SOP that
runs infrequently should retain its own cursor or increase the lookback in a
future version. Token-2022 transfer-fee and transfer-hook accounting are not
yet supported and should be treated as non-matching until explicitly added.

## Build and test

```bash
cargo test --locked
cargo clippy --all-targets -- -D warnings
rustup target add wasm32-wasip2
cargo build --locked --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
cp target/wasm32-wasip2/release/payment_watch.wasm payment_watch.wasm
```

## License

MIT
