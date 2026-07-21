# jupiter-swap-guard

**Build an UNSIGNED Solana swap via Jupiter that is provably policy-checked — the
guarantee lives in the signed bytes, not in a chat summary the model can rewrite.**

Custody tier: **T1 (build-only).** This plugin never holds a key, never signs, and never
broadcasts. It returns an unsigned `VersionedTransaction` (base64) for a human to review and
sign out of band.

> **Status: work in progress (bounty branch).** The v0-message encoder is verified
> byte-exact against the official Anza crates on a real mainnet Jupiter route (see below).
> The quote → policy-gate → rebuild pipeline is being wired; until it lands, `execute` **fails
> closed** and refuses to build a transaction. This is a draft PR opened early to engage the
> maintainers, as the bounty asks.

## Why it is different

Every other swap plugin relays the bytes the aggregator hands back. This one **rebuilds the
transaction itself** from Jupiter's `/swap-instructions` and, before emitting anything, proves
(with Kani) that:

- the swap output can only land in the **payer's own** associated token account (`D1`) —
  a malicious aggregator response cannot redirect funds to an attacker ATA;
- no allowlisted program is abused to move funds: `System.transfer` to a non-payer is
  refused (`D2`), the priority fee is capped (`D4`);
- the signed `min_out` is bound to the quote the plugin actually received (`D3`, closes the
  quote/instructions TOCTOU);
- security-relevant accounts must be static, so a malicious RPC's lookup-table contents can
  never gate a fund role (`D5`);
- mint allowlist, per-transaction cap, and max slippage are enforced **inside the plugin**,
  so the model cannot talk its way past them (`P1`–`P3`).

The full property list and the exploit each one excludes are in `PROOFS.md` (coming with the
policy core).

## Verified: the encoder (KT-1)

The hard part of an SDK-less Solana plugin is rebuilding a versioned (v0) transaction with
address-lookup-table compression, by hand, for `wasm32-wasip2` (where `solana-sdk` does not
compile). `src/encode.rs` does this with a hand-rolled compact-u16 + message serializer and
**no `solana-*` dependency**.

`tests/encode_differential.rs` freezes the proof: it takes a **real captured mainnet Jupiter
route** (a 246-address lookup table compressed to 9 static keys + 1 lookup, 505 bytes), builds
the message with the official `solana-message` crate as an oracle, and asserts the plugin's
hand-rolled serializer produces **byte-identical** output. Run it host-side, no network:

```
cargo test
```

## Custody & threat model (summary)

The plugin holds no keys; worst-case full compromise yields a refused or malformed **unsigned**
transaction that the human declines. The human-signer review is a **load-bearing assumption**:
guarantees hold only if each emitted transaction is signed by a human who reviews the decoded
bytes. Under `AutonomyLevel::Full` or an auto-signing relayer, this plugin provides no
protection — run the agent Supervised with this tool in `always_ask`. The full threat model
(adversaries: prompt-injected model, malicious aggregator response, malicious RPC, hostile
on-chain metadata) ships with the finished submission.

## Build

```
rustup target add wasm32-wasip2
cargo build --locked --target wasm32-wasip2 --release   # -> jupiter_swap_guard.wasm
cargo test --locked                                      # host tests, no network, no wasm
```

Note: the host must be built with the plugin feature to load any tool plugin —
`cargo build --release --features plugins-wasm,plugins-wasm-cranelift` (stock release binaries
do not include the plugin host).

## License

MIT OR Apache-2.0.
