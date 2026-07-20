# aval-core

Shared pure-Rust Solana substrate for the **Aval** tool-plugin suite
([`nonce-vault-init`](../nonce-vault-init), [`durable-tx-build`](../durable-tx-build),
[`approval-recheck`](../approval-recheck)).

Not a plugin — a plain `rlib` consumed by the three components via path
dependency, with no wasm, HTTP, or WIT surface of its own. Everything here
runs under a host `cargo test` with zero toolchain setup.

## What it provides

- `codec` — hand-rolled base58 and base64 (no `bs58`, no `base64` crate)
- `pubkey` — 32-byte keys, well-known program ids, `createAccountWithSeed`
  derivation, PDA search with an ed25519 off-curve check, ATA derivation
- `instruction` — byte-exact encoders for the five system-program
  instructions the suite uses, SPL `TransferChecked`, ATA `CreateIdempotent`,
  and memo
- `message` — compact-u16, legacy message compilation (dedupe + runtime
  account ordering), unsigned-transaction serialization, and the reverse
  parser `approval-recheck` verifies bytes with
- `nonce` — the 80-byte durable nonce account layout
- `amount` — decimal-string ⇄ base-unit conversion in integer arithmetic
  (floating point never touches a money path)
- `rpc` — a five-method Solana JSON-RPC client behind an injectable
  `HttpPost` trait: host tests inject fixtures, wasm shims inject `waki`

## Why not solana-sdk

It does not compile for `wasm32-wasip2` inside a WIT component without a
fight, and the suite needs a page of byte layouts, not a runtime. The only
non-trivial dependency is `curve25519-dalek` (`default-features = false`)
because PDA derivation genuinely requires an off-curve check. Every layout
is pinned by byte-exact tests so drift is loud.

## License

MIT — see [LICENSE](LICENSE).
