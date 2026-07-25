# solana-core-wasi

The Solana substrate for ZeroClaw WIT plugins: everything a payment tool
needs on `wasm32-wasip2`, where `solana-sdk` and `solana-client` do not
compile (tokio, sockets, ring). Pure Rust, no wasm dependency anywhere, so
the whole crate tests on the host with a plain `cargo test` and compiles
identically inside a component.

Ships with three plugins built on top of it in this repo:
`spl-transfer-build` (unsigned transfers under policy, durable-nonce mode),
`payment-watch` (Solana Pay reference settlement checks) and `nonce-status`
(durable nonce account health).

## Modules

| module | what it gives you |
| --- | --- |
| `pubkey` | base58 pubkeys, well-known program IDs, PDA + ATA derivation |
| `encoding` | compact-u16 ("short vec"), strict base64 |
| `instruction` | system transfer, SPL `transferChecked`, ATA create-idempotent, memo, durable-nonce trio (advance / create / initialize), Solana Pay reference attachment |
| `message` | legacy message compilation with correct key ordering, unsigned-transaction envelopes |
| `nonce` | 80-byte durable nonce account state parsing, fail-closed on every tag |
| `amount` | exact decimal arithmetic, string in, base units out, no floats ever |
| `pay` | Solana Pay transfer-request URLs per the maintained spec |
| `rpc` | JSON-RPC bodies + strict parsers for the five calls payment flows need |
| `policy` | fail-closed operator policy: allowlists + per-mint caps the model cannot argue with |

## Ground truth, not folklore

Every byte layout here was verified against independent sources before it
became code, and the receipts are pinned as tests:

- The Solana Pay spec's own example transaction decodes and re-encodes
  **byte-exact** through `message::compile_legacy`
  (`spec_example_transaction_byte_exact`).
- compact-u16 vectors are lifted from `solana-sdk/short-vec`'s test suite.
- The canonical (wallet, USDC) ATA derivation vector matches mainnet
  (`ata_derivation_mainnet_vector`).
- The durable-nonce domain hash (`sha256("DURABLE_NONCE" || blockhash)`) is
  pinned against the constant in `solana-sdk/nonce`.
- The full instruction set (transfer, transferChecked, create-idempotent,
  memo, advance-nonce, create+initialize nonce) was simulated on devnet with
  `err: null` during development; the structural invariants live in
  `tests/vectors.rs` and the end-to-end proof (component output accepted by
  devnet `simulateTransaction`) runs in the host repo's e2e suite.

## Design rules

- **No floats.** Amounts travel as decimal strings and convert with the
  mint's decimals via checked integer arithmetic. `9007199.254740993` at 9
  decimals is not representable in an `f64`; it is exact here.
- **Fail closed everywhere.** Unknown config keys, unknown nonce tags, bad
  base58, truncated data, RPC error envelopes: every branch returns an error,
  never a guess. Empty allowlist means deny all, not allow all.
- **Transport-agnostic.** `rpc` builds request bodies and parses responses;
  it never talks to the network. Components plug in `waki`, host tests plug
  in fixtures, and the parsers cannot tell the difference.
- **Shape the output.** Parsers extract the fields a model needs and drop the
  rest; a tool built on this crate returns a line, not a payload.

## Dependency posture

`serde`/`serde_json`, `bs58`, `sha2`, `curve25519-dalek` (off-curve checks
for PDA derivation; already in the tree via ed25519 everywhere Solana goes).
No `getrandom` anywhere in the graph
(`cargo tree --target wasm32-wasip2 -i getrandom` resolves to nothing), no
sockets, no tokio, no borsh (the system program is bincode-style fixed
layouts; SPL programs use single-byte discriminants).

## License

MIT.
