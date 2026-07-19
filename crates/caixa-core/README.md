# caixa-core

Track E substrate for Caixa ZeroClaw plugins — **no `solana-sdk`**.

| Module | Role |
|--------|------|
| `rpc` | JSON-RPC over `RpcTransport` / `MockTransport`; wasm uses `waki` |
| `pay` | Solana Pay transfer-request URLs |
| `quote` | BRL→USDC via injected HTTP GET |
| `spl` / `tx` | ATA, memo, transfer-checked, advance-nonce, legacy unsigned tx |
| `output` | Soft cap so tools never flood the model |

```
pure core (host `cargo test`)     wasm-only
  encode · pay · quote · spl        WakiTransport · WakiHttpGet
  MockTransport · MockHttpGet
```

Proven by: `caixa-charge`, `caixa-transfer-build`, `caixa-watch`.

```bash
cargo test
```

See **[CAIXA.md](../../CAIXA.md)**. Dual-licensed: [LICENSE-MIT](LICENSE-MIT) / [LICENSE-APACHE](LICENSE-APACHE).
