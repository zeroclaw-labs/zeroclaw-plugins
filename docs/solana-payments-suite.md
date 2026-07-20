# Solana Payments Suite for ZeroClaw

Track A plugins for the Superteam bounty: **safe Solana hands** for a self-hosted agent.

One component = one tool. Depth over breadth. Custody is explicit.

| Plugin | Tool name | Tier | Role |
|--------|-----------|------|------|
| [`solana-pay-request`](../plugins/solana-pay-request/) | `solana_pay_request` | **T1** | Build Solana Pay URL / QR (charge) |
| [`payment-watch`](../plugins/payment-watch/) | `payment_watch` | **T0** | Confirm payment landed (close invoice) |
| [`spl-transfer-build`](../plugins/spl-transfer-build/) | `spl_transfer_build` | **T1** | Unsigned SPL transfer for human/Squads sign |
| [`x402-settle`](../plugins/x402-settle/) | `x402_settle` | **T2** | Session-key x402 settle with hard rails |

## Recommended flows

### A. Payment terminal (T0 + T1 only — prize sweet spot)

```
User: "Charge table 4 for 25 USDC"
  → solana_pay_request  (URL + QR, no keys)
User pays in wallet
  → payment_watch       (reference + amount match)
Agent: "Invoice paid ← 25 USDC from …"
```

### B. Settlement proposal (T1)

```
Agent proposes payout
  → spl_transfer_build  (unsigned base64 tx + summary)
Human / Squads / approval gate signs and submits
```

### C. Agent-to-machine commerce (T2 — optional, high bar)

```
Agent needs paywalled API
  → x402_settle(url, approval=<token>)
Rails: max_amount, daily_cap, mint/payee allowlist, approval gate, session key only
```

Use a **tiny session wallet** for T2. Never a main wallet.

## Custody ladder (honest)

| Tier | Plugins | Secrets | Signs? |
|------|---------|---------|--------|
| T0 | payment-watch | RPC key at most | No |
| T1 | solana-pay-request, spl-transfer-build | RPC key at most | No |
| T2 | x402-settle | Scoped **session** key + approval token | Yes |

Prompt injection must **fail closed** — each plugin README has a transcript.

## Layout (each plugin)

```
plugins/<name>/
  Cargo.toml       # cdylib + rlib, MIT, standalone [workspace]
  manifest.toml    # name, version, wasm_path, capabilities, permissions
  README.md        # custody, config, threat model, injection test
  LICENSE          # MIT
  src/<core>.rs    # pure logic (host-testable)
  src/lib.rs       # #[cfg(target_family = "wasm")] shim
  tests/           # cargo test, mocked RPC/HTTP
```

Matches the canonical [`redact-text`](../plugins/redact-text/) layout.

## Build all

Windows (GNU toolchain if MSVC `link.exe` is missing):

```powershell
# from repo root
.\scripts\package-solana-payments.ps1
```

Manual per plugin:

```powershell
$tc = "+stable-x86_64-pc-windows-gnu"
foreach ($p in @("solana-pay-request","payment-watch","spl-transfer-build","x402-settle")) {
  Push-Location "plugins\$p"
  cargo $tc test
  cargo $tc build --target wasm32-wasip2 --release
  $wasm = Get-ChildItem "target\wasm32-wasip2\release\*.wasm" | Select-Object -First 1
  Copy-Item $wasm.FullName -Destination (Join-Path (Get-Location) $wasm.Name) -Force
  Pop-Location
}
```

Linux/macOS:

```bash
./scripts/package-solana-payments.sh
```

Artifacts land next to each `manifest.toml` as `wasm_path` names, and a zip under `dist/solana-payments-suite/` (gitignored).

## Install (local ZeroClaw)

1. Build/package (above).
2. Enable plugins in ZeroClaw config:

```toml
[plugins]
enabled = true
```

3. Copy each plugin directory (with `manifest.toml` + `.wasm`) into your plugins dir, **or** point install at the packaged folders.
4. Merge operator config from [`config.example.toml`](./solana-payments-config.example.toml).
5. Run a host that includes a wasm plugin backend (e.g. `plugins-wasm` / `plugins-wasm-cranelift` as documented upstream).

## Permissions summary

| Plugin | permissions |
|--------|-------------|
| solana-pay-request | `config_read` |
| payment-watch | `http_client`, `config_read` |
| spl-transfer-build | `http_client`, `config_read` |
| x402-settle | `http_client`, `config_read` |

Minimal by design. No sockets. No unrestricted sign API beyond the T2 session path inside the component.

## Hard requirements checklist

- [x] Layout matches `redact-text`
- [x] Pure core + thin wasm shim (`cdylib` + `rlib`)
- [x] Host `cargo test` (mocked network)
- [x] `cargo build --target wasm32-wasip2 --release`
- [x] Structured logging import (no secret dumps)
- [x] `manifest.toml` complete
- [x] README: custody, config, threat model, worked example, injection transcript
- [x] MIT License
- [x] T2: caps + allowlists + approval gate + session key only

## Submission notes

1. PR to [zeroclaw-labs/zeroclaw-plugins](https://github.com/zeroclaw-labs/zeroclaw-plugins) containing these plugin directories + this doc  
2. Demo video ≤ 3 min — prefer Flow A (pay request + watch) on Telegram  
3. Superteam Earn form + this write-up  

## wasm32-wasip2 lessons (for judges)

- Avoided `solana-sdk` / `solana-client` inside components  
- JSON-RPC over host `wasi:http` (`waki`)  
- Hand-rolled legacy tx wire format + PDA (`sha2`, `curve25519-dalek`)  
- T2 signing via `ed25519-dalek` on session key only  
- Output shaped for the model (~hundreds of tokens, not raw RPC dumps)

## License

MIT — see each plugin `LICENSE`.
