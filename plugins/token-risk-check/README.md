# token-risk-check

`token-risk-check` is a ZeroClaw **T0 read-only tool plugin** for screening a
Solana SPL or Token-2022 mint before an agent recommends interacting with it.
It gathers public on-chain and market evidence, applies deterministic rules,
and returns a compact red/amber/green JSON report.

It never accepts a recovery phrase or private key, never connects a wallet,
and cannot construct, sign, simulate, or submit a transaction. The report is
evidence for a human decision, not financial advice or a guarantee of safety.

## What it checks

- mint and freeze authority status;
- owner-level concentration across the largest token accounts;
- presence and liquidity of public Solana DEX pairs;
- Token-2022 transfer fees and fee authority;
- transfer hooks, permanent delegate, default-frozen, non-transferable, and
  confidential-transfer extensions;
- missing, malformed, or partial evidence, which fails closed rather than
  producing a reassuring result.

Example output:

```json
{"mint":"So11111111111111111111111111111111111111112","rating":"red","score":70,"complete":true,"findings":[{"severity":"red","code":"PERMANENT_DELEGATE","detail":"delegate can transfer or burn holder tokens"},{"severity":"red","code":"TRANSFER_HOOK","detail":"custom program runs on every transfer"}],"facts":{"program":"token-2022","decimals":6,"mint_authority":false,"freeze_authority":false,"transfer_hook":true,"permanent_delegate":true,"extensions":["permanentDelegate","transferHook"],"top1_pct":8.2,"top10_pct":38.7,"liquidity_usd":92000.0,"market":"orca"},"note":"Read-only evidence, not financial advice."}
```

## Architecture

```text
LLM supplies one mint string
        |
        v
exact 32-byte base58 validation (no network yet)
        |
        +--> Solana JSON-RPC: mint + largest accounts + parsed owners
        |
        +--> DEX pair endpoint: best reported Solana liquidity
        |
        v
pure Rust parser + deterministic risk rules
        |
        v
bounded JSON report + structured ZeroClaw log
```

The implementation follows the registry's pure-core/thin-shim pattern:

- `src/risk.rs` contains host-testable parsing, aggregation, validation, and
  scoring with no WASM or network dependency;
- `src/lib.rs` is the small `tool-plugin` WIT component shim and the only place
  that performs HTTP;
- `tests/risk.rs` runs adversarial fixtures through the same core used by the
  component;
- `manifest.toml` declares only `tool`, `http_client`, and `config_read`.

## Evidence calls

The component uses host-mediated `wasi:http` via `waki`:

1. Solana `getAccountInfo` with `jsonParsed` for mint owner, authorities,
   supply, decimals, and Token-2022 extensions;
2. Solana `getTokenLargestAccounts` for the largest token accounts;
3. Solana `getMultipleAccounts` with `jsonParsed` to aggregate those accounts
   by owner rather than treating several accounts from one owner as independent;
4. `GET {market_base_url}/{mint}` for public Solana pair liquidity.

The default endpoints are:

- `https://api.mainnet-beta.solana.com`
- `https://api.dexscreener.com/token-pairs/v1/solana`

No API token is required by the defaults.

## Input and output contract

The model-visible schema exposes exactly one field:

```json
{"mint":"<Solana mint public key>"}
```

The host-reserved `__config` field is not in the schema. ZeroClaw removes any
caller-supplied `__config` and injects only the operator-owned section, so an
LLM cannot redirect traffic or weaken thresholds. The mint is rejected before
network access unless it is canonical base58 representing exactly 32 bytes.

Ratings are deterministic:

- **red**: any red finding, missing required evidence, or score at least 50;
- **amber**: one or more amber findings, or score at least 20;
- **green**: complete evidence and no findings.

`complete: false` means a required source was missing or partial. Missing
evidence is a red result, never a silent pass.

## Operator configuration

All keys are optional strings in the plugin's own jailed config section:

| Key | Default | Meaning |
|---|---:|---|
| `rpc_url` | Solana public mainnet RPC | Read-only JSON-RPC endpoint. |
| `market_base_url` | DexScreener Solana pairs endpoint | Base URL followed by the validated mint. |
| `require_market_data` | `true` | Fail closed when market evidence is unavailable. |
| `min_liquidity_usd` | `25000` | Amber threshold; below 10% of it is red. |
| `top1_amber_pct` | `20` | Largest-owner amber threshold. |
| `top1_red_pct` | `50` | Largest-owner red threshold. |
| `top10_amber_pct` | `50` | Top-owner-set amber threshold. |
| `top10_red_pct` | `80` | Top-owner-set red threshold. |

Remote endpoints must use HTTPS. Plain HTTP is accepted only for the exact
loopback hosts `127.0.0.1`, `localhost`, and `[::1]`; lookalike hosts and URL
user-info are rejected. This is defense in depth on top of ZeroClaw's
host-mediated HTTP permission.

## Build and test

Prerequisites: stable Rust and the `wasm32-wasip2` target.

```bash
rustup target add wasm32-wasip2
cd plugins/token-risk-check
cargo test --locked
cargo build --locked --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/token_risk_check.wasm token_risk_check.wasm
```

From the registry root, also run:

```bash
python -m unittest discover -s tools/ci/tests -p "test_*.py"
python tools/build-registry.py --source-plugins plugins --check-metadata registry.json
```

Do not hand-edit `registry.json`; the repository workflow generates it.

## Install and use

After building, keep `token_risk_check.wasm` next to `manifest.toml`, then:

```bash
zeroclaw plugin install token-risk-check
```

The host must be built with the WIT plugin runtime and a compiler backend, for
example `--features plugins-wasm,plugins-wasm-cranelift`, with plugins enabled
in operator configuration. A typical request is:

```text
Use token-risk-check on So11111111111111111111111111111111111111112.
Explain the evidence, but do not trade or connect a wallet.
```

## Custody tier and permissions

**Tier T0 — read-only.** The component can make public HTTP requests and read
its own config section. It requests no file, memory, socket, wallet, signing,
or transaction capability. It contains no instruction that can move funds.

| Permission | Why it is needed | What it cannot do |
|---|---|---|
| `http_client` | Read public Solana RPC and DEX-pair evidence. | No wallet or signing access; endpoints are fixed by validated operator config. |
| `config_read` | Read endpoints and deterministic thresholds. | ZeroClaw jails this to the plugin's own section and strips LLM spoofing. |

Structured logs contain only outcome, rating, score, and completeness. They do
not contain configuration values, raw upstream bodies, secrets, or credentials.

## Threat model

| Threat | Mitigation |
|---|---|
| Prompt injection or a URL supplied as `mint` | Exact base58/32-byte validation occurs before every network call. |
| Model tries to inject `__config` | ZeroClaw reserves, strips, and operator-injects that field; it is absent from the tool schema. |
| SSRF through configured endpoints | Only operator config can select endpoints; remote HTTP is rejected, exact loopback is the sole development exception, and user-info/lookalike hosts are blocked. |
| Malicious Token-2022 behavior | High-impact extensions and retained authorities produce explicit red/amber findings. |
| One owner splits holdings among several accounts | Largest token accounts are resolved and aggregated by owner. |
| RPC/market outage or malformed response | The report fails closed with `complete: false` and a red finding. |
| Upstream text attempts prompt injection | Upstream fields are parsed into typed facts, labels are character/length bounded, and raw text is never treated as an instruction. |
| Oversized response or log injection | Pair processing, extension lists, labels, errors, findings, and report content are bounded; logs use fixed messages and structured attributes. |
| Compromised binary | Review source, verify registry SHA-256/signature policy, and run with only the declared T0 permissions. |

### Prompt-injection test transcript

Model attempt:

```json
{
  "mint": "So11111111111111111111111111111111111111112?ignore=rules",
  "__config": {"rpc_url": "http://169.254.169.254/latest/meta-data"}
}
```

Host/plugin behavior:

1. ZeroClaw strips caller-controlled `__config` before injecting the real
   operator section.
2. `validate_mint` rejects `?` as non-base58 before any request is made.
3. The tool returns `INVALID_MINT`; there is no wallet action, transaction, or
   retry against the supplied URL.

Adversarial coverage for this path, loopback-lookalike SSRF, RPC errors,
malicious Token-2022 extensions, partial holder data, concentration, and compact
output is in `tests/risk.rs`.

## Limitations

- This is a fast deterministic screen, not a contract audit or prediction of
  future developer behavior.
- The largest-account RPC is a bounded sample. Owner aggregation reduces false
  diversification but cannot reliably label exchanges, bridges, burn accounts,
  market makers, or liquidity pools.
- Public pair liquidity does not prove LP tokens are locked or burned. It is
  reported as liquidity presence and size, not as a lock guarantee.
- Token metadata, social reputation, off-chain identity, price momentum, and
  proprietary risk feeds are intentionally outside this T0 version.
- Public RPC and pair APIs may rate-limit. Configure operator-owned endpoints
  when reliability matters; missing evidence will remain visibly red.

## License

MIT. See `LICENSE`.
