# token-risk-check

`token-risk-check` is a ZeroClaw **T0 read-only tool plugin** for screening a
Solana SPL or Token-2022 mint before an agent recommends interacting with it.
It gathers public on-chain and market evidence, applies deterministic rules,
and returns a compact red/amber/green JSON report.

**Submission status:** the post-hardening release has been rebuilt and exercised
in a ZeroClaw 0.8.3 host against live Solana RPC, DexScreener, and GoPlus
evidence. Its final WASM digest and reproducible host result are recorded below.
The remaining bounty artifact is a short real Telegram or Discord channel
recording; the earlier slide-based demo is not submission evidence.

It never accepts a recovery phrase or private key, never connects a wallet,
and cannot construct, sign, simulate, or submit a transaction. The report is
evidence for a human decision, not financial advice or a guarantee of safety.

## What it checks

- mint and freeze authority status;
- owner-level concentration across the largest token accounts;
- presence and liquidity of public Solana DEX pairs;
- LP lock/burn evidence for the highest-TVL pool reported by the default
  GoPlus Solana token-security source;
- Token-2022 transfer fees and fee authority;
- transfer hooks, permanent delegate, default-frozen, non-transferable,
  confidential-transfer, pausable, permissioned-burn, and scaled-UI-amount
  extensions;
- unknown Token-2022 extensions, which are surfaced as unassessed and prevent
  a complete green report;
- missing, malformed, or partial evidence, which fails closed rather than
  producing a reassuring result.

Illustrative output shape (not the final live-capture result):

```json
{"mint":"<validated-mint>","rating":"amber","score":15,"complete":true,"findings":[{"severity":"amber","code":"LP_PARTIALLY_LOCKED","detail":"only part of the observed LP position is locked or burned"}],"facts":{"program":"spl-token","decimals":9,"mint_authority":false,"freeze_authority":false,"transfer_hook":false,"permanent_delegate":false,"pausable_authority":false,"paused":false,"permissioned_burn_authority":false,"scaled_ui_amount_authority":false,"unassessed_extensions":[],"top1_pct":8.2,"top10_pct":38.7,"liquidity_usd":92000.0,"market":"orca","lp_status":"partially_locked","lp_burned_pct":40.0,"lp_locked_pct":0.0,"lp_pool_type":"standard","lp_evidence_source":"goplus"},"note":"Read-only evidence, not financial advice."}
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
        +--> GoPlus: LP lock/burn evidence for the highest-TVL pool
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
4. `GET {market_base_url}/{mint}` for public Solana pair liquidity;
5. `GET {security_base_url}?contract_addresses={mint}` for LP lock/burn
   evidence associated with the requested mint.

Every outbound request has a 10-second connection timeout, and every response
body is streamed through a hard 1 MiB limit before JSON parsing.
Largest-account addresses must be valid and unique, the parsed account count
must match the request, every parsed holder account must name the requested
mint, DEX pairs must contain the requested mint, and the LP-security result
must be keyed by the requested mint. For a single standard pool, locked share
is derived from locked holder balances divided by the pool's `lp_amount`; the
provider's raw `percent` field is not trusted. Multi-pool holder evidence and
unknown pool types remain unknown/incomplete because GoPlus does not expose a
pool id on each LP-holder record. A mismatch is rejected rather than silently
scored.

The default endpoints are:

- `https://api.mainnet-beta.solana.com`
- `https://api.dexscreener.com/token-pairs/v1/solana`
- `https://api.gopluslabs.io/api/v1/solana/token_security`

No API token is required by the current defaults.

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

`complete: false` means a required source was missing, partial, or could not be
fully assessed. Missing required evidence is a red result, never a silent pass.

LP status uses the highest-TVL reported pool's type and burn percentage plus
the response's locked LP-holder percentages. At least 95% burned or locked is
treated as established evidence. A partial lock/burn is amber; observed zero
lock/burn is red. Concentrated-liquidity pools are amber and incomplete because
fungible LP-token control cannot be established from those fields. Unknown or
missing required LP status is red and incomplete. Token-2022 hook/delegate
findings require a present controlling value; unknown extension types are
listed as unassessed and prevent a complete green report.

## Operator configuration

All keys are optional strings in the plugin's own jailed config section:

| Key | Default | Meaning |
|---|---:|---|
| `rpc_url` | Solana public mainnet RPC | Read-only JSON-RPC endpoint. |
| `rpc_fallback_url` | unset | Optional read-only RPC retried when the primary returns a network, HTTP, JSON, or JSON-RPC error. |
| `market_base_url` | DexScreener Solana pairs endpoint | Base URL followed by the validated mint. |
| `security_base_url` | GoPlus Solana token-security endpoint | Base URL queried with the validated mint for LP lock/burn evidence. |
| `require_market_data` | `true` | Fail closed when market evidence is unavailable. |
| `require_lp_status` | `true` | Fail closed when LP lock/burn evidence is unavailable or cannot be established. |
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
cargo fmt --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo clippy --target wasm32-wasip2 -- -D warnings
cargo build --locked --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/token_risk_check.wasm token_risk_check.wasm
```

From the registry root, also run:

```bash
python -m unittest discover -s tools/ci/tests -p "test_*.py"
python tools/build-registry.py --source-plugins plugins --check-metadata registry.json
```

Do not hand-edit `registry.json`; the repository workflow generates it.

### What fought us on `wasm32-wasip2`

The component cannot rely on a native HTTP stack. Network access stays in the
small WIT shim and uses host-mediated `wasi:http` through the WASM-only `waki`
dependency, while all parsing and scoring remain native-testable Rust. Response
bodies are read in 64 KiB chunks so the 1 MiB limit is enforced before JSON
allocation. The final artifact must be built for `wasm32-wasip2`, copied next
to `manifest.toml`, and loaded by a ZeroClaw host built with the WIT plugin
runtime plus a compiler backend.

### Deterministic offline demo

The demo executable exercises the same scoring core as the component with
green, malicious Token-2022, and missing-evidence fixtures. It makes no network
request and needs no key or wallet:

```bash
cargo run --locked --example demo -- green
cargo run --locked --example demo -- red
cargo run --locked --example demo -- incomplete
```

The 18 host tests exercise mint validation, endpoint validation, authority and
Token-2022 parsing, holder/account cardinality and mint binding, market-pair
mint binding, LP-security parsing, response-size enforcement, deterministic
ratings, and compact output. The release component wires the same parsers to
host-mediated `wasi:http`.

### Final pre-submission evidence

The post-hardening release was rebuilt and exercised in a ZeroClaw 0.8.3 host
on 2026-07-22:

- release WASM: **442,725 bytes**;
- SHA-256:
  `537A0D594A4308DE66B5C3F1C7D336671D8E75EA9D1386441BD29A3DF09F64A5`;
- model-selected tool call: **1 native / 1 parsed**;
- evidence sources reached by the component: live Solana RPC, DexScreener, and
  GoPlus Solana token security;
- the exact tool result was returned to the model on its second turn:

```json
{"mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","rating":"red","score":70,"complete":false,"findings":[{"severity":"red","code":"MINT_AUTHORITY_ACTIVE","detail":"supply can still be increased"},{"severity":"amber","code":"FREEZE_AUTHORITY_ACTIVE","detail":"token accounts can be frozen"},{"severity":"amber","code":"LP_POSITION_CONTROL_UNVERIFIED","detail":"the largest pool uses concentrated positions; lock control is unverified"}],"facts":{"program":"spl-token","decimals":6,"mint_authority":true,"freeze_authority":true,"transfer_hook":false,"permanent_delegate":false,"pausable_authority":false,"paused":false,"permissioned_burn_authority":false,"scaled_ui_amount_authority":false,"unassessed_extensions":[],"top1_pct":11.6,"top10_pct":33.9,"liquidity_usd":14994072.0,"market":"pumpswap","lp_status":"concentrated_position","lp_pool_type":"Concentrated","lp_evidence_source":"goplus"},"note":"Read-only evidence, not financial advice."}
```

The real Telegram channel path was authenticated and exercised end to end on
2026-07-22: a Telegram user sent the canonical USDC mint, ZeroClaw selected this
WASM tool, live evidence returned, and the second-turn answer was delivered to
Telegram. The remaining bounty artifact is a new continuous public recording,
no longer than three minutes, that visibly proves that full sequence. The
earlier slide-based player is not final proof. Live concentration and liquidity
values naturally change between runs. If any required source fails, the report
remains visibly incomplete/red rather than inventing evidence.

## Install and use

`token-risk-check` is not in the public registry before this pull request is
merged and its release asset is published. For pre-merge testing, build the
component, keep `token_risk_check.wasm` next to `manifest.toml`, and copy that
directory into the host's configured plugins directory. For example:

```bash
PLUGIN_DIR=/path/to/configured/plugins/token-risk-check
mkdir -p "$PLUGIN_DIR"
cp manifest.toml token_risk_check.wasm LICENSE "$PLUGIN_DIR/"
```

Only after the registry contains the published version will this command be
valid:

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
| `http_client` | Read public Solana RPC, DEX-pair, and LP-security evidence. | No wallet or signing access; endpoints are fixed by validated operator config. |
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
| RPC, market, or LP-security outage or malformed response | Required evidence fails closed with `complete: false` and a red finding. |
| Cross-mint or truncated evidence | Largest-account addresses are validated and deduplicated; account cardinality and holder/market/security mint bindings are enforced. |
| Upstream text attempts prompt injection | Upstream fields are parsed into typed facts, labels are character/length bounded, and raw upstream error text is discarded rather than returned to the model. |
| Oversized response or log injection | Every HTTP body has a 1 MiB hard cap; pair processing, extension lists, labels, findings, and report content are bounded; logs use fixed messages and structured attributes. |
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
malicious and unknown Token-2022 extensions, partial or cross-mint holder data,
duplicate/malformed largest accounts, cross-mint market and LP evidence,
response-size enforcement, concentration, and compact output is in
`tests/risk.rs`.

## Limitations

- This is a fast deterministic screen, not a contract audit or prediction of
  future developer behavior.
- The largest-account RPC is a bounded sample. Owner aggregation reduces false
  diversification but cannot reliably label exchanges, bridges, burn accounts,
  market makers, or liquidity pools.
- DexScreener liquidity and GoPlus LP evidence are separate signals. The
  default GoPlus Solana token-security endpoint is a third-party beta source;
  the plugin evaluates its highest-TVL reported pool, and an outage or malformed
  response fails closed when `require_lp_status` is enabled.
- Concentrated-liquidity positions do not map cleanly to fungible LP-token
  lock/burn percentages, so they are explicitly reported as unverified and
  prevent a complete green result.
- Token metadata, social reputation, off-chain identity, price momentum, and
  proprietary risk feeds are intentionally outside this T0 version.
- Public RPC, pair, and LP-security APIs may rate-limit. Configure
  operator-owned endpoints when reliability matters; required missing evidence
  will remain visibly red.

## License

MIT. See `LICENSE`.
