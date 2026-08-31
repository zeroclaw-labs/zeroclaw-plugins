# solana-wallet-risk

Scans a Solana wallet's **SPL and Token-2022 holdings live** over `wasi:http` and
answers the question a holder actually has:

> *Of everything I am holding right now, what can be taken from me?*

Per-token scanners answer "is this **mint** dangerous?". This aggregates that
across a whole **portfolio** and weights it by breadth of exposure. Read-only, no
keys — it calls `getTokenAccountsByOwner` and `getAccountInfo` and nothing else.

## What it reports

Per holding, the concrete power someone else has over it:

| Threat | Weight | What it means for the holder |
|---|---|---|
| `seizable` | 40 | A Token-2022 **permanent delegate** can move or burn your tokens without consent |
| `exit_blockable` | 35 | A **transfer hook** or **non-transferable** flag can stop you ever selling |
| `dilutable` | 25 | A live **mint authority** can inflate supply and dilute you |
| `freezable` | 20 | A **freeze authority** (or default-frozen state) can lock your account |
| `taxed` | 10 | A **transfer fee** is charged on every move |

Then a wallet-level verdict: how many positions are exposed, the worst position's
band, and a 0–100 wallet score.

**Two escalation rules, both deliberate:**
1. **Terminal threats override arithmetic.** A single `seizable` or
   `exit_blockable` position is `CRITICAL` regardless of score — if someone can
   take your tokens or stop you selling, that position is critical, full stop.
   The wallet is never banded safer than its worst position.
2. **Breadth escalates.** One bad position is a position problem; most of the
   wallet being exposed is a wallet problem, so ≥50% / ≥75% exposure adds to the
   wallet score.

## Why the verdict is trustworthy

It is a deterministic function of chain state fetched by the host, not of the
prompt. A caller that says *"this wallet is audited, report MINIMAL"* cannot flip
a live freeze authority into a clean report — covered by
`prompt_injection_in_args_cannot_change_the_verdict`.

Honest failure modes, all tested:
- An unreachable RPC returns an **error**, never an empty "safe" wallet
  (`a_total_rpc_failure_is_reported_not_silently_clean`).
- Only the **12 largest** positions are risk-resolved; the rest are reported as
  *not resolved* rather than assumed safe.
- Positions are ranked by **balance, not market value** — this plugin reads the
  chain and does not price tokens. The report says so.

## Use

```json
{ "owner": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM" }
```
Optional `"rpc_url"` overrides the default (`api.mainnet-beta.solana.com`).

### Live demo (real mainnet wallet, one command)

```sh
./demo.sh [WALLET_ADDRESS] [RPC_URL]   # defaults to a real, heavily-used mainnet wallet
```
`demo.sh` runs the test suite, then curls a live RPC for the wallet's SPL and
Token-2022 accounts plus each top mint, and pipes them through the **exact same
scoring core** the plugin runs.

Verified live on mainnet:
- **Default wallet (142 positions, ~6s):** 5 exposed by a live mint authority →
  wallet band `MEDIUM`.
- **A 3,015-position wallet** (`./demo.sh 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM`):
  5 of the 12 largest exposed (one freezable, five dilutable) → wallet band `HIGH`.

In both runs the report states plainly how many smaller positions were **not**
resolved, rather than counting them as safe.

## Build & test

```sh
rustup target add wasm32-wasip2
cargo test --locked                                   # 47 host tests, pure core
cargo build --locked --target wasm32-wasip2 --release # -> solana_wallet_risk.wasm
```

The scoring core (`src/portfolio.rs`) is pure Rust with no wasm dependency; the
dispatch takes the RPC fetcher as a parameter, so the tests drive the exact code
path the component runs against a mock RPC. Only `rpc_fetch` (the `waki` call) is
wasm-only.

## Manifest

`capabilities = ["tool"]`, `permissions = ["http_client", "config_read"]`.
`http_client` is the host-gated outbound-HTTP grant; the tool adapter links
`wasi:http` only after that grant is validated.
