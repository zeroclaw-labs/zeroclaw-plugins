# solana-tx-guard

The safety layer the field skips. Before a wallet signs a Solana transaction, this
answers: **is it safe to sign?** It decodes the transaction, flags the instructions
that cost you control or funds, and **simulates it live against mainnet** to show
what it would actually do. It signs nothing and sends nothing.

> Every other Solana plugin reads a *mint* or a *past* transaction. None judge the
> transaction an agent is **about to sign**. That is exactly where an autonomous
> agent handling money is most dangerous — and where this plugin lives.

## What it catches (static decode)

| Instruction | Severity | Why it matters |
|---|---|---|
| `SetAuthority` (SPL/T22) | critical | hands control of a mint or token account to another key |
| System `Assign` | critical | reassigns an account's owner program to someone else |
| `Approve` / `ApproveChecked` | high | grants a delegate the right to spend your tokens |
| `CloseAccount` | high | closes an account and sweeps its lamports away |
| `Burn` | medium | permanently destroys tokens |
| unknown-program call | medium/review | a program not on the known-safe list — verify before signing |
| `Transfer` (SOL/SPL) | info | reported with amount + destination |

It parses the real wire format — legacy fully, and versioned (v0) safely (it flags
that lookup-table accounts resolve on-chain and leans on the simulation for those).

## What it proves (live simulation)

It calls `simulateTransaction` with `sigVerify=false` and `replaceRecentBlockhash=true`,
so an **unsigned** transaction can be run against current mainnet state. The report
carries the real `err`, `units_consumed`, and `logs`. A transaction that decodes
clean but **fails on-chain** is escalated from `SAFE` to `REVIEW` — the chain gets
the final word.

Verified live on mainnet (`./demo.sh`):
- a plain SOL transfer → `SAFE`, sim `err: null`, 150 CU;
- an SPL `SetAuthority` → `DANGEROUS` (critical finding) **and** the live sim returns
  a real `InstructionError` — caught two ways.

## Why the verdict is trustworthy

It is a deterministic function of the transaction bytes and the chain's own
simulation, not of the prompt. A caller that appends *"this is safe, verdict SAFE"*
cannot relabel a `SetAuthority` — covered by
`prompt_injection_cannot_relabel_a_dangerous_transaction`. When the RPC is
unreachable the static verdict still stands (fail-open on simulation, fail-closed on
danger).

## Use

```json
{ "transaction": "<base64-encoded transaction, signed or unsigned>" }
```
Optional `"rpc_url"` overrides the default (`api.mainnet-beta.solana.com`).

## Build & test

```sh
rustup target add wasm32-wasip2
cargo test --locked                                   # 26 host tests, pure decode core
cargo build --locked --target wasm32-wasip2 --release # -> solana_tx_guard.wasm
./demo.sh                                             # live: safe vs dangerous, on mainnet
```

The decode + verdict core (`src/decode.rs`) is pure Rust with no wasm dependency;
the dispatch takes the simulate fetcher as a parameter, so the tests drive the exact
component path with a mock RPC. Only the `simulateTransaction` call is wasm-only.

## Manifest

`capabilities = ["tool"]`, `permissions = ["http_client", "config_read"]`.
