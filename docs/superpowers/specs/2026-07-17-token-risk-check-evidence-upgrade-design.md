# Token Risk Check Evidence Upgrade Design

## Goal

Improve the ZeroClaw `token-risk-check` bounty entry against the published judging criteria without weakening its T0 custody model. Add bounded owner-concentration evidence and observed DEX-liquidity evidence, then strengthen adversarial tests, output clarity, and documentation.

## Scope

This change keeps one read-only tool component. It does not hold keys, sign, build transactions, select trades, or accept caller-controlled endpoints, RPC methods, thresholds, or liquidity providers.

The tool will make four sequential bounded HTTPS requests:

1. Solana `getAccountInfo` for the requested mint, JSON-RPC ID 1.
2. Solana `getTokenLargestAccounts` for the same mint, JSON-RPC ID 2.
3. Solana `getMultipleAccounts` for the returned token-account addresses, JSON-RPC ID 3.
4. `GET https://api.dexscreener.com/token-pairs/v1/solana/{mint}`.

No retries or fallback providers are added.

## Owner Concentration

`getTokenLargestAccounts` returns at most 20 token accounts. The third RPC request will send those exact addresses to `getMultipleAccounts` with `encoding: jsonParsed` and `minContextSlot` equal to the mint-account slot.

The parser must require:

- response ID 3 and a bounded, non-reversed context slot;
- one non-null result for every requested address, in the same order;
- the expected SPL Token or Token-2022 program owner;
- parsed type `account`;
- parsed mint equal to the requested mint;
- initialized account state;
- parsed token amount equal to the corresponding largest-account amount;
- a valid 32-byte base58 owner.

Amounts are aggregated by owner with checked arithmetic. The report retains `top_account_bps` and adds `top_observed_owner_bps`. The latter is a lower bound derived only from the largest accounts returned by Solana, not a complete holder census. A value at or above 5,000 basis points produces Amber `TOP_OWNER_CONCENTRATED`.

The report always includes `OWNER_CONCENTRATION_TOP_ACCOUNTS_ONLY`. Any malformed, missing, contradictory, duplicate-address, or inconsistent-slot owner evidence returns Unknown rather than falling back to account-only Green.

## Liquidity Observation

The component will call DEX Screener's fixed Solana token-pairs endpoint. The mint is validated before being appended as one path segment, and no caller-controlled host or query is accepted.

The parser accepts only a top-level array. Every retained pair must:

- have `chainId` equal to `solana`;
- identify the requested mint as either base or quote token;
- contain valid non-negative finite `liquidity.usd` evidence;
- have bounded string fields and a valid base58 pair address.

The report adds:

- `liquidity_status`: `observed`, `not_observed`, or `unknown`;
- `liquidity_pair_count`;
- `max_liquidity_usd`, serialized as a bounded decimal string to avoid JSON floating-point ambiguity;
- `liquidity_source`: `dexscreener`.

At least one valid pair with positive USD liquidity yields `observed`. An empty valid response yields Amber `LIQUIDITY_NOT_OBSERVED`. Pairs with only zero liquidity also yield Amber. A malformed response, wrong-chain pair, mint mismatch, non-finite number, timeout, non-2xx response, or oversized body yields Unknown.

`DEXSCREENER_COVERAGE_ONLY` is always included. The README must state that observation proves only that DEX Screener indexed at least one qualifying pool at request time; absence is not proof that no on-chain liquidity exists.

## Verdict Policy

- Existing Red Token-2022 rules remain dominant.
- Existing Amber authority, extension, slot-skew, and account-concentration rules remain.
- Owner concentration and no observed liquidity add Amber reasons.
- Green requires complete valid evidence from all four requests, no Red or Amber rule, and positive observed liquidity.
- Any required evidence failure returns Unknown and never degrades to a partial Green.

Reasons remain deterministically ordered and bounded. Output remains capped at 8 KiB.

## Transport Bounds

All four requests reuse the existing connect, first-byte, between-byte, full-response, 1 MiB response, 64 KiB chunk, and no-retry limits. The DEX Screener request uses a fixed HTTPS authority and path prefix. Logs contain only verdict and stable codes, never mint, owner, RPC URL, pair address, response body, or liquidity amount.

## Test Strategy

Production behavior will be implemented test-first. New focused tests will cover:

- RPC request ID 3, exact address order, encoding, and `minContextSlot`;
- two token accounts owned by one wallet crossing the 50% threshold;
- distinct owners, duplicate token-account addresses, null entries, wrong mint, wrong token program, wrong amount, invalid owner, non-initialized account, reversed slot, and excessive slot skew;
- observed, empty, zero, malformed, wrong-chain, wrong-mint, missing-liquidity, negative, non-finite, oversized, and excessive-pair DEX responses;
- deterministic reason ordering, limitations, output-size fallback, and stable serialization;
- prompt-injected liquidity endpoint, method, threshold, or owner data rejected before network access;
- existing timeout, response-size, UTF-8, authority, Token-2022, and prompt-injection regressions.

The full completion gate is:

```text
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 --release -- -D warnings
```

The README, manifest description if needed, PR body, demo, and Superteam submission are updated only after all gates pass and the final branch remains mergeable.

## Non-Goals

- Full holder enumeration or identity attribution.
- Detecting every Solana DEX or proving absence of liquidity.
- LP lock, burn, ownership, price quality, slippage, market depth, or sellability guarantees.
- Trading advice, transaction construction, signing, or submission.
- Configurable external API hosts, retries, fallback APIs, or caller-selected thresholds.
