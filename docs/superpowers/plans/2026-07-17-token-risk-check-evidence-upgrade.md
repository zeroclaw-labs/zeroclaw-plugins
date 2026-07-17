# Token Risk Check Evidence Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded owner-concentration and DEX-liquidity evidence to `token-risk-check`, then strengthen adversarial coverage and documentation without weakening T0 custody safety.

**Architecture:** Keep one WASM tool with a pure Rust assessment core and thin transport shim. Extend the fixed evidence sequence to three Solana RPC calls plus one fixed DEX Screener GET, validate every cross-response binding, and fail closed when any required evidence is malformed or unavailable.

**Tech Stack:** Rust 2021, serde/serde_json, bs58, url, waki 0.5.1, wit-bindgen 0.46, wasm32-wasip2, Cargo tests and Clippy.

## Global Constraints

- Keep custody tier T0: no keys, signatures, transaction construction, trading decisions, or transaction submission.
- Accept only `mint` from the model and only `__config.rpc_url` from host-injected config.
- Use JSON-RPC IDs 1, 2, and 3 for `getAccountInfo`, `getTokenLargestAccounts`, and `getMultipleAccounts` respectively.
- Use only `GET https://api.dexscreener.com/token-pairs/v1/solana/{mint}` for liquidity evidence.
- Make at most four sequential HTTPS requests, with no retry or fallback.
- Preserve current timeout, 1 MiB response-body, 64 KiB chunk, 8 KiB report, and 12-reason bounds.
- Green requires complete valid evidence, positive observed liquidity, and no Red or Amber rule.
- Never log mint, owner, endpoint, pair address, response body, or liquidity amount.

---

### Task 1: Build the bounded owner-evidence RPC request

**Files:**
- Modify: `plugins/token-risk-check/src/lib.rs`
- Modify: `plugins/token-risk-check/src/risk.rs`
- Test: `plugins/token-risk-check/tests/risk.rs`

**Interfaces:**
- Consumes: a validated `getTokenLargestAccounts` JSON-RPC response with ID 2.
- Produces: `pub const OWNER_ACCOUNTS_REQUEST_ID: u64 = 3` and `pub fn owner_accounts_request_body(largest_json: &str) -> Result<String, RiskError>`.

- [ ] **Step 1: Write failing request tests**

Add focused tests asserting that `owner_accounts_request_body` emits `getMultipleAccounts`, preserves the returned address order, uses `encoding: "jsonParsed"`, sets `minContextSlot` to the largest-accounts slot, rejects duplicate/invalid addresses, rejects more than 20 entries, and rejects response ID mismatch.

```rust
#[test]
fn owner_request_binds_addresses_and_slot() {
    let body = owner_accounts_request_body(include_str!("fixtures/dispersed-largest.json"))
        .expect("owner request");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["id"], OWNER_ACCOUNTS_REQUEST_ID);
    assert_eq!(json["method"], "getMultipleAccounts");
    assert_eq!(json["params"][1]["encoding"], "jsonParsed");
    assert_eq!(json["params"][1]["minContextSlot"], 250000000);
}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test --manifest-path plugins/token-risk-check/Cargo.toml owner_request -- --nocapture`

Expected: compilation fails because `OWNER_ACCOUNTS_REQUEST_ID` and `owner_accounts_request_body` do not exist.

- [ ] **Step 3: Implement the minimal request builder**

Add `address: String` to the strict largest-account evidence, validate every address with `validate_mint`, reject duplicates and counts outside `1..=20`, then serialize this exact request:

```rust
serde_json::json!({
    "jsonrpc": "2.0",
    "id": OWNER_ACCOUNTS_REQUEST_ID,
    "method": "getMultipleAccounts",
    "params": [addresses, {
        "encoding": "jsonParsed",
        "minContextSlot": largest.context.slot,
    }],
})
```

- [ ] **Step 4: Run focused and existing tests**

Run: `cargo test --manifest-path plugins/token-risk-check/Cargo.toml`

Expected: all tests pass with the fixture addresses updated to valid unique pubkeys.

- [ ] **Step 5: Commit**

```bash
git add plugins/token-risk-check/src/lib.rs plugins/token-risk-check/src/risk.rs plugins/token-risk-check/tests
git commit -m "feat(token-risk-check): bind owner evidence request"
```

### Task 2: Aggregate observed balances by owner

**Files:**
- Modify: `plugins/token-risk-check/src/risk.rs`
- Modify: `plugins/token-risk-check/tests/risk.rs`
- Create: `plugins/token-risk-check/tests/fixtures/owners-shared.json`
- Create: `plugins/token-risk-check/tests/fixtures/owners-dispersed.json`

**Interfaces:**
- Consumes: mint, token program, supply, largest-account address/amount pairs, and JSON-RPC ID 3 response.
- Produces: `Evidence.top_observed_owner_bps: Option<u16>`, `Slots.owner_accounts: u64`, Amber `TOP_OWNER_CONCENTRATED`, and limitation `OWNER_CONCENTRATION_TOP_ACCOUNTS_ONLY`.

- [ ] **Step 1: Write failing owner-aggregation tests**

Cover two accounts sharing one owner and totaling exactly 5,000 bps, distinct owners below threshold, null entries, wrong count/order binding, wrong mint, wrong token program, wrong amount, invalid owner, non-initialized account, reversed/excessive slot skew, and duplicate address evidence.

```rust
#[test]
fn shared_owner_at_half_supply_is_amber() {
    let report = assess(
        VALID_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        include_str!("fixtures/dispersed-largest.json"),
        include_str!("fixtures/owners-shared.json"),
    )
    .unwrap();
    assert_eq!(report.evidence.top_observed_owner_bps, Some(5000));
    assert!(report.reasons.iter().any(|r| r.code == "TOP_OWNER_CONCENTRATED"));
}
```

- [ ] **Step 2: Run owner tests and verify RED**

Run: `cargo test --manifest-path plugins/token-risk-check/Cargo.toml owner -- --nocapture`

Expected: compilation fails because `assess` does not accept the fourth owner-evidence argument and `Evidence` lacks `top_observed_owner_bps`. Liquidity remains out of this task and is added as the fifth argument in Task 3.

- [ ] **Step 3: Implement strict owner parsing and aggregation**

Parse ID 3 as ordered nullable account values. Require parsed type `account`, expected mint/program/state/amount, then aggregate with a `BTreeMap<String, u128>` and checked addition. Compute the maximum observed owner balance as basis points of supply and add the deterministic Amber rule at `>= 5_000`.

- [ ] **Step 4: Run all host tests**

Run: `cargo test --manifest-path plugins/token-risk-check/Cargo.toml`

Expected: all tests pass; malformed owner evidence returns the expected stable error instead of Green.

- [ ] **Step 5: Commit**

```bash
git add plugins/token-risk-check/src/risk.rs plugins/token-risk-check/tests
git commit -m "feat(token-risk-check): aggregate observed token owners"
```

### Task 3: Parse bounded DEX-liquidity evidence

**Files:**
- Create: `plugins/token-risk-check/src/liquidity.rs`
- Modify: `plugins/token-risk-check/src/lib.rs`
- Modify: `plugins/token-risk-check/src/risk.rs`
- Modify: `plugins/token-risk-check/tests/risk.rs`
- Create: `plugins/token-risk-check/tests/fixtures/liquidity-observed.json`
- Create: `plugins/token-risk-check/tests/fixtures/liquidity-empty.json`

**Interfaces:**
- Produces: `pub fn liquidity_url(mint: &str) -> Result<String, RiskError>` and `pub fn assess_liquidity(mint: &str, body: &str) -> Result<LiquidityEvidence, RiskError>`; malformed vendor evidence maps to stable `MALFORMED_LIQUIDITY_RESPONSE`.
- `LiquidityEvidence` contains status, pair count, maximum USD liquidity as a bounded decimal string, and source `dexscreener`.

- [ ] **Step 1: Write failing liquidity tests**

Cover fixed URL construction, positive observed pair, empty array, zero-liquidity pair, wrong chain, mint mismatch, missing liquidity, negative/non-finite number, invalid pair address, excessive pair count, oversized strings, deterministic maximum selection, and caller attempts to inject endpoint/query/path data through mint.

```rust
#[test]
fn positive_solana_pair_is_observed() {
    let evidence = assess_liquidity(VALID_MINT, include_str!("fixtures/liquidity-observed.json"))
        .unwrap();
    assert_eq!(evidence.status, LiquidityStatus::Observed);
    assert_eq!(evidence.max_liquidity_usd.as_deref(), Some("125000.5"));
}
```

- [ ] **Step 2: Run liquidity tests and verify RED**

Run: `cargo test --manifest-path plugins/token-risk-check/Cargo.toml liquidity -- --nocapture`

Expected: compilation fails because the liquidity module and interfaces do not exist.

- [ ] **Step 3: Implement the minimal strict parser**

Deserialize a top-level array with a hard maximum of 100 pairs. Require `chainId == "solana"`, the mint in base or quote token, a valid pair address, and a finite non-negative JSON Number in `liquidity.usd`. Reject number strings longer than 32 characters and serialize the selected `serde_json::Number` with `Number::to_string()`. Return `NotObserved` for an empty array or all-zero valid pairs.

- [ ] **Step 4: Integrate verdict and report fields**

Extend `assess` to consume liquidity JSON. Add Amber `LIQUIDITY_NOT_OBSERVED`, limitation `DEXSCREENER_COVERAGE_ONLY`, and report fields `liquidity_status`, `liquidity_pair_count`, `max_liquidity_usd`, and `liquidity_source`. Green requires `Observed`.

- [ ] **Step 5: Run all host tests and commit**

Run: `cargo test --manifest-path plugins/token-risk-check/Cargo.toml`

Expected: all tests pass.

```bash
git add plugins/token-risk-check/src plugins/token-risk-check/tests
git commit -m "feat(token-risk-check): add bounded liquidity evidence"
```

### Task 4: Extend the thin WASM transport flow

**Files:**
- Modify: `plugins/token-risk-check/src/lib.rs`
- Modify: `plugins/token-risk-check/tests/risk.rs`

**Interfaces:**
- Consumes: the primary two RPC responses, generated owner request, fixed liquidity URL, and all four bounded bodies.
- Produces: execute flow `POST account -> POST largest -> POST owners -> GET liquidity -> assess`.

- [ ] **Step 1: Write failing host-side transport construction tests**

Assert that the third request body has ID 3 and the DEX URL has fixed scheme/authority/path with no query, userinfo, fragment, or caller-controlled host.

- [ ] **Step 2: Run tests and verify RED**

Run: `cargo test --manifest-path plugins/token-risk-check/Cargo.toml request -- --nocapture`

Expected: tests fail because execute still makes only two requests and no fixed GET helper exists.

- [ ] **Step 3: Implement bounded GET and sequential execution**

Refactor the internal request sender to accept `Method::Post` with a JSON body or `Method::Get` without a body. Reuse all existing timeout and body bounds. Generate the owner request only after largest-account evidence passes request-level validation. Do not log URLs or bodies.

- [ ] **Step 4: Verify host and WASM targets**

Run:

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml
cargo build --manifest-path plugins/token-risk-check/Cargo.toml --target wasm32-wasip2 --release
```

Expected: host tests pass and the release component builds.

- [ ] **Step 5: Commit**

```bash
git add plugins/token-risk-check/src/lib.rs plugins/token-risk-check/tests/risk.rs
git commit -m "feat(token-risk-check): fetch complete bounded evidence"
```

### Task 5: Strengthen adversarial behavior and user-facing documentation

**Files:**
- Modify: `plugins/token-risk-check/tests/risk.rs`
- Modify: `plugins/token-risk-check/README.md`
- Modify: `plugins/token-risk-check/manifest.toml`

**Interfaces:**
- Produces: stable documented codes, updated threat model, worked example, and prompt-injection transcript matching production behavior.

- [ ] **Step 1: Add failing policy/document contract tests**

Assert stable serialization, Red-before-Amber ordering, unknown fallback after malformed owner/liquidity evidence, 8 KiB output bound, rejection of extra execute arguments, and documentation presence for `TOP_OWNER_CONCENTRATED`, `LIQUIDITY_NOT_OBSERVED`, `OWNER_CONCENTRATION_TOP_ACCOUNTS_ONLY`, and `DEXSCREENER_COVERAGE_ONLY`.

- [ ] **Step 2: Run tests and verify RED**

Run: `cargo test --manifest-path plugins/token-risk-check/Cargo.toml`

Expected: documentation/code contract tests fail until the README and stable-code tables are updated.

- [ ] **Step 3: Update README and manifest**

Document four requests, lower-bound owner semantics, DEX Screener trust/privacy/rate-limit boundary, no-liquidity limitations, new output fields, revised worked example, revised prompt-injection example, and all new stable codes. Keep the custody tier T0 and permissions limited to `http_client` and `config_read`.

- [ ] **Step 4: Run full quality gate**

Run:

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml
cargo fmt --manifest-path plugins/token-risk-check/Cargo.toml --check
cargo clippy --manifest-path plugins/token-risk-check/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/token-risk-check/Cargo.toml --target wasm32-wasip2 --release
cargo clippy --manifest-path plugins/token-risk-check/Cargo.toml --target wasm32-wasip2 --release -- -D warnings
```

Expected: every command exits 0 with no warnings.

- [ ] **Step 5: Commit**

```bash
git add plugins/token-risk-check
git commit -m "docs(token-risk-check): explain complete risk evidence"
```

### Task 6: Revalidate delivery and update external evidence

**Files:**
- Modify: `plugins/token-risk-check/README.md` only if live behavior exposes a documented discrepancy.
- Modify: Superteam submission and GitHub PR body through their supported interfaces.
- Create: a replacement demo release asset only if the visible output changed materially.

**Interfaces:**
- Produces: one mergeable upstream PR, current public demo, and Superteam submission that match the final commit.

- [ ] **Step 1: Rebase audit without rewriting unrelated history**

Run: `git fetch upstream main && git merge-base --is-ancestor upstream/main HEAD`

Expected: determine whether the branch already contains current upstream. If not, merge or rebase only after checking conflicts and rerun the full gate.

- [ ] **Step 2: Run a live bounded call with public mint data**

Use the existing local ZeroClaw test configuration without printing credentials. Confirm the tool performs four requests and returns owner/liquidity fields. Stop the bot immediately after the test.

- [ ] **Step 3: Inspect output and secrets**

Run repository secret scanning and inspect the final JSON for mint-independent logs, stable codes, bounded output, and truthful limitations.

- [ ] **Step 4: Push and update PR**

Push `codex/token-risk-check`, update PR #27 with the new evidence model and exact validation results, and verify the PR remains open and mergeable.

- [ ] **Step 5: Update demo and Superteam entry**

If the existing demo no longer represents the output, record a new sub-three-minute real Discord demo, publish it as a release asset, and edit the Superteam entry. Verify the authoritative submission receipt after saving.

- [ ] **Step 6: Record earnings-route status**

Update the money-maker daily activity log with the final commit, PR state, tests, demo URL, submission state, and next review action. Do not count any prize until payment is received.
