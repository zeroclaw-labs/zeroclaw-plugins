# Solana DePIN + Core ZeroClaw Plugins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Track E `solana-core` substrate plus two Track C tools (`depin-attest` T1, `depin-uptime-watch` T0) that build clean for `wasm32-wasip2`, fail closed under prompt injection, and are merge-ready for `zeroclaw-labs/zeroclaw-plugins`.

**Architecture:** Pure Rust cores with zero WIT/waki deps; thin `#[cfg(target_family = "wasm")]` shims. Upstream CI snapshots only `plugins/<name>` + `wit/v0`, so each plugin vendors an identical copy of the core at `src/vendor/solana_core/`. Canonical source lives at repo-root `solana-core/` for Track E visibility, kept in sync by `tools/sync-solana-core.sh`.

**Tech Stack:** Rust 2021 / toolchain matching upstream (`1.96.1`), `wit-bindgen 0.46`, `serde`/`serde_json`, wasm-only `waki 0.5.1`, hand-rolled Solana wire encoding (no `solana-sdk`), SHA-256 via `sha2`, base58 via `bs58`, base64 via `base64`.

**Spec:** `docs/superpowers/specs/2026-07-22-solana-depin-zeroclaw-design.md`

## Global Constraints

- Custody: T0/T1 only — no private keys, no `sendTransaction`, no T2 path in any crate.
- Permissions: only `http_client` and `config_read` when needed.
- Layout must match `plugins/redact-text` (standalone `[workspace]`, `cdylib`+`rlib`, pure module + wasm shim).
- Host tests: `cargo test` with mocked HTTP — no live network.
- Build: `cargo build --target wasm32-wasip2 --release` must succeed for both plugins.
- Logging: WIT `log-record` only — never stdout/stderr from components.
- Config: `rpc_url` required and operator-supplied; never hardcode a keyed endpoint.
- Fail closed: unknown JSON fields refuse; config-only `payer`/`nonce_account`; empty `allowed_metrics` authorizes nothing.
- Output shaping: chat-facing strings budget-tested (attest summary ≤ 1200 chars; watch ≤ 800 chars).
- License: MIT on all new crates.
- Do not put a non-tool crate under `plugins/` (CI requires `manifest.toml` per plugin dir).

---

## File structure (locked)

```
solana-core/                          # Track E canonical crate (NOT under plugins/)
  Cargo.toml
  LICENSE
  README.md
  src/lib.rs
  src/error.rs
  src/keys.rs
  src/shape.rs
  src/ix.rs
  src/nonce.rs
  src/tx.rs
  src/rpc.rs
  tests/*.rs

plugins/depin-attest/
  Cargo.toml
  Cargo.lock
  LICENSE
  README.md
  manifest.toml
  src/lib.rs                          # wasm shim + re-exports
  src/attest.rs                       # pure policy + orchestration
  src/vendor/solana_core/             # synced copy of solana-core/src
  tests/attest.rs
  tests/injection.rs

plugins/depin-uptime-watch/
  Cargo.toml
  Cargo.lock
  LICENSE
  README.md
  manifest.toml
  src/lib.rs
  src/watch.rs
  src/vendor/solana_core/
  tests/watch.rs
  tests/injection.rs

tools/sync-solana-core.sh             # copies solana-core/src → both vendor trees
docs/superpowers/specs/...            # already committed
wit/v0/                               # from upstream fork — do not modify
```

---

### Task 1: Bootstrap fork workspace

**Files:**
- Create: clone/fork checkout into this working tree (or sibling worktree)
- Create: `tools/sync-solana-core.sh`
- Create: `solana-core/Cargo.toml`, `solana-core/src/lib.rs`, `solana-core/LICENSE`, `solana-core/README.md`

**Interfaces:**
- Consumes: upstream `zeroclaw-labs/zeroclaw-plugins` main
- Produces: empty `solana-core` crate that `cargo test` passes; sync script that mirrors `solana-core/src` into plugin vendor dirs

- [ ] **Step 1: Clone upstream plugins repo as the implementation base**

If this workspace stays empty of plugin sources, clone into the project (or replace contents) so `wit/v0` and `plugins/redact-text` exist:

```bash
cd /Users/dell/Downloads/Projects/solana-zeroclaw-plugin
git clone https://github.com/zeroclaw-labs/zeroclaw-plugins.git zeroclaw-plugins-work
# Prefer: fork on GitHub first, then clone your fork and add upstream remote.
```

Keep the design/plan docs either in this Untitled repo or copy them into the work clone under `docs/superpowers/`. Preferred: do all plugin work inside the forked `zeroclaw-plugins` clone; leave the design/plan in Untitled or copy both.

- [ ] **Step 2: Create canonical `solana-core` skeleton**

`solana-core/Cargo.toml`:

```toml
[package]
name = "solana-core"
version = "0.1.0"
edition = "2021"
license = "MIT"
description = "Wasm32-wasip2-friendly Solana substrate: JSON-RPC trait, base58, memo/tx encode, durable nonce"
publish = false

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
bs58 = "0.5"
base64 = "0.22"
sha2 = "0.10"
thiserror = "2"

[dev-dependencies]
serde_json = "1"

[profile.release]
opt-level = "s"
lto = true
strip = true
codegen-units = 1
overflow-checks = true

[workspace]
```

`solana-core/src/lib.rs`:

```rust
//! Pure Solana substrate for ZeroClaw wasm tool plugins.
//! No wit-bindgen, waki, or solana-sdk.

pub mod error;
pub mod ix;
pub mod keys;
pub mod nonce;
pub mod rpc;
pub mod shape;
pub mod tx;

pub use error::{CoreError, CoreResult};
```

`solana-core/src/error.rs`:

```rust
use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("{0}")]
    Msg(String),
}

impl CoreError {
    pub fn msg(m: impl Into<String>) -> Self {
        Self::Msg(m.into())
    }
}
```

Stub empty modules (`keys.rs`, `shape.rs`, `ix.rs`, `nonce.rs`, `tx.rs`, `rpc.rs`) with `// placeholder` so the crate compiles.

- [ ] **Step 3: Add sync script**

`tools/sync-solana-core.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/solana-core/src"
for dest in \
  "$ROOT/plugins/depin-attest/src/vendor/solana_core" \
  "$ROOT/plugins/depin-uptime-watch/src/vendor/solana_core"
do
  mkdir -p "$dest"
  rsync -a --delete --exclude 'vendor' "$SRC/" "$dest/"
done
echo "synced solana-core → plugin vendor trees"
```

`chmod +x tools/sync-solana-core.sh`

- [ ] **Step 4: Verify skeleton**

Run: `cargo test --manifest-path solana-core/Cargo.toml`
Expected: PASS (0 tests ok)

- [ ] **Step 5: Commit**

```bash
git add solana-core tools/sync-solana-core.sh
git commit -m "chore: scaffold solana-core and vendor sync script"
```

---

### Task 2: `solana-core` keys + shape

**Files:**
- Modify: `solana-core/src/keys.rs`, `solana-core/src/shape.rs`, `solana-core/src/lib.rs`
- Test: `solana-core/tests/keys_shape.rs`

**Interfaces:**
- Consumes: `CoreError`
- Produces:
  - `keys::Pubkey` with `from_base58(s: &str) -> CoreResult<Pubkey>`, `to_base58(&self) -> String`, `as_bytes(&self) -> &[u8; 32]`
  - `shape::truncate(s: &str, max_chars: usize) -> String`
  - `shape::assert_budget(s: &str, max_chars: usize) -> CoreResult<()>`

- [ ] **Step 1: Write failing tests**

`solana-core/tests/keys_shape.rs`:

```rust
use solana_core::keys::Pubkey;
use solana_core::shape::{assert_budget, truncate};

#[test]
fn pubkey_roundtrip_system_program() {
    // System Program: 11111111111111111111111111111111
    let s = "11111111111111111111111111111111";
    let pk = Pubkey::from_base58(s).expect("decode");
    assert_eq!(pk.to_base58(), s);
    assert_eq!(pk.as_bytes(), &[0u8; 32]);
}

#[test]
fn pubkey_rejects_bad_base58() {
    assert!(Pubkey::from_base58("!!!").is_err());
}

#[test]
fn truncate_and_budget() {
    assert_eq!(truncate("abcdef", 3), "abc");
    assert!(assert_budget("hi", 10).is_ok());
    assert!(assert_budget("hello world", 5).is_err());
}
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `cargo test --manifest-path solana-core/Cargo.toml --test keys_shape`
Expected: FAIL (module/items missing or stub)

- [ ] **Step 3: Implement**

`solana-core/src/keys.rs`:

```rust
use crate::{CoreError, CoreResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pubkey([u8; 32]);

impl Pubkey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_base58(s: &str) -> CoreResult<Self> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| CoreError::msg(format!("invalid base58 pubkey: {e}")))?;
        if bytes.len() != 32 {
            return Err(CoreError::msg(format!(
                "pubkey must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }
}
```

`solana-core/src/shape.rs`:

```rust
use crate::{CoreError, CoreResult};

pub fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

pub fn assert_budget(s: &str, max_chars: usize) -> CoreResult<()> {
    if s.chars().count() > max_chars {
        Err(CoreError::msg(format!(
            "output exceeds budget ({max_chars} chars)"
        )))
    } else {
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `cargo test --manifest-path solana-core/Cargo.toml --test keys_shape`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add solana-core
git commit -m "feat(solana-core): add pubkey base58 and output shape helpers"
```

---

### Task 3: Memo instruction + compact-u16 + legacy message encode

**Files:**
- Modify: `solana-core/src/ix.rs`, `solana-core/src/tx.rs`
- Test: `solana-core/tests/memo_tx.rs`

**Interfaces:**
- Consumes: `Pubkey`
- Produces:
  - `ix::MEMO_PROGRAM_ID: Pubkey` (MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr)
  - `ix::memo_instruction(payer: &Pubkey, memo: &str) -> Instruction` where `Instruction { program_id, accounts: Vec<AccountMeta>, data: Vec<u8> }`
  - `tx::encode_legacy_message(header, account_keys, blockhash, instructions) -> Vec<u8>`
  - `tx::encode_unsigned_legacy_tx(message: &[u8], num_required_signatures: u8) -> Vec<u8>` (compact array of empty signatures + message)
  - `tx::to_base64(bytes: &[u8]) -> String`

Pinned Memo program id: `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`

- [ ] **Step 1: Write failing tests**

```rust
use solana_core::ix::{memo_instruction, MEMO_PROGRAM_ID};
use solana_core::keys::Pubkey;
use solana_core::tx::{encode_legacy_message, encode_unsigned_legacy_tx, to_base64};

#[test]
fn memo_program_id_decodes() {
    assert_eq!(
        MEMO_PROGRAM_ID.to_base58(),
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
    );
}

#[test]
fn memo_ix_data_is_utf8_bytes() {
    let payer = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
    let ix = memo_instruction(&payer, "hello");
    assert_eq!(ix.data, b"hello");
    assert_eq!(ix.program_id, MEMO_PROGRAM_ID);
    assert_eq!(ix.accounts.len(), 1);
}

#[test]
fn unsigned_tx_roundtrips_base64() {
    let payer = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
    let ix = memo_instruction(&payer, "ZCDEPIN|test");
    let blockhash = [7u8; 32];
    let msg = encode_legacy_message(
        /* num_required_signatures */ 1,
        /* num_readonly_signed */ 0,
        /* num_readonly_unsigned */ 1, // memo program
        &[payer, MEMO_PROGRAM_ID],
        &blockhash,
        &[ix],
    );
    let tx = encode_unsigned_legacy_tx(&msg, 1);
    assert_eq!(tx[0], 1); // compact-u16 length of signatures = 1
    let b64 = to_base64(&tx);
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &b64,
    )
    .unwrap();
    assert_eq!(decoded, tx);
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo test --manifest-path solana-core/Cargo.toml --test memo_tx`
Expected: FAIL

- [ ] **Step 3: Implement compact-u16, AccountMeta, memo ix, legacy message**

Implement in `ix.rs` / `tx.rs`:

- Compact-u16 encode for lengths (Solana shortvec).
- `AccountMeta { pubkey: Pubkey, is_signer: bool, is_writable: bool }`.
- Memo ix: program = MemoSq4…, accounts = `[AccountMeta { pubkey: payer, is_signer: true, is_writable: false }]`, data = memo UTF-8 bytes.
- Legacy message: header (3 bytes) + shortvec keys + 32-byte blockhash + shortvec instructions (each: program_id_index u8, shortvec account indices, shortvec data).
- Unsigned tx: shortvec of `num_required_signatures` zeroed 64-byte signatures + message bytes.
- `to_base64` using `base64::engine::general_purpose::STANDARD`.

Document in `solana-core/README.md` that legacy messages were chosen first for wasip2 simplicity; v0 can be added later if needed.

- [ ] **Step 4: Run — expect PASS**

Run: `cargo test --manifest-path solana-core/Cargo.toml --test memo_tx`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add solana-core
git commit -m "feat(solana-core): memo instruction and unsigned legacy tx encode"
```

---

### Task 4: Durable nonce account parse + advance+memo message

**Files:**
- Modify: `solana-core/src/nonce.rs`, `solana-core/src/tx.rs`, `solana-core/src/ix.rs`
- Test: `solana-core/tests/nonce.rs`

**Interfaces:**
- Consumes: `Pubkey`, memo ix helpers
- Produces:
  - `nonce::NONCE_ACCOUNT_SIZE` / parse: `parse_nonce_account(data: &[u8]) -> CoreResult<NonceState>`
  - `NonceState { authority: Pubkey, durable_nonce: [u8; 32], fee_calculator_lamports_per_signature: u64 }` for initialized state only
  - `ix::advance_nonce_instruction(nonce_account: &Pubkey, authority: &Pubkey) -> Instruction` (System Program `AdvanceNonceAccount` = index 4)
  - `tx::build_durable_memo_tx(payer, nonce_account, authority, durable_nonce, memo) -> CoreResult<Vec<u8>>` — message uses durable nonce as recent blockhash; instructions = `[advance_nonce, memo]`

Nonce account layout (initialized): version u32 + state u32 + authority 32 + durable_nonce 32 + fee lamports_per_signature u64 (little-endian). Reject non-initialized states.

- [ ] **Step 1: Write failing tests with fixture bytes**

Build a minimal 80+ byte fixture in the test (hand-written LE fields) for an initialized nonce; assert authority/nonce roundtrip; assert `build_durable_memo_tx` places durable nonce bytes at the message blockhash offset and includes two instructions.

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement parse + advance ix + builder**

System program id: `11111111111111111111111111111111`.  
`AdvanceNonceAccount` accounts: nonce (writable), recent_blockhashes sysvar (readonly), authority (signer).  
Recent blockhashes sysvar: `SysvarRecentB1ockHashes11111111111111111111`.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add solana-core
git commit -m "feat(solana-core): durable nonce parse and advance+memo tx builder"
```

---

### Task 5: Injectable JSON-RPC client

**Files:**
- Modify: `solana-core/src/rpc.rs`
- Test: `solana-core/tests/rpc_mock.rs`

**Interfaces:**
- Consumes: `Pubkey`, `NonceState`
- Produces:

```rust
pub trait HttpClient {
    fn post_json(&self, url: &str, body: &serde_json::Value) -> CoreResult<serde_json::Value>;
}

pub struct Rpc<'a, H: HttpClient> {
    pub url: &'a str,
    pub http: &'a H,
}

impl<'a, H: HttpClient> Rpc<'a, H> {
    pub fn get_account_data(&self, pubkey: &Pubkey) -> CoreResult<Vec<u8>>;
    pub fn get_nonce(&self, nonce_account: &Pubkey) -> CoreResult<NonceState>;
    pub fn get_signatures_for_address(
        &self,
        address: &Pubkey,
        limit: usize,
    ) -> CoreResult<Vec<SignatureInfo>>;
    pub fn get_transaction_memo(&self, signature: &str) -> CoreResult<Option<ParsedMemoTx>>;
}

pub struct SignatureInfo {
    pub signature: String,
    pub block_time: Option<i64>,
    pub err: Option<serde_json::Value>,
}

pub struct ParsedMemoTx {
    pub signature: String,
    pub block_time: Option<i64>,
    pub memo: String,
}
```

`get_account_data` calls `getAccountInfo` with `encoding=base64`, decodes data.  
`get_nonce` wraps parse.  
`get_signatures_for_address` uses `getSignaturesForAddress`.  
`get_transaction_memo` uses `getTransaction` jsonParsed (or base64+manual) and extracts UTF-8 memo from Memo program ix if present.

- [ ] **Step 1: Write mock HTTP client tests**

```rust
struct MapHttp {
    // url+body fingerprint -> response
    responses: std::collections::HashMap<String, serde_json::Value>,
}
```

Stub responses for account info (nonce fixture), signatures list, and a tx containing a memo string. Assert parse paths and error on RPC `error` object.

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `rpc.rs`**

Refuse empty `url`. Map serde/transport failures to `CoreError::msg` short strings. Never return raw 40KB blobs to callers — memo extraction returns only the memo string + metadata.

- [ ] **Step 4: Run — expect PASS**

Run: `cargo test --manifest-path solana-core/Cargo.toml`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add solana-core
git commit -m "feat(solana-core): injectable JSON-RPC client with mockable HTTP"
```

---

### Task 6: `depin-attest` pure policy + memo payload

**Files:**
- Create: `plugins/depin-attest/Cargo.toml`, `src/lib.rs`, `src/attest.rs`, `tests/attest.rs`, `tests/injection.rs`, `manifest.toml`, `LICENSE`, `README.md` (stub)
- Create: vendor tree via sync script
- Modify: `tools/sync-solana-core.sh` targets must exist

**Interfaces:**
- Consumes: vendored `solana_core` modules
- Produces:

```rust
pub struct AttestConfig { /* from HashMap<String,String> */ }
pub struct AttestArgs { device_id, reading: f64, unit, metric, memo_prefix: Option<String> }

pub fn parse_args_strict(json: &str) -> Result<AttestArgs, String>; // unknown fields err
pub fn AttestConfig::from_section(map: &HashMap<String,String>) -> Result<AttestConfig, String>;
pub fn format_reading(v: f64) -> String; // max 6 dp, trim trailing zeros
pub fn period_bucket(unix_secs: u64) -> u64; // / 300
pub fn attestation_hash(device_id, metric, reading_str, unit, period) -> String; // sha256 hex
pub fn build_memo(prefix, device_id, metric, reading_str, unit, period, hash12) -> Result<String, String>;
pub fn validate_policy(cfg: &AttestConfig, args: &AttestArgs) -> Result<(), String>;
```

Default allowlist when `allowed_metrics` absent: `temperature,humidity,uptime,pressure,air_quality`.  
Present-but-empty CSV → error `"allowed_metrics is empty"`.  
`max_abs_reading` default e.g. `1_000_000.0` if unset.

- [ ] **Step 1: Scaffold plugin crate**

`Cargo.toml` mirrors `redact-text` + deps: `serde`, `serde_json`, `sha2`, `bs58`, `base64`, `thiserror`; wasm-only `waki`.  
`lib.rs`:

```rust
pub mod attest;
#[path = "vendor/solana_core/mod.rs"]
pub mod solana_core; // after sync, ensure vendor has mod.rs = lib.rs content renamed

#[cfg(target_family = "wasm")]
mod component { /* empty for now */ }
```

Because vendored tree is `solana-core/src/*` with `lib.rs`, the sync script should also write `mod.rs` that is a copy of `lib.rs` **or** the plugin uses:

```rust
#[path = "vendor/solana_core/lib.rs"]
mod solana_core;
```

Prefer `#[path = "vendor/solana_core/lib.rs"] mod solana_core;` so sync stays a straight file copy.

Update sync script to create parent dirs; run it after scaffolding empty plugin dirs.

- [ ] **Step 2: Write failing policy/hash tests**

Cover: hash stability, period bucket, reading format, allowlist refuse, empty allowlist refuse, unknown JSON field refuse, args containing `payer`/`private_key` refuse, memo length refuse if device_id huge.

- [ ] **Step 3: Run — expect FAIL**

- [ ] **Step 4: Implement `attest.rs` policy + memo builders (no RPC yet)**

- [ ] **Step 5: Run — expect PASS**

Run: `cargo test --manifest-path plugins/depin-attest/Cargo.toml`
Expected: policy tests PASS

- [ ] **Step 6: Commit**

```bash
./tools/sync-solana-core.sh
git add plugins/depin-attest tools/sync-solana-core.sh
git commit -m "feat(depin-attest): pure policy, memo payload, injection refusals"
```

---

### Task 7: `depin-attest` execute path (mock RPC → unsigned tx)

**Files:**
- Modify: `plugins/depin-attest/src/attest.rs`
- Test: `plugins/depin-attest/tests/attest.rs`, `tests/injection.rs`

**Interfaces:**
- Produces:

```rust
pub struct AttestOutput {
    pub summary: String,
    pub unsigned_tx_base64: String,
    pub attestation_hash: String,
    pub nonce_account: String,
    pub durability: &'static str, // "durable-nonce"
}

pub fn execute<H: solana_core::rpc::HttpClient>(
    args_json: &str,
    config: &HashMap<String, String>,
    http: &H,
    now_unix: u64,
) -> Result<AttestOutput, String>;
```

Flow: parse_args_strict → config → validate_policy → RPC get_nonce → verify authority == config.payer → build_memo → build_durable_memo_tx → shape summary → assert_budget(summary, 1200).

Summary format (pinned):

```
DEPIN attest OK
device: {device_id}
metric: {metric}={reading_str} {unit}
period: {period}
hash: {hash12}…
nonce: {nonce_account}
durability: durable-nonce
unsigned_tx_base64: {b64}
```

- [ ] **Step 1: Write failing execute + injection tests with MapHttp mock**

Injection cases (must match README transcript later):

1. args include `"private_key":"..."` → refuse  
2. args include `"payer":"..."` → refuse  
3. `reading: 1e99` above cap → refuse  
4. metric `drain_wallet` → refuse  
5. successful path returns durability `durable-nonce` and summary under budget  

Also: wrong nonce authority → refuse.

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `execute`**

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add plugins/depin-attest
git commit -m "feat(depin-attest): mockable execute builds durable unsigned memo tx"
```

---

### Task 8: `depin-attest` wasm shim + manifest

**Files:**
- Modify: `plugins/depin-attest/src/lib.rs`
- Create/overwrite: `plugins/depin-attest/manifest.toml`
- Modify: `plugins/depin-attest/Cargo.toml` (wasm deps)

**Interfaces:**
- Tool export name: `depin_attest`
- Plugin name: `depin-attest`
- Wasm adapter: `waki::Client` implements `HttpClient` only under `cfg(wasm)`

- [ ] **Step 1: Implement component module mirroring `redact-text`**

```rust
#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });
    // PluginInfo + Tool impls calling attest::execute with WakiHttp
    // log_record on success/failure
    // now_unix: use wasi clocks if available, else require config `now_unix` for deterministic tests only on host — on wasm use std::time if wasi supports it.
}
```

For wasm time: use `std::time::{SystemTime, UNIX_EPOCH}` (works on wasip2). Host tests pass `now_unix` explicitly into `execute`.

`manifest.toml`:

```toml
name = "depin-attest"
version = "0.1.0"
description = "Build an unsigned durable-nonce Solana memo attestation from a device sensor reading (T1)"
author = "Superteam Brasil bounty submission"
wasm_path = "depin_attest.wasm"
capabilities = ["tool"]
permissions = ["http_client", "config_read"]
```

Ensure `[profile.release] overflow-checks = true`.

- [ ] **Step 2: Generate lockfile and host-test**

```bash
cargo test --manifest-path plugins/depin-attest/Cargo.toml
cargo generate-lockfile --manifest-path plugins/depin-attest/Cargo.toml
```

- [ ] **Step 3: Wasm build**

```bash
rustup target add wasm32-wasip2
cargo build --manifest-path plugins/depin-attest/Cargo.toml --target wasm32-wasip2 --release
```

Expected: success; artifact under `target/wasm32-wasip2/release/depin_attest.wasm` (or cdylib name from package). Adjust `wasm_path` to match actual artifact filename (underscores vs hyphens).

- [ ] **Step 4: Clippy**

```bash
cargo clippy --manifest-path plugins/depin-attest/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path plugins/depin-attest/Cargo.toml --target wasm32-wasip2 -- -D warnings
```

- [ ] **Step 5: Commit**

```bash
git add plugins/depin-attest
git commit -m "feat(depin-attest): WIT shim, manifest, wasm32-wasip2 build"
```

---

### Task 9: `depin-uptime-watch` pure core + tests

**Files:**
- Create: full `plugins/depin-uptime-watch/` tree (mirror attest scaffolding)
- Create: `src/watch.rs`, `tests/watch.rs`, `tests/injection.rs`

**Interfaces:**

```rust
pub struct WatchConfig { rpc_url, payer, max_age_secs, memo_prefix, scan_limit }
pub struct WatchArgs { device_id, max_age_secs: Option<u64> }

pub enum Verdict { Ok, Stale, Missing }

pub struct WatchOutput {
    pub summary: String,
    pub verdict: Verdict,
    pub age_secs: Option<u64>,
}

pub fn execute<H: HttpClient>(
    args_json: &str,
    config: &HashMap<String, String>,
    http: &H,
    now_unix: u64,
) -> Result<WatchOutput, String>;
```

Logic: parse strict args (reject `payer`/`private_key`/unknown) → load config (payer+rpc required) → `get_signatures_for_address(payer, scan_limit)` → for each success sig, `get_transaction_memo` → keep newest memo matching prefix + device_id → compute age → OK/STALE/MISSING → summary ≤ 800 chars.

- [ ] **Step 1: Scaffold + sync vendor + failing tests (OK/STALE/MISSING + injection)**

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `watch.rs`**

- [ ] **Step 4: Wasm shim + manifest (`depin-uptime-watch`, tool `depin_uptime_watch`, permissions same)**

- [ ] **Step 5: `cargo test` + wasm build + clippy**

- [ ] **Step 6: Commit**

```bash
./tools/sync-solana-core.sh
git add plugins/depin-uptime-watch
git commit -m "feat(depin-uptime-watch): T0 freshness watch with shaped verdicts"
```

---

### Task 10: Docs, threat model, wiring diagram, Track E README

**Files:**
- Modify: `solana-core/README.md`
- Modify: `plugins/depin-attest/README.md`
- Modify: `plugins/depin-uptime-watch/README.md`
- Create: `plugins/depin-attest/docs/wiring-diagram.md` (or embed ASCII/Mermaid in README)

**Required README sections (each plugin):**

1. What it does  
2. Config keys table  
3. Custody tier + why  
4. Threat model  
5. Worked example  
6. Prompt-injection transcript (identical scenarios to `tests/injection.rs`)  
7. wasm32-wasip2 friction notes (what compiled: bs58/sha2/waki; what was avoided: solana-sdk)  
8. SOP snippet for cron/Telegram  

`solana-core/README.md`: module map, HttpClient trait, how plugins vendor, sync script, MIT.

Wiring diagram content (ASCII is fine):

```
[BME280/DHT22] --I2C/GPIO--> [Raspberry Pi]
                               | ZeroClaw host tools / MQTT SOP
                               v
                     depin_attest (T1 unsigned tx)
                               v
                     Human approval / durable nonce
                               v
                     Solana memo attestation
                               v
              cron -> depin_uptime_watch -> Telegram alert if STALE
```

- [ ] **Step 1: Write READMEs completely (no TBD)**

- [ ] **Step 2: Confirm injection tests assert the same strings/outcomes as the README transcript**

- [ ] **Step 3: Commit**

```bash
git add solana-core/README.md plugins/depin-attest plugins/depin-uptime-watch
git commit -m "docs: custody, threat model, wiring, injection transcripts"
```

---

### Task 11: Final verification + open PR

**Files:**
- Modify: none unless fixes
- Verify: sync script drift check

- [ ] **Step 1: Drift guard**

Add to `tools/sync-solana-core.sh` a `--check` mode:

```bash
if [[ "${1:-}" == "--check" ]]; then
  for dest in ...; do
    diff -ru "$SRC" "$dest"
  done
  exit 0
fi
```

Run: `./tools/sync-solana-core.sh --check`  
Expected: no diff

- [ ] **Step 2: Full local gate**

```bash
cargo test --manifest-path solana-core/Cargo.toml
cargo test --manifest-path plugins/depin-attest/Cargo.toml
cargo test --manifest-path plugins/depin-uptime-watch/Cargo.toml
cargo build --manifest-path plugins/depin-attest/Cargo.toml --target wasm32-wasip2 --release
cargo build --manifest-path plugins/depin-uptime-watch/Cargo.toml --target wasm32-wasip2 --release
cargo fmt --manifest-path plugins/depin-attest/Cargo.toml --all -- --check
cargo fmt --manifest-path plugins/depin-uptime-watch/Cargo.toml --all -- --check
```

Expected: all green

- [ ] **Step 3: Open PR early**

```bash
git push -u origin HEAD
gh pr create --title "feat(plugins): solana-core + depin-attest + depin-uptime-watch (Track C+E)" --body "$(cat <<'EOF'
## Summary
- Track E: `solana-core` (canonical) vendored into plugins for isolated CI
- Track C T1: `depin-attest` — durable-nonce unsigned memo attestations
- Track C T0: `depin-uptime-watch` — OK/STALE/MISSING for cron SOPs

## Custody
T0/T1 only. No keys. No submitTransaction.

## Test plan
- [ ] `cargo test` in each crate
- [ ] `cargo build --target wasm32-wasip2 --release`
- [ ] injection tests fail closed
- [ ] demo video (Telegram + explorer memo + STALE alert)
EOF
)"
```

- [ ] **Step 4: Commit any CI fixes; engage `#solana-bounty`; schedule demo recording**

---

## Self-review (plan vs spec)

| Spec requirement | Task |
|------------------|------|
| Track E core, MIT, wasip2-friendly | 1–5, 10 |
| Pure core / thin shim / cdylib+rlib | 6–9 |
| Durable nonce solves blockhash expiry | 4, 7 |
| `depin-attest` T1 unsigned memo | 6–8 |
| `depin-uptime-watch` T0 OK/STALE/MISSING | 9 |
| Config-only payer/nonce; fail closed | 6–7, 9 |
| Host tests mocked RPC | 5, 7, 9 |
| wasm32-wasip2 release build | 8, 9, 11 |
| log-record, no stdout | 8, 9 |
| manifest minimal permissions | 8, 9 |
| README custody + threat + injection + wiring | 10 |
| CI isolation / vendor core | 1, 6, 11 |
| No GPIO WIT / no T2 | Global constraints |
| Demo ≤3 min | 11 (recording) |

Placeholder scan: none intentionally left. Exact memo/hash/period/budgets pinned to match the design spec.
