//! Pure attestation core: no wasm or wasi dependency, so it compiles and
//! tests on the host with a plain `cargo test`. The wasm component (`lib.rs`)
//! reuses this exact logic and only adds the wasi:http fetch of chain state.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Input from the LLM tool call. `#[serde(deny_unknown_fields)]` makes this
/// fail closed against prompt-injection attempts that try to smuggle extra
/// fields (e.g. a `"private_key"`) into the arguments — see
/// `prompt_injection_unknown_field_rejected` in `tests/attest_tests.rs`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestArgs {
    pub device_id: String,
    pub sensor_type: String,
    pub value: f64,
    pub unit: String,
}

#[derive(Debug, Serialize)]
pub struct AttestResult {
    pub unsigned_tx_b64: String,
    pub attestation_hash: String,
    pub memo_payload: String,
    pub replay_nonce: String,
    pub custody_tier: &'static str,
    pub summary: String,
}

/// Encode bytes as lowercase hex without pulling in a `hex` crate.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Derive the replay-guard nonce: `sha256(device_id || "|" || slot_le)`.
/// Deterministic per (device, slot) pair, so a resubmitted attestation for a
/// slot that has already been committed reuses the same nonce and can be
/// detected/rejected downstream.
pub fn derive_nonce(device_id: &str, slot: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(device_id.as_bytes());
    h.update(b"|");
    h.update(slot.to_le_bytes());
    h.finalize().into()
}

/// Build the memo string committed on-chain.
pub fn build_memo(args: &AttestArgs, slot: u64, nonce: &[u8; 32]) -> String {
    format!(
        "zc-depin|{}|{}|{:.4}{}|slot:{}|nonce:{}",
        args.device_id,
        args.sensor_type,
        args.value,
        args.unit,
        slot,
        hex_encode(nonce)
    )
}

/// sha256 of the memo payload, used as the attestation hash returned to the
/// caller (independent of the tx bytes, so it stays stable if serialization
/// details change).
pub fn attestation_hash(memo: &str) -> [u8; 32] {
    Sha256::digest(memo.as_bytes()).into()
}
