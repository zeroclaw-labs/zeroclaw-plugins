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
    pub fee_payer_note: String,
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

/// Strip pipe characters (the memo field delimiter) and enforce max length.
/// Called on every user-controlled string before it enters the memo payload.
fn sanitize(s: &str, max_len: usize, field: &str) -> Result<String, String> {
    if s.len() > max_len {
        return Err(format!("{field} too long: {} chars (max {max_len})", s.len()));
    }
    // Reject '|' — it is the memo field delimiter; allowing it lets a caller
    // forge fake slot:/nonce: segments that a downstream parser would accept.
    if s.contains('|') {
        return Err(format!("{field} must not contain '|'"));
    }
    Ok(s.to_string())
}

/// Build the memo string committed on-chain.
/// Returns Err if any field would corrupt the delimiter-separated format.
pub fn build_memo(args: &AttestArgs, slot: u64, nonce: &[u8; 32]) -> Result<String, String> {
    let device_id = sanitize(&args.device_id, 64, "device_id")?;
    let sensor_type = sanitize(&args.sensor_type, 32, "sensor_type")?;
    let unit = sanitize(&args.unit, 16, "unit")?;

    let memo = format!(
        "zc-depin|{}|{}|{:.4}{}|slot:{}|nonce:{}",
        device_id,
        sensor_type,
        args.value,
        unit,
        slot,
        hex_encode(nonce)
    );
    // Hard cap: Solana Memo program accepts up to ~566 bytes; stay well under.
    if memo.len() > 256 {
        return Err(format!("memo too long: {} chars (max 256)", memo.len()));
    }
    Ok(memo)
}

/// sha256 of the memo payload, used as the attestation hash returned to the
/// caller (independent of the tx bytes, so it stays stable if serialization
/// details change).
pub fn attestation_hash(memo: &str) -> [u8; 32] {
    Sha256::digest(memo.as_bytes()).into()
}
