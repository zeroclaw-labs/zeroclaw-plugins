//! Attestation payload: v1|device_pubkey|unix_ts|nonce|sha256(reading‖ts‖nonce)hex
use sha2::{Digest, Sha256};

pub struct Attestation {
    pub hash_hex: String,
    pub timestamp: u64,
    pub nonce: u64,
}

pub fn build(reading: f64, timestamp: u64, nonce: u64) -> Attestation {
    let mut h = Sha256::new();
    h.update(reading.to_le_bytes());
    h.update(timestamp.to_le_bytes());
    h.update(nonce.to_le_bytes());
    Attestation {
        hash_hex: hex(&h.finalize()),
        timestamp,
        nonce,
    }
}

pub fn memo_text(device_pubkey: &str, a: &Attestation) -> String {
    format!(
        "v1|{}|{}|{}|{}",
        device_pubkey, a.timestamp, a.nonce, a.hash_hex
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Replay guard: strictly monotonic nonce. Caller persists last_nonce.
pub fn check_nonce(last: u64, proposed: u64) -> Result<(), crate::CoreError> {
    if proposed > last {
        Ok(())
    } else {
        Err(crate::CoreError::Input(format!(
            "replay: nonce {proposed} <= last {last}"
        )))
    }
}

/// Extract the nonce field from an attestation memo (`v1|device|ts|nonce|hash`),
/// tolerating a `[len] ` prefix that `getSignaturesForAddress` adds.
pub fn parse_memo_nonce(memo: &str) -> Option<u64> {
    let start = memo.find("v1|")?;
    memo[start..].split('|').nth(3)?.parse::<u64>().ok()
}

/// Derive the last used nonce from the newest on-chain attestation, so the
/// replay guard survives restarts without host-side state (DESIGN §8 Q3).
/// Returns 0 when the device has never attested.
pub fn latest_nonce(
    http: &impl crate::HttpClient,
    url: &str,
    device_pubkey: &str,
) -> Result<u64, crate::CoreError> {
    let sigs = crate::rpc::get_signatures_for_address(http, url, device_pubkey, 25)?;
    Ok(sigs
        .iter()
        .filter(|s| !s.err)
        .filter_map(|s| s.memo.as_deref().and_then(parse_memo_nonce))
        .max()
        .unwrap_or(0))
}
