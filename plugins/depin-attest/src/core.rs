//! Pure plugin logic — host-testable. The shim only adapts I/O.
use crate::{attest, encode, instructions, rpc, sanitize, shape, CoreError, HttpClient};

pub struct Config {
    pub rpc_url: String,
    pub device_pubkey: String,
    pub sensor_source: String, // "bme280" | "mock"
    pub nonce_account: Option<String>,
    pub nonce_authority: Option<String>,
}

pub struct Args {
    pub reading: Option<f64>,
    pub note: Option<String>,
}

/// Build an UNSIGNED Memo attestation transaction. Returns JSON:
/// `{ summary, unsigned_tx_b64, attestation: {hash_hex, timestamp, nonce} }`.
/// No key ever exists here — a human signs the returned base64.
pub fn run(
    cfg: &Config,
    args: &Args,
    http: &impl HttpClient,
    now: u64,
    last_nonce: u64,
) -> Result<String, CoreError> {
    if let Some(note) = &args.note {
        sanitize::check_text("note", note, 64)?; // fail closed
    }
    // Durable-nonce reading is not wired yet — fail closed rather than silently
    // building a blockhash-expiring tx when a nonce account is configured.
    if cfg.nonce_account.is_some() {
        return Err(CoreError::Input(
            "durable nonce configured but not yet wired (I3)".into(),
        ));
    }
    let reading = match args.reading {
        Some(r) if (-40.0..=85.0).contains(&r) => r, // BME280 bounds
        Some(_) => return Err(CoreError::Input("reading out of sensor bounds".into())),
        None if cfg.sensor_source == "mock" => 23.5,
        None => return Err(CoreError::Input("no reading available".into())),
    };
    let nonce = last_nonce + 1;
    attest::check_nonce(last_nonce, nonce)?;
    let a = attest::build(reading, now, nonce);
    let memo = attest::memo_text(&cfg.device_pubkey, &a);

    let blockhash = rpc::get_latest_blockhash(http, &cfg.rpc_url)?;
    let memo_ix = instructions::memo(&memo)?;
    let message = encode::compile_message(&cfg.device_pubkey, &[memo_ix], &blockhash)?;
    let bytes = encode::serialize_message(&message);

    let full_tx_len = 1 + 64 * message.header.num_required_signatures as usize + bytes.len();
    if full_tx_len > 1232 {
        return Err(CoreError::Input(format!(
            "unsigned tx {full_tx_len} bytes exceeds 1232"
        )));
    }
    let unsigned_tx_b64 = encode::to_base64(&bytes);

    let out = serde_json::json!({
        "summary": format!("Unsigned attestation of reading {reading} (nonce {nonce}). A human must sign the base64 tx."),
        "unsigned_tx_b64": unsigned_tx_b64,
        "attestation": { "hash_hex": a.hash_hex, "timestamp": a.timestamp, "nonce": a.nonce },
    })
    .to_string();
    Ok(shape::cap(&out))
}
