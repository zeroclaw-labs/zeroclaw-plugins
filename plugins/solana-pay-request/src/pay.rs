//! Pure Solana Pay transfer-request URL construction.
//!
//! No wasm, no network, no keys — just validated string building, so it compiles
//! and tests on the host with a plain `cargo test`, and the wasm component reuses
//! the exact same logic through the shim in `lib.rs`.
//!
//! Spec: `solana:<recipient>?amount=<amount>&spl-token=<mint>&reference=<ref>&label=<label>&message=<message>&memo=<memo>`
//! (Solana Pay transfer request, <https://docs.solanapay.com/spec>).

use serde::Deserialize;

/// A transfer-request payment the agent proposes. Every field the caller controls
/// is validated before it can appear in the URL; nothing is silently altered.
#[derive(Deserialize, Default, Debug)]
pub struct PayRequest {
    /// Base58 Solana address to be paid (required).
    pub recipient: String,
    /// Amount in SOL, or in the SPL token's UI units when `spl_token` is set.
    #[serde(default)]
    pub amount: Option<String>,
    /// SPL token mint address. Omit for a native SOL payment.
    #[serde(default)]
    pub spl_token: Option<String>,
    /// Optional base58 reference public keys for later transaction lookup.
    #[serde(default)]
    pub reference: Vec<String>,
    /// Who is requesting payment (shown in the wallet).
    #[serde(default)]
    pub label: Option<String>,
    /// What the payment is for (shown in the wallet).
    #[serde(default)]
    pub message: Option<String>,
    /// Optional SPL memo recorded on-chain.
    #[serde(default)]
    pub memo: Option<String>,
}

/// Validate a base58-encoded Ed25519 public key (decodes to exactly 32 bytes).
fn validate_pubkey(s: &str, field: &str) -> Result<(), String> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|_| format!("`{field}` is not valid base58"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "`{field}` is not a 32-byte Solana public key (decoded to {} bytes)",
            bytes.len()
        ));
    }
    Ok(())
}

/// Validate a non-negative plain-decimal amount (no sign, no exponent).
fn validate_amount(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("`amount` is empty".into());
    }
    let mut seen_dot = false;
    let mut seen_digit = false;
    for c in s.chars() {
        match c {
            '0'..='9' => seen_digit = true,
            '.' if !seen_dot => seen_dot = true,
            '.' => return Err("`amount` has more than one decimal point".into()),
            other => {
                return Err(format!(
                    "`amount` must be a non-negative decimal; found {other:?}"
                ))
            }
        }
    }
    if !seen_digit {
        return Err("`amount` has no digits".into());
    }
    Ok(())
}

/// Percent-encode a query value, escaping everything but RFC 3986 unreserved chars.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build a Solana Pay transfer-request URL.
///
/// Fails closed: any invalid input returns `Err` and NO URL. The recipient is
/// validated and echoed verbatim — it is never silently rewritten or dropped, so
/// the worst a poisoned `label`/`message` can do is add text the human sees in
/// their wallet next to the true recipient before signing.
pub fn build_url(req: &PayRequest) -> Result<String, String> {
    if req.recipient.trim().is_empty() {
        return Err("`recipient` is required".into());
    }
    validate_pubkey(&req.recipient, "recipient")?;
    if let Some(t) = &req.spl_token {
        validate_pubkey(t, "spl_token")?;
    }
    for r in &req.reference {
        validate_pubkey(r, "reference")?;
    }
    if let Some(a) = &req.amount {
        validate_amount(a)?;
    }

    // recipient is base58 (URL-safe) and goes in the path, unencoded.
    let mut url = format!("solana:{}", req.recipient);
    let mut params: Vec<String> = Vec::new();
    if let Some(a) = &req.amount {
        params.push(format!("amount={a}"));
    }
    if let Some(t) = &req.spl_token {
        params.push(format!("spl-token={t}"));
    }
    for r in &req.reference {
        params.push(format!("reference={r}"));
    }
    if let Some(l) = &req.label {
        params.push(format!("label={}", encode(l)));
    }
    if let Some(m) = &req.message {
        params.push(format!("message={}", encode(m)));
    }
    if let Some(m) = &req.memo {
        params.push(format!("memo={}", encode(m)));
    }
    if !params.is_empty() {
        url.push('?');
        url.push_str(&params.join("&"));
    }
    Ok(url)
}
