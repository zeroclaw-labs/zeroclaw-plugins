//! Solana Pay transfer-request URL builder (zero secrets).

use crate::pubkey::Pubkey;

#[derive(Debug, Clone)]
pub struct PayRequest {
    pub recipient: Pubkey,
    /// Human decimal amount (e.g. "25.00" USDC).
    pub amount: String,
    pub spl_token: Option<Pubkey>,
    pub memo: Option<String>,
    pub reference: Option<String>,
    pub label: Option<String>,
    pub message: Option<String>,
}

/// Telegram-clickable HTTPS link that opens a Solana Pay QR (customer scans in Phantom).
///
/// `solana:` is not auto-linked in Telegram. Phantom `ul/browse` wrapping a `solana:` URI
/// opens a blank in-app browser page — it is for HTTPS dApps, not Pay transfer requests.
/// A QR image URL is the reliable mobile + desktop click path.
pub fn solana_pay_qr_https(solana_pay_url: &str) -> String {
    format!(
        "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data={}",
        urlencoding_encode(solana_pay_url)
    )
}

/// Deprecated name kept for call-site clarity in older docs; same as [`solana_pay_qr_https`].
pub fn phantom_browse_https(solana_pay_url: &str) -> String {
    solana_pay_qr_https(solana_pay_url)
}

/// Build a `solana:` transfer request URL per the Solana Pay spec.
pub fn build_solana_pay_url(req: &PayRequest) -> Result<String, String> {
    if req.amount.is_empty() {
        return Err("amount is required".into());
    }
    // Basic amount sanity: digits + optional single dot.
    validate_amount(&req.amount)?;

    let mut url = format!("solana:{}", req.recipient.to_base58());
    let mut params: Vec<String> = Vec::new();
    params.push(format!("amount={}", urlencoding_encode(&req.amount)));
    if let Some(mint) = &req.spl_token {
        params.push(format!("spl-token={}", mint.to_base58()));
    }
    if let Some(memo) = &req.memo {
        params.push(format!("memo={}", urlencoding_encode(memo)));
    }
    if let Some(reference) = &req.reference {
        params.push(format!("reference={}", urlencoding_encode(reference)));
    }
    if let Some(label) = &req.label {
        params.push(format!("label={}", urlencoding_encode(label)));
    }
    if let Some(message) = &req.message {
        params.push(format!("message={}", urlencoding_encode(message)));
    }
    url.push('?');
    url.push_str(&params.join("&"));
    Ok(url)
}

fn validate_amount(amount: &str) -> Result<(), String> {
    if amount.len() > 32 {
        return Err("amount too long".into());
    }
    let mut dots = 0usize;
    for c in amount.chars() {
        if c == '.' {
            dots += 1;
            if dots > 1 {
                return Err("invalid amount".into());
            }
        } else if !c.is_ascii_digit() {
            return Err("invalid amount".into());
        }
    }
    if amount.is_empty() || amount == "." {
        return Err("invalid amount".into());
    }
    Ok(())
}

/// Minimal URL-encode for Solana Pay query values (UTF-8 safe).
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubkey::{usdc_mint_mainnet, SYSTEM_PROGRAM_ID};

    #[test]
    fn builds_usdc_invoice_url() {
        let url = build_solana_pay_url(&PayRequest {
            recipient: SYSTEM_PROGRAM_ID,
            amount: "25.00".into(),
            spl_token: Some(usdc_mint_mainnet()),
            memo: Some("INV=412 BRL=25.00".into()),
            reference: Some("inv-412".into()),
            label: Some("Caixa".into()),
            message: Some("Mesa 4".into()),
        })
        .unwrap();
        assert!(url.starts_with("solana:11111111111111111111111111111111?"));
        assert!(url.contains("amount=25.00"));
        assert!(url.contains("spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
        assert!(url.contains("memo=INV%3D412%20BRL%3D25.00"));
        assert!(url.contains("reference=inv-412"));
        let https = solana_pay_qr_https(&url);
        assert!(https.starts_with("https://api.qrserver.com/v1/create-qr-code/"));
        assert!(https.contains("data=solana%3A"));
    }

    #[test]
    fn rejects_bad_amount() {
        assert!(build_solana_pay_url(&PayRequest {
            recipient: SYSTEM_PROGRAM_ID,
            amount: "1.2.3".into(),
            spl_token: None,
            memo: None,
            reference: None,
            label: None,
            message: None,
        })
        .is_err());
    }
}
