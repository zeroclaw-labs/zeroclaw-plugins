//! Pure Solana Pay URL construction. No wasm imports — host-testable with
//! `cargo test`. Implements the transfer-request URL spec:
//!
//!   solana:<recipient>?amount=<n>&spl-token=<mint>&reference=<key>&label=<..>&message=<..>&memo=<..>
//!
//! Custody tier: T1 — the plugin outputs a URL / QR payload only. The payer's
//! wallet (a human, on their phone) builds and signs the actual transaction.
//! This plugin holds no secrets whatsoever and performs no network I/O.

const B58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, Clone)]
pub struct PayRequest {
    /// Recipient address (base58, 32–44 chars typical).
    pub recipient: String,
    /// Amount in token ui units. Must be > 0.
    pub amount: f64,
    /// SPL mint address; None/"SOL" = native SOL.
    pub mint: Option<String>,
    /// Invoice memo (becomes `memo` param — wallets attach it on-chain).
    pub memo: Option<String>,
    /// Reference key(s) for watch-side reconciliation (Solana Pay reference).
    pub reference: Vec<String>,
    /// Label for the payer UI (merchant name).
    pub label: Option<String>,
    /// Message for the payer UI (description of the charge).
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PayPayload {
    pub url: String,
    /// UTF-8 payload suitable for QR encoding (== url; QR renderers are host-side).
    pub qr_payload: String,
    pub summary: String,
}

/// Percent-encode per RFC 3986 query rules (Solana Pay spec uses
/// application/x-www-form-urlencoded semantics for params).
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Minimal base58 sanity check (alphabet + length). Not a checksum — Solana
/// addresses are Ed25519 pubkeys encoded base58; we validate shape only.
pub fn looks_base58(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| B58_ALPHABET.contains(&b))
}

/// Format an amount the way the spec wants: plain decimal, no exponent,
/// no trailing zeros beyond significance ("25", "0.025", "1.5").
pub fn format_amount(amount: f64) -> Option<String> {
    if !(amount.is_finite() && amount > 0.0) {
        return None;
    }
    let s = format!("{amount:.9}");
    let s = s.trim_end_matches('0').trim_end_matches('.').to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

pub fn build(req: &PayRequest) -> Result<PayPayload, String> {
    if !looks_base58(&req.recipient) {
        return Err(format!("recipient is not base58-shaped: {:?}", req.recipient));
    }
    let amount = format_amount(req.amount).ok_or("amount must be a positive finite number")?;
    if let Some(m) = &req.mint {
        if m != "SOL" && !looks_base58(m) {
            return Err(format!("mint is not base58-shaped: {m:?}"));
        }
    }
    for r in &req.reference {
        if !looks_base58(r) {
            return Err(format!("reference is not base58-shaped: {r:?}"));
        }
    }

    let mut url = format!("solana:{}?amount={amount}", req.recipient);
    if let Some(m) = &req.mint {
        if m != "SOL" {
            url.push_str(&format!("&spl-token={m}"));
        }
    }
    for r in &req.reference {
        url.push_str(&format!("&reference={r}"));
    }
    if let Some(l) = &req.label {
        url.push_str(&format!("&label={}", urlencode(l)));
    }
    if let Some(m) = &req.message {
        url.push_str(&format!("&message={}", urlencode(m)));
    }
    if let Some(memo) = &req.memo {
        url.push_str(&format!("&memo={}", urlencode(memo)));
    }

    let token = match &req.mint {
        Some(m) if m != "SOL" => "SPL",
        _ => "SOL",
    };
    let summary = format!(
        "Charge {amount} {token} to {}{}",
        &req.recipient[..req.recipient.len().min(8)],
        req.memo
            .as_deref()
            .map(|m| format!(" — memo: {m}"))
            .unwrap_or_default()
    );

    Ok(PayPayload {
        qr_payload: url.clone(),
        url,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PayRequest {
        PayRequest {
            recipient: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".into(),
            amount: 25.0,
            mint: None,
            memo: None,
            reference: vec![],
            label: None,
            message: None,
        }
    }

    #[test]
    fn builds_sol_transfer_url() {
        let p = build(&base()).unwrap();
        assert_eq!(
            p.url,
            "solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?amount=25"
        );
        assert_eq!(p.qr_payload, p.url);
    }

    #[test]
    fn formats_amounts_without_trailing_zeros() {
        assert_eq!(format_amount(25.0).unwrap(), "25");
        assert_eq!(format_amount(0.025).unwrap(), "0.025");
        assert_eq!(format_amount(1.5).unwrap(), "1.5");
        assert!(format_amount(0.0).is_none());
        assert!(format_amount(-1.0).is_none());
        assert!(format_amount(f64::NAN).is_none());
    }

    #[test]
    fn includes_spl_mint() {
        let mut r = base();
        r.mint = Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into()); // USDC
        let p = build(&r).unwrap();
        assert!(p.url.contains("&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
        assert!(p.summary.contains("SPL"));
    }

    #[test]
    fn sol_mint_marker_omits_spl_param() {
        let mut r = base();
        r.mint = Some("SOL".into());
        let p = build(&r).unwrap();
        assert!(!p.url.contains("spl-token"));
    }

    #[test]
    fn encodes_memo_label_message() {
        let mut r = base();
        r.memo = Some("Invoice #412".into());
        r.label = Some("Café Sol".into());
        r.message = Some("table 4".into());
        let p = build(&r).unwrap();
        assert!(p.url.contains("&memo=Invoice%20%23412"));
        assert!(p.url.contains("&label=Caf%C3%A9%20Sol"));
        assert!(p.url.contains("&message=table%204"));
    }

    #[test]
    fn includes_references_in_order() {
        let mut r = base();
        r.reference = vec![
            "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM".into(),
            "5uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofN".into(),
        ];
        let p = build(&r).unwrap();
        let i1 = p.url.find("reference=4uQ").unwrap();
        let i2 = p.url.find("reference=5uQ").unwrap();
        assert!(i1 < i2);
    }

    #[test]
    fn rejects_bad_recipient() {
        let mut r = base();
        r.recipient = "not!base58".into();
        assert!(build(&r).is_err());
        r.recipient = "".into();
        assert!(build(&r).is_err());
    }

    #[test]
    fn rejects_bad_mint_and_reference() {
        let mut r = base();
        r.mint = Some("0ilI".into()); // invalid base58 chars
        assert!(build(&r).is_err());
        let mut r = base();
        r.reference = vec!["with space".into()];
        assert!(build(&r).is_err());
    }

    #[test]
    fn base58_shape_check() {
        assert!(looks_base58("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"));
        assert!(!looks_base58("0OIl"));
        assert!(!looks_base58(""));
    }
}
