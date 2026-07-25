//! Solana Pay transfer-request URL builder (docs.solanapay.com spec).
//!
//! `solana:<recipient>?amount=<n>&spl-token=<mint>&reference=<pk>&label=..&message=..&memo=..`
//!
//! All inputs are validated fail-closed: recipient/mint/reference must be
//! 32-byte base58 pubkeys, amount must be positive, finite, and within the
//! operator's cap, and free-text fields are percent-encoded. The recipient is
//! ALWAYS the operator's configured address — this module has no way to accept
//! one from a model.

use crate::b58;

#[derive(Debug, PartialEq)]
pub enum PayError {
    BadRecipient,
    BadMint,
    BadReference,
    BadAmount(String),
}

impl core::fmt::Display for PayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PayError::BadRecipient => write!(f, "recipient is not a valid 32-byte base58 pubkey"),
            PayError::BadMint => write!(f, "spl-token mint is not a valid 32-byte base58 pubkey"),
            PayError::BadReference => write!(f, "reference is not a valid 32-byte base58 pubkey"),
            PayError::BadAmount(m) => write!(f, "invalid amount: {m}"),
        }
    }
}

/// A validated transfer request. Construct via [`TransferRequest::new`].
pub struct TransferRequest {
    recipient: String,
    /// Amount in whole token units (e.g. `1.5` USDC), already validated.
    amount: String,
    spl_token: Option<String>,
    reference: Option<String>,
    label: Option<String>,
    message: Option<String>,
    memo: Option<String>,
}

impl TransferRequest {
    /// Validate and build. `amount_str` is a decimal string; `decimals` is the
    /// mint's decimal count (6 for USDC); `max_amount` is the operator cap.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recipient: &str,
        amount_str: &str,
        decimals: u8,
        max_amount: f64,
        spl_token: Option<&str>,
        reference: Option<&str>,
        label: Option<&str>,
        message: Option<&str>,
        memo: Option<&str>,
    ) -> Result<Self, PayError> {
        if b58::decode_pubkey(recipient).is_none() {
            return Err(PayError::BadRecipient);
        }
        if let Some(m) = spl_token {
            if b58::decode_pubkey(m).is_none() {
                return Err(PayError::BadMint);
            }
        }
        if let Some(r) = reference {
            if b58::decode_pubkey(r).is_none() {
                return Err(PayError::BadReference);
            }
        }
        let amount = validate_amount(amount_str, decimals, max_amount)?;
        Ok(Self {
            recipient: recipient.to_string(),
            amount,
            spl_token: spl_token.map(str::to_string),
            reference: reference.map(str::to_string),
            label: label.map(str::to_string),
            message: message.map(str::to_string),
            memo: memo.map(str::to_string),
        })
    }

    /// Render the `solana:` URL.
    pub fn url(&self) -> String {
        let mut url = format!("solana:{}?amount={}", self.recipient, self.amount);
        if let Some(m) = &self.spl_token {
            url.push_str("&spl-token=");
            url.push_str(m);
        }
        if let Some(r) = &self.reference {
            url.push_str("&reference=");
            url.push_str(r);
        }
        if let Some(l) = &self.label {
            url.push_str("&label=");
            url.push_str(&pct_encode(l));
        }
        if let Some(m) = &self.message {
            url.push_str("&message=");
            url.push_str(&pct_encode(m));
        }
        if let Some(m) = &self.memo {
            url.push_str("&memo=");
            url.push_str(&pct_encode(m));
        }
        url
    }
}

/// Parse, bound and canonicalize a decimal amount without floats drifting:
/// max `decimals` fraction digits, > 0, <= max_amount, no scientific notation.
fn validate_amount(s: &str, decimals: u8, max_amount: f64) -> Result<String, PayError> {
    let s = s.trim();
    if s.is_empty() || s.starts_with('+') || s.starts_with('-') {
        return Err(PayError::BadAmount(
            "must be a plain positive decimal".into(),
        ));
    }
    let mut parts = s.splitn(2, '.');
    let int = parts.next().unwrap_or("");
    let frac = parts.next().unwrap_or("");
    if int.is_empty() && frac.is_empty() {
        return Err(PayError::BadAmount("empty".into()));
    }
    if !int.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(PayError::BadAmount("non-digit characters".into()));
    }
    if frac.len() > decimals as usize {
        return Err(PayError::BadAmount(format!(
            "more than {decimals} decimal places"
        )));
    }
    let value: f64 = s
        .parse()
        .map_err(|_| PayError::BadAmount("unparseable".into()))?;
    // Reject NaN explicitly as well as non-positive: a money amount must be a
    // finite positive number. (Digits-only parsing upstream already excludes
    // NaN/inf; this stays defensive.)
    if value.is_nan() || value <= 0.0 {
        return Err(PayError::BadAmount("must be greater than zero".into()));
    }
    if value > max_amount {
        return Err(PayError::BadAmount(format!(
            "exceeds operator cap of {max_amount}"
        )));
    }
    // Canonical form: strip leading zeros (keep one) and trailing fraction zeros.
    let int_norm = int.trim_start_matches('0');
    let int_norm = if int_norm.is_empty() { "0" } else { int_norm };
    let frac_norm = frac.trim_end_matches('0');
    Ok(if frac_norm.is_empty() {
        int_norm.to_string()
    } else {
        format!("{int_norm}.{frac_norm}")
    })
}

/// Minimal RFC 3986 percent-encoding for query values.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MERCHANT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // any valid pk
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const REF: &str = "11111111111111111111111111111111";

    #[test]
    fn golden_url_full() {
        let t = TransferRequest::new(
            MERCHANT,
            "1.5",
            6,
            100.0,
            Some(USDC),
            Some(REF),
            Some("Kiosk 01"),
            Some("Cold drink"),
            Some("order#42"),
        )
        .unwrap();
        assert_eq!(
            t.url(),
            format!(
                "solana:{MERCHANT}?amount=1.5&spl-token={USDC}&reference={REF}&label=Kiosk%2001&message=Cold%20drink&memo=order%2342"
            )
        );
    }

    #[test]
    fn amount_canonicalization() {
        for (input, want) in [
            ("1.500000", "1.5"),
            ("01.50", "1.5"),
            ("2", "2"),
            ("0.10", "0.1"),
        ] {
            let t = TransferRequest::new(MERCHANT, input, 6, 100.0, None, None, None, None, None)
                .unwrap();
            assert!(t.url().contains(&format!("amount={want}")), "{input}");
        }
    }

    #[test]
    fn amount_fails_closed() {
        for bad in ["0", "-1", "+1", "1e6", "abc", "", "1.1234567", "101"] {
            let r = TransferRequest::new(MERCHANT, bad, 6, 100.0, None, None, None, None, None);
            assert!(r.is_err(), "amount {bad:?} must be rejected");
        }
    }

    #[test]
    fn bad_keys_fail_closed() {
        assert_eq!(
            TransferRequest::new("not-a-key", "1", 6, 10.0, None, None, None, None, None).err(),
            Some(PayError::BadRecipient)
        );
        assert_eq!(
            TransferRequest::new(MERCHANT, "1", 6, 10.0, Some("xx"), None, None, None, None).err(),
            Some(PayError::BadMint)
        );
        assert_eq!(
            TransferRequest::new(MERCHANT, "1", 6, 10.0, None, Some("yy"), None, None, None).err(),
            Some(PayError::BadReference)
        );
    }

    #[test]
    fn injection_in_text_fields_is_encoded_inert() {
        let t = TransferRequest::new(
            MERCHANT,
            "1",
            6,
            10.0,
            None,
            None,
            Some("a&amount=999"),
            None,
            Some("&recipient=EVIL"),
        )
        .unwrap();
        let url = t.url();
        // The hostile text cannot introduce new query parameters: '&' and '='
        // inside text fields are percent-encoded, so exactly one live `amount`
        // parameter and zero live `recipient` parameters exist.
        assert!(url.contains("label=a%26amount%3D999"));
        assert!(url.contains("memo=%26recipient%3DEVIL"));
        assert_eq!(url.matches("amount=").count(), 1);
        assert_eq!(url.matches("&recipient=").count(), 0);
    }
}
