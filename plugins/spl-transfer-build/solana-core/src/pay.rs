//! Solana Pay transfer-request URLs, per the maintained spec at
//! solana-foundation/pay (SPEC.md, v1.1): `solana:<recipient>?amount=...`.
//! Display fields are percent-encoded; amount rules are enforced upstream by
//! [`crate::amount`] so a URL we emit is always spec-valid.

use crate::pubkey::Pubkey;

/// Fields of a transfer request. `recipient` must be a wallet address (never
/// an ATA — the paying wallet derives the ATA from `spl_token`).
#[derive(Debug, Default)]
pub struct TransferRequest {
    pub recipient: String,
    /// Decimal user-units amount string, already validated.
    pub amount: Option<String>,
    pub spl_token: Option<String>,
    pub references: Vec<String>,
    pub label: Option<String>,
    pub message: Option<String>,
    pub memo: Option<String>,
}

/// Percent-encode for a URL query value: unreserved chars pass through,
/// everything else becomes %XX.
fn percent_encode(s: &str) -> String {
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

impl TransferRequest {
    /// Render the `solana:` URL.
    pub fn to_url(&self) -> String {
        let mut url = format!("solana:{}", self.recipient);
        let mut params: Vec<String> = Vec::new();
        if let Some(a) = &self.amount {
            params.push(format!("amount={a}"));
        }
        if let Some(t) = &self.spl_token {
            params.push(format!("spl-token={t}"));
        }
        for r in &self.references {
            params.push(format!("reference={r}"));
        }
        if let Some(l) = &self.label {
            params.push(format!("label={}", percent_encode(l)));
        }
        if let Some(m) = &self.message {
            params.push(format!("message={}", percent_encode(m)));
        }
        if let Some(m) = &self.memo {
            params.push(format!("memo={}", percent_encode(m)));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        url
    }
}

/// Validate a reference: base58, 32 bytes. Need not be on-curve or exist.
pub fn valid_reference(s: &str) -> bool {
    Pubkey::parse(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_example_shape() {
        // Mirrors the SPEC.md example URL structure.
        let req = TransferRequest {
            recipient: "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN".into(),
            amount: Some("1".into()),
            label: Some("Michael".into()),
            message: Some("Thanks for all the fish".into()),
            memo: Some("OrderId12345".into()),
            ..Default::default()
        };
        assert_eq!(
            req.to_url(),
            "solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=1&label=Michael&message=Thanks%20for%20all%20the%20fish&memo=OrderId12345"
        );
    }

    #[test]
    fn spl_token_and_references() {
        let req = TransferRequest {
            recipient: "r".into(),
            amount: Some("0.01".into()),
            spl_token: Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into()),
            references: vec!["A".into(), "B".into()],
            ..Default::default()
        };
        let url = req.to_url();
        assert!(url.contains("spl-token=EPjFWdd5"));
        assert!(
            url.contains("reference=A&reference=B"),
            "references repeat in order"
        );
    }

    #[test]
    fn reference_must_be_32_bytes() {
        assert!(valid_reference(
            "SysvarC1ock11111111111111111111111111111111"
        ));
        assert!(!valid_reference("tooshort"));
    }
}
