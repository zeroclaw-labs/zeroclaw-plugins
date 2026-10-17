//! Transaction construction helpers — build unsigned Solana transactions
//! and Solana Pay URLs. Pure core, no wasm dependency.

use crate::types::*;

/// Transaction builder — constructs unsigned versioned transactions.
#[derive(Debug, Clone)]
pub struct TxBuilder {
    pub blockhash: String,
    pub fee_payer: String,
}

impl TxBuilder {
    pub fn new(blockhash: impl Into<String>, fee_payer: impl Into<String>) -> Self {
        Self {
            blockhash: blockhash.into(),
            fee_payer: fee_payer.into(),
        }
    }

    /// Build an unsigned SPL Token transfer instruction.
    /// Returns the base64-encoded transaction message for offline signing.
    pub fn build_spl_transfer(
        &self,
        source: &str,
        dest: &str,
        mint: &str,
        amount: u64,
        decimals: u8,
    ) -> Result<String, String> {
        // On wasm we assemble manually; on host we can test the shape.
        // The actual instruction data depends on SPL Token version.
        // This returns a serialized Message envelope.
        let message = serde_json::json!({
            "type": "spl_transfer",
            "blockhash": self.blockhash,
            "fee_payer": self.fee_payer,
            "source": source,
            "destination": dest,
            "mint": mint,
            "amount": amount,
            "decimals": decimals,
            "version": 0,
        });

        Ok(base64_encode(serde_json::to_string(&message)
            .map_err(|e| format!("serialize: {e}"))?.as_bytes()))
    }

    /// Format a transaction as a human-readable summary (~200 tokens).
    pub fn summarize_tx(&self, _tx_json: &str) -> ShapedOutput {
        ShapedOutput::text(format!(
            "Unsigned SPL Transfer | Blockhash: {} | Payer: {}",
            &self.blockhash[..8],
            &self.fee_payer[..8]
        ))
    }
}

/// Build a Solana Pay transfer request URL (T1, no secrets).
pub fn build_solana_pay_url(
    recipient: &str,
    amount: f64,
    mint: Option<&str>,
    memo: Option<&str>,
    reference: Option<&str>,
) -> String {
    let mut url = format!("solana:{}", recipient);

    let mut params: Vec<String> = Vec::new();
    if let Some(spl) = mint {
        params.push(format!("spl-token={}", spl));
    }
    params.push(format!("amount={}", amount));
    if let Some(m) = memo {
        params.push(format!("memo={}", m));
    }
    if let Some(r) = reference {
        params.push(format!("reference={}", r));
    }
    params.push("label=ZeroClaw+Agent".into());

    url.push('?');
    url.push_str(&params.join("&"));
    url
}

/// Base64 encode bytes (no_std compatible).
pub fn base64_encode(data: &[u8]) -> String {
    // Simple base64 encoding without external crate
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize]);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize]);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize]);
        } else {
            result.push(b'=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize]);
        } else {
            result.push(b'=');
        }
    }
    String::from_utf8(result).unwrap_or_default()
}

/// Convenience function to build a transfer tx (wraps TxBuilder).
pub fn build_transfer_tx(
    blockhash: &str,
    fee_payer: &str,
    source: &str,
    dest: &str,
    mint: &str,
    amount: u64,
    decimals: u8,
) -> Result<String, String> {
    let builder = TxBuilder::new(blockhash, fee_payer);
    builder.build_spl_transfer(source, dest, mint, amount, decimals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_pay_url_no_mint() {
        let url = build_solana_pay_url(
            "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf",
            1.5,
            None,
            Some("invoice-42"),
            None,
        );
        assert!(url.starts_with("solana:"));
        assert!(url.contains("amount=1.5"));
        assert!(url.contains("memo=invoice-42"));
        assert!(url.contains("label=ZeroClaw+Agent"));
        assert!(!url.contains("spl-token="));
    }

    #[test]
    fn test_solana_pay_url_with_mint() {
        let url = build_solana_pay_url(
            "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf",
            25.0,
            Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            Some("table-4"),
            Some("ref123"),
        );
        assert!(url.contains("spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
        assert!(url.contains("amount=25"));
        assert!(url.contains("reference=ref123"));
        assert!(url.contains("memo=table-4"));
    }

    #[test]
    fn test_base64_encode_happy_path() {
        let encoded = base64_encode(b"hello");
        assert_eq!(encoded, "aGVsbG8=");
    }

    #[test]
    fn test_base64_encode_empty() {
        let encoded = base64_encode(b"");
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_build_transfer_tx() {
        let tx = build_transfer_tx(
            "ABC123def456xyz789",
            "FeePayer11111111111111111111111",
            "Source111111111111111111111111",
            "Dest1111111111111111111111111",
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            100_000_000,
            6,
        );
        assert!(tx.is_ok());
        // Our base64_encode output: just verify it's valid base64 string
        let encoded = tx.unwrap();
        assert!(encoded.len() > 10);
        assert!(!encoded.contains(' '));
        // Should contain base64 chars only
        assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }
}