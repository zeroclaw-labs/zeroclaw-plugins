//! Solana Pay transfer request URL encoder.
//!
//! Spec: <https://docs.solanapay.com/spec>
//!
//! ```text
//! solana:<recipient>?amount=...&spl-token=...&reference=...&label=...&message=...&memo=...
//! ```

/// Mainnet USDC mint address.
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Parameters for a Solana Pay transfer request URL.
#[derive(Debug, Clone)]
pub struct SolanaPayParams<'a> {
    pub recipient: &'a str,
    pub amount: &'a str,
    pub spl_token: &'a str,
    pub reference: &'a str,
    pub label: Option<&'a str>,
    pub message: Option<&'a str>,
    pub memo: Option<&'a str>,
}

/// Build a Solana Pay transfer request URL.
///
/// Returns `Err` if the recipient does not look like a base58 public key.
pub fn build_solana_pay_url(params: &SolanaPayParams<'_>) -> Result<String, String> {
    if !is_valid_base58_pubkey(params.recipient) {
        return Err(format!(
            "invalid recipient pubkey (expected base58): {}",
            params.recipient
        ));
    }

    let mut url = String::with_capacity(256);
    url.push_str("solana:");
    url.push_str(params.recipient);
    url.push('?');

    let mut first = true;
    let mut append = |key: &str, value: &str| {
        if !first {
            url.push('&');
        }
        first = false;
        url.push_str(key);
        url.push('=');
        url.push_str(value);
    };

    append("amount", params.amount);
    append("spl-token", params.spl_token);
    append("reference", params.reference);

    if let Some(label) = params.label {
        if !label.is_empty() {
            append("label", &url_encode(label));
        }
    }
    if let Some(message) = params.message {
        if !message.is_empty() {
            append("message", &url_encode(message));
        }
    }
    if let Some(memo) = params.memo {
        if !memo.is_empty() {
            append("memo", &url_encode(memo));
        }
    }

    Ok(url)
}

/// Check that `s` looks like a Solana base58 public key (32-byte payload).
///
/// Accepts decoded length of 32 bytes; alphabet is Bitcoin-style base58
/// (no `0`, `O`, `I`, `l`).
pub fn is_valid_base58_pubkey(s: &str) -> bool {
    if s.is_empty() || s.len() < 32 || s.len() > 44 {
        return false;
    }
    if !s.chars().all(is_base58_char) {
        return false;
    }
    match bs58::decode(s).into_vec() {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

fn is_base58_char(c: char) -> bool {
    matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
}

/// Minimal application/x-www-form-urlencoded style encoding for query values.
///
/// Encodes everything that is not unreserved (RFC 3986): ALPHA / DIGIT / - . _ ~
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push_str("%20"),
            _ => {
                out.push('%');
                out.push(nibble_hex(b >> 4));
                out.push(nibble_hex(b & 0x0f));
            }
        }
    }
    out
}

fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // System program id — well-known 32-byte base58 pubkey.
    const RECIPIENT: &str = "11111111111111111111111111111112";

    #[test]
    fn solana_pay_url_golden_structure() {
        let url = build_solana_pay_url(&SolanaPayParams {
            recipient: RECIPIENT,
            amount: "27.272727",
            spl_token: USDC_MINT,
            reference: "RefBase58Example1111111111111111111",
            label: Some("Loja Demo"),
            message: Some("Invoice inv-001"),
            memo: Some("PIX|BRL|inv-001|Pedido"),
        })
        .unwrap();

        assert!(url.starts_with(&format!("solana:{RECIPIENT}?")));
        assert!(url.contains("amount=27.272727"));
        assert!(url.contains(&format!("spl-token={USDC_MINT}")));
        assert!(url.contains("reference=RefBase58Example1111111111111111111"));
        assert!(url.contains("label=Loja%20Demo"));
        assert!(url.contains("message=Invoice%20inv-001"));
        // Pipe and letters
        assert!(url.contains("memo=PIX%7CBRL%7Cinv-001%7CPedido"));
    }

    #[test]
    fn rejects_bad_recipient() {
        let err = build_solana_pay_url(&SolanaPayParams {
            recipient: "not-a-key!!!",
            amount: "1",
            spl_token: USDC_MINT,
            reference: "r",
            label: None,
            message: None,
            memo: None,
        })
        .unwrap_err();
        assert!(err.contains("invalid recipient"));
    }

    #[test]
    fn usdc_mint_constant() {
        assert_eq!(
            USDC_MINT,
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        );
        assert!(is_valid_base58_pubkey(USDC_MINT));
    }

    #[test]
    fn url_encode_specials() {
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("a|b"), "a%7Cb");
        assert_eq!(url_encode("ok-._~"), "ok-._~");
    }
}
