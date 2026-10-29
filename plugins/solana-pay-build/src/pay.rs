//! Solana Pay transfer-request construction, and the reference key that ties an
//! on-chain payment back to one order.
//!
//! Why this is code and not a procedure step. Both halves of this job — minting
//! a reference key and assembling the URL — were originally written as SOP steps
//! for the model to carry out. Neither is something a language model can do. A
//! reference key is 32 bytes of entropy, and a transfer request is a URL with
//! exact percent-encoding rules. Asked to do them anyway, the model reached for
//! the only tool it had and invented endpoints that do not exist:
//!
//! ```text
//! http_request GET https://example.com/generate-reference-key
//! http_request GET https://api.example.com/shop/token/verify?token=USDC
//! ```
//!
//! It did not report that it could not proceed. It fabricated a plausible URL,
//! which is the same failure this suite has now seen three times. The fix is not
//! a better prompt: it is removing the decision from the model entirely.
//!
//! Nothing here holds a key, signs, or submits. A transfer request is a string;
//! the customer's own wallet builds and signs the transaction. Custody tier T0.

use crate::base58::{b58_encode, is_valid_address};
use sha2::{Digest, Sha256};

/// A charge the shop wants paid.
#[derive(Debug, Clone)]
pub struct Charge {
    pub label: String,
    pub amount: String,
    pub token: String,
}

/// The operator's own settings, read from this plugin's jailed config section.
#[derive(Debug, Clone)]
pub struct ShopConfig {
    pub recipient: String,
    /// Symbols and/or mint addresses the shop accepts. Empty accepts nothing.
    pub allowed_tokens: Vec<String>,
    /// Per-charge ceiling in whole tokens, as a decimal string.
    pub max_amount: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequest {
    pub url: String,
    pub reference: String,
    pub label: String,
    pub amount: String,
    pub token: String,
}

/// Amounts are decimal strings end to end, never floats — a binary float cannot
/// represent 25.10 exactly, and a till that quietly re-renders the amount it
/// charges is worse than one that refuses.
///
/// Compares two decimal strings numerically without parsing either into a
/// number. Returns `None` if either side is not a plain decimal.
fn decimal_le(a: &str, b: &str) -> Option<bool> {
    fn split(s: &str) -> Option<(&str, &str)> {
        if s.is_empty() {
            return None;
        }
        let (int, frac) = match s.split_once('.') {
            Some((i, f)) => (i, f),
            None => (s, ""),
        };
        if int.is_empty() && frac.is_empty() {
            return None;
        }
        if !int.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if !frac.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        Some((int, frac))
    }

    let (ai, af) = split(a)?;
    let (bi, bf) = split(b)?;

    let ai_t = ai.trim_start_matches('0');
    let bi_t = bi.trim_start_matches('0');
    if ai_t.len() != bi_t.len() {
        return Some(ai_t.len() < bi_t.len());
    }
    if ai_t != bi_t {
        return Some(ai_t < bi_t);
    }

    let width = af.len().max(bf.len());
    let pad = |f: &str| {
        let mut s = f.to_string();
        while s.len() < width {
            s.push('0');
        }
        s
    };
    Some(pad(af) <= pad(bf))
}

/// Percent-encodes per RFC 3986 unreserved rules. The label goes into a query
/// value and a shop's table name is not guaranteed to be URL-safe — `Table 4`
/// and `Café` both appear in practice.
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Derives the reference key for one charge.
///
/// A Solana Pay reference is a 32-byte account key used read-only to identify a
/// payment; no private key for it ever needs to exist, which is what keeps this
/// at custody tier T0. It must be unique per charge, because it is the only
/// thing that distinguishes two identical orders — `table 4, 25 USDC` twice in
/// one evening is normal, and reusing a reference would make the second payment
/// indistinguishable from the first.
///
/// `salt` supplies that uniqueness and must differ per charge; the caller passes
/// a clock reading. It is mixed with the shop and the order so that two shops
/// sharing a clock tick still derive different keys.
pub fn derive_reference(cfg: &ShopConfig, charge: &Charge, salt: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"aval:solana-pay:reference:v1");
    // Length-prefix every field. Without this, ("ab","c") and ("a","bc") hash
    // identically, and a label chosen by whoever types into the shop channel is
    // exactly where that would be noticed.
    for part in [
        cfg.recipient.as_str(),
        charge.label.as_str(),
        charge.amount.as_str(),
        charge.token.as_str(),
        salt,
    ] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    let digest: [u8; 32] = h.finalize().into();
    b58_encode(&digest)
}

/// Builds the transfer request, refusing anything the shop has not allowed.
///
/// Every refusal here is enforced in Rust and cannot be argued with. The model
/// does not pass the ceiling or the allowlist as arguments, so no message
/// arriving in the shop channel can raise either one.
pub fn build_payment_request(
    cfg: &ShopConfig,
    charge: &Charge,
    salt: &str,
) -> Result<PaymentRequest, String> {
    is_valid_address(&cfg.recipient)
        .map_err(|e| format!("shop recipient address is not a valid public key: {e}"))?;

    if charge.label.trim().is_empty() {
        return Err("charge has no order label".to_string());
    }

    if !cfg
        .allowed_tokens
        .iter()
        .any(|t| t.eq_ignore_ascii_case(&charge.token))
    {
        return Err(format!(
            "token {:?} is not on the shop's allowlist",
            charge.token
        ));
    }

    match decimal_le(&charge.amount, &cfg.max_amount) {
        Some(true) => {}
        Some(false) => {
            return Err(format!(
                "amount {} is over the shop's per-charge ceiling of {}",
                charge.amount, cfg.max_amount
            ))
        }
        None => {
            return Err(format!(
                "amount {:?} is not a plain decimal string",
                charge.amount
            ))
        }
    }

    let reference = derive_reference(cfg, charge, salt);

    // `solana:<recipient>?amount=..&spl-token=..&reference=..&label=..`
    // SOL is the native case and carries no spl-token parameter.
    let mut url = format!(
        "solana:{}?amount={}",
        cfg.recipient,
        encode_component(&charge.amount)
    );
    if !charge.token.eq_ignore_ascii_case("SOL") {
        url.push_str(&format!("&spl-token={}", encode_component(&charge.token)));
    }
    url.push_str(&format!("&reference={reference}"));
    url.push_str(&format!("&label={}", encode_component(&charge.label)));

    Ok(PaymentRequest {
        url,
        reference,
        label: charge.label.clone(),
        amount: charge.amount.clone(),
        token: charge.token.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOP: &str = "GsbwXfJraMomNxBcjK1LfJ8HPnzUnEzUcNvLYSbxNQpr";
    const USDC: &str = "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr";

    fn cfg() -> ShopConfig {
        ShopConfig {
            recipient: SHOP.to_string(),
            allowed_tokens: vec!["SOL".into(), USDC.into()],
            max_amount: "500".into(),
        }
    }

    fn charge(amount: &str, token: &str) -> Charge {
        Charge {
            label: "table-4".into(),
            amount: amount.into(),
            token: token.into(),
        }
    }

    #[test]
    fn builds_an_spl_transfer_request() {
        let r = build_payment_request(&cfg(), &charge("25", USDC), "t0").unwrap();
        assert!(r.url.starts_with(&format!("solana:{SHOP}?amount=25")));
        assert!(r.url.contains(&format!("&spl-token={USDC}")));
        assert!(r.url.contains(&format!("&reference={}", r.reference)));
        assert!(r.url.contains("&label=table-4"));
    }

    #[test]
    fn native_sol_carries_no_spl_token_parameter() {
        let r = build_payment_request(&cfg(), &charge("1.5", "SOL"), "t0").unwrap();
        assert!(!r.url.contains("spl-token"));
        assert!(r.url.contains("amount=1.5"));
    }

    #[test]
    fn reference_is_a_valid_32_byte_key() {
        let r = build_payment_request(&cfg(), &charge("25", USDC), "t0").unwrap();
        assert!(
            is_valid_address(&r.reference).is_ok(),
            "reference must decode as a 32-byte key"
        );
    }

    /// The same order charged twice in one evening is ordinary. If both charges
    /// shared a reference, the second payment would be indistinguishable from
    /// the first and one customer would be told they had already paid.
    #[test]
    fn identical_charges_get_different_references() {
        let a = build_payment_request(&cfg(), &charge("25", USDC), "t0").unwrap();
        let b = build_payment_request(&cfg(), &charge("25", USDC), "t1").unwrap();
        assert_ne!(a.reference, b.reference);
    }

    #[test]
    fn reference_is_reproducible_for_one_charge() {
        let a = derive_reference(&cfg(), &charge("25", USDC), "t0");
        let b = derive_reference(&cfg(), &charge("25", USDC), "t0");
        assert_eq!(a, b);
    }

    /// Length-prefixing guards this: without it, a label chosen by whoever types
    /// into the shop channel could collide with a different charge.
    #[test]
    fn field_boundaries_cannot_be_shifted_by_a_crafted_label() {
        let mut x = charge("25", USDC);
        x.label = "table-4".into();
        let mut y = charge("5", USDC);
        y.label = "table-42".into();
        assert_ne!(
            derive_reference(&cfg(), &x, "t"),
            derive_reference(&cfg(), &y, "t")
        );
    }

    #[test]
    fn refuses_a_token_off_the_allowlist() {
        let err = build_payment_request(&cfg(), &charge("25", "BONK"), "t0").unwrap_err();
        assert!(err.contains("allowlist"), "{err}");
    }

    #[test]
    fn refuses_an_amount_over_the_ceiling() {
        let err = build_payment_request(&cfg(), &charge("501", USDC), "t0").unwrap_err();
        assert!(err.contains("ceiling"), "{err}");
    }

    #[test]
    fn accepts_the_ceiling_exactly() {
        assert!(build_payment_request(&cfg(), &charge("500", USDC), "t0").is_ok());
    }

    #[test]
    fn refuses_a_non_decimal_amount() {
        for bad in ["25e3", "-25", "twenty", "25.0.1", ""] {
            assert!(
                build_payment_request(&cfg(), &charge(bad, USDC), "t0").is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn refuses_an_empty_label() {
        let mut c = charge("25", USDC);
        c.label = "   ".into();
        assert!(build_payment_request(&cfg(), &c, "t0").is_err());
    }

    #[test]
    fn refuses_a_malformed_recipient() {
        let mut bad = cfg();
        bad.recipient = "not-an-address".into();
        assert!(build_payment_request(&bad, &charge("25", USDC), "t0").is_err());
    }

    /// A table name is free text. `Table 4` and `Café` both occur, and an
    /// unencoded space or accent would truncate or corrupt the request.
    #[test]
    fn encodes_labels_that_are_not_url_safe() {
        let mut c = charge("25", USDC);
        c.label = "Café table 4".into();
        let r = build_payment_request(&cfg(), &c, "t0").unwrap();
        assert!(r.url.contains("label=Caf%C3%A9%20table%204"), "{}", r.url);
        assert!(!r.url.contains(' '));
    }

    #[test]
    fn decimal_comparison_handles_padding_and_precision() {
        assert_eq!(decimal_le("25", "500"), Some(true));
        assert_eq!(decimal_le("500", "500"), Some(true));
        assert_eq!(decimal_le("500.01", "500"), Some(false));
        assert_eq!(decimal_le("0025", "25"), Some(true));
        assert_eq!(decimal_le("25.10", "25.1"), Some(true));
        assert_eq!(decimal_le("9", "10"), Some(true));
        assert_eq!(decimal_le("abc", "10"), None);
    }
}
