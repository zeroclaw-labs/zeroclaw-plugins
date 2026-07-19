//! Brazilian invoice memo convention: `INV=<id> BRL=<amount>`.

pub fn build_invoice_memo(invoice_id: &str, amount_brl: Option<&str>, extra: Option<&str>) -> Result<String, String> {
    let inv = invoice_id.trim();
    if inv.is_empty() {
        return Err("invoice_id is required".into());
    }
    if inv.len() > 64 || inv.chars().any(|c| c.is_whitespace()) {
        return Err("invoice_id must be a single token ≤64 chars".into());
    }
    let mut memo = format!("INV={inv}");
    if let Some(brl) = amount_brl {
        let brl = brl.trim();
        if !brl.is_empty() {
            memo.push_str(&format!(" BRL={brl}"));
        }
    }
    if let Some(extra) = extra {
        let extra = extra.trim();
        if !extra.is_empty() {
            memo.push(' ');
            memo.push_str(extra);
        }
    }
    if memo.len() > 566 {
        // SPL memo practical limit for a single instruction.
        return Err("memo too long".into());
    }
    Ok(memo)
}

pub fn memo_contains_invoice(memo: &str, invoice_id: &str) -> bool {
    let needle = format!("INV={}", invoice_id.trim());
    // Token-aware: "INV=412" must not match "INV=4120".
    memo.split_whitespace().any(|tok| tok == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_matches() {
        let m = build_invoice_memo("412", Some("25.00"), Some("mesa4")).unwrap();
        assert_eq!(m, "INV=412 BRL=25.00 mesa4");
        assert!(memo_contains_invoice(&m, "412"));
        assert!(!memo_contains_invoice(&m, "413"));
    }
}
