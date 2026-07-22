//! Host tests for invoice tool (Telegram QR card).

use brl_usdc_invoice::invoice_tool::{execute_from_args, execute_invoice, ExecuteArgs};
use std::collections::HashMap;

const MERCHANT: &str = "11111111111111111111111111111112";
const OTHER_MERCHANT: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Fixed issuance instant (unix ms): the core takes the clock as data, so the
/// host tests are deterministic and read no clock at all.
const T0: i64 = 1_700_000_000_000;

/// `execute_invoice` at the fixed test instant.
fn execute_invoice_t(args_json: &str) -> Result<String, String> {
    execute_invoice(args_json, T0)
}

fn base_config() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("pix_key".into(), "merchant@example.com".into());
    m.insert("pix_name".into(), "Loja Demo".into());
    m.insert("pix_city".into(), "Sao Paulo".into());
    m.insert("merchant_solana".into(), MERCHANT.into());
    m.insert("max_amount_brl".into(), "1000".into());
    m.insert("max_amount_usdc".into(), "200".into());
    m.insert("recipient_locked".into(), "true".into());
    m.insert("brl_per_usdc".into(), "5.5".into());
    m
}

fn args_json(amount_brl: &str, invoice_id: &str, config: &HashMap<String, String>) -> String {
    serde_json::json!({
        "amount_brl": amount_brl,
        "invoice_id": invoice_id,
        "description": "Pedido teste",
        "__config": config,
    })
    .to_string()
}

#[test]
fn empty_config_fails_clearly() {
    let err = execute_invoice_t(r#"{"amount_brl":"10.00","invoice_id":"inv-empty","__config":{}}"#)
        .unwrap_err();
    assert!(err.contains("required") || err.contains("pix_key") || err.contains("merchant"));
}

#[test]
fn over_max_amount_brl_fails() {
    let err = execute_invoice_t(&args_json("1000.01", "inv-over", &base_config())).unwrap_err();
    assert!(err.contains("exceeds max_amount_brl"));
}

#[test]
fn happy_path_has_qr() {
    let out = execute_invoice_t(&args_json("150.00", "inv-001", &base_config())).unwrap();
    assert!(out.contains("000201"));
    assert!(out.contains("api.qrserver.com"));
    assert!(out.contains("PixZClaw"));
    // v0.4: USDC leg is QR-only — the host redacts raw base58, so no raw
    // solana: line may appear; the QR link encodes the full pay URL.
    assert!(
        !out.lines().any(|l| l.trim().starts_with("solana:")),
        "raw solana: line must be omitted (host redacts it):\n{out}"
    );
    assert!(
        out.contains("```"),
        "expected fenced PIX code block:\n{out}"
    );
    assert!(out.contains("Encaminhe esta mensagem ao cliente"));
    assert!(out.contains("150.00") || out.contains("R$ 150"));
}

#[test]
fn prompt_injection_huge_amount_fails_closed() {
    let args = args_json("999999999.99", "inv-inject", &base_config());
    let err = execute_invoice_t(&args).unwrap_err();
    assert!(err.contains("exceeds"));
}

#[test]
fn prompt_injection_merchant_override_ignored_when_locked() {
    let args = ExecuteArgs {
        amount_brl: "10.00".into(),
        invoice_id: Some("inv-lock".into()),
        description: Some("locked".into()),
        payer_name: None,
        usdc_amount: None,
        merchant_override: Some(OTHER_MERCHANT.into()),
        mint_override: None,
        config: base_config(),
    };
    let out = execute_from_args(args, T0).unwrap();
    // QR encodes merchant; raw solana line omitted
    assert!(out.contains("api.qrserver.com"));
    assert!(!out.contains(OTHER_MERCHANT));
}

#[test]
fn auto_invoice_id_when_omitted() {
    let json = serde_json::json!({
        "amount_brl": "25.00",
        "description": "cafe",
        "__config": base_config(),
    })
    .to_string();
    let out = execute_invoice_t(&json).unwrap();
    assert!(out.contains("INV-") || out.contains("Fatura"));
    assert!(out.contains("api.qrserver.com"));
}

/// FURO B: two identical charges issued at different moments must be two
/// different invoices. With the old unsalted auto id both got the same
/// `INV-XXXXXXXX`, hence the same Solana Pay reference, so the payment of the
/// first marked the second `PAID ✅` with a receipt.
#[test]
fn auto_invoice_id_is_unique_per_issuance_instant() {
    let json = serde_json::json!({
        "amount_brl": "10.00",
        "__config": base_config(),
    })
    .to_string();

    let today = execute_invoice(&json, T0).unwrap();
    let tomorrow = execute_invoice(&json, T0 + 86_400_000).unwrap();

    let id_of = |card: &str| card.lines().next().unwrap().to_string();
    assert!(id_of(&today).contains("Fatura #INV-"), "{today}");
    assert_ne!(
        id_of(&today),
        id_of(&tomorrow),
        "same charge on two days must not share an invoice id"
    );
    // Both cards are otherwise complete invoices.
    assert!(tomorrow.contains("api.qrserver.com"), "{tomorrow}");
}

/// An explicit id stays the merchant's: verbatim, unaffected by the clock, so
/// its reference remains reproducible by `invoice_status` from the id alone.
#[test]
fn explicit_invoice_id_is_stable_across_instants() {
    let json = args_json("150.00", "inv-001", &base_config());
    let a = execute_invoice(&json, T0).unwrap();
    let b = execute_invoice(&json, T0 + 999_999_999).unwrap();
    assert_eq!(a, b, "explicit id must produce a byte-identical card");
    assert!(a.contains("Fatura #inv-001"), "{a}");
}

#[test]
fn watch_hint_line_on_by_default_and_off_by_config() {
    // Default (key absent) → merchant-only reminder CTA with the real id.
    let out = execute_invoice_t(&args_json("150.00", "inv-412", &base_config())).unwrap();
    let line = out
        .lines()
        .find(|l| l.starts_with("🔔"))
        .unwrap_or_else(|| panic!("watch line missing:\n{out}"));
    assert!(line.contains("(só pra você)"), "{line}");
    assert!(line.contains("avisa quando a inv-412 pagar"), "{line}");
    // Stays out of the anti-redact system line, which remains last.
    let last = out.lines().last().unwrap();
    assert!(
        last.starts_with("[sistema]") && last.contains("redact"),
        "{last}"
    );

    // watch_hint=false → line disappears entirely.
    let mut cfg = base_config();
    cfg.insert("watch_hint".into(), "false".into());
    let off = execute_invoice_t(&args_json("150.00", "inv-412", &cfg)).unwrap();
    assert!(!off.contains('🔔'), "watch line must vanish:\n{off}");
    assert!(
        off.contains("api.qrserver.com"),
        "card otherwise intact:\n{off}"
    );

    // Explicit truthy value keeps it on.
    cfg.insert("watch_hint".into(), "yes".into());
    let on = execute_invoice_t(&args_json("150.00", "inv-412", &cfg)).unwrap();
    assert!(on.contains("avisa quando a inv-412 pagar"), "{on}");
}

#[test]
fn invalid_json_fails() {
    assert!(execute_invoice_t("not-json")
        .unwrap_err()
        .contains("invalid arguments"));
}
