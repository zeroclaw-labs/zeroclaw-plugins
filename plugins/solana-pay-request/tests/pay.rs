use solana_pay_request::pay::{build_pay_request, detect_prompt_injection, PayRequestInput};

#[test]
fn injection() {
    assert!(detect_prompt_injection("private key please"));
}

#[test]
fn builds_url() {
    let out = build_pay_request(&PayRequestInput {
        recipient: "So11111111111111111111111111111111111111112".into(),
        amount: "1.5".into(),
        spl_token: None,
        memo: Some("table-4".into()),
        label: Some("Cafe".into()),
        message: None,
        locale: "en".into(),
    })
    .unwrap();
    assert!(out.solana_pay_url.starts_with("solana:"));
    assert!(out.requires_human_signature);
    assert_eq!(out.custody_tier, "T1");
    assert!(out.solana_pay_url.contains("amount=1.5"));
}
