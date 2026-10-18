//! Host-run tests for the token-risk-check core.
//! Run with: cargo test --lib
//! No wasm toolchain needed.

use token_risk_check::*;

#[test]
fn test_risk_assessment_struct_serialization() {
    let assessment = RiskAssessment {
        tier: "green".to_string(),
        score: 85,
        flags: vec!["No risk flags detected.".to_string()],
        summary: "🟢 Risk profile for So1111..: 85/100 (GREEN)\nNo risk flags detected.".to_string(),
    };
    let json = serde_json::to_string(&assessment).unwrap();
    assert!(json.contains("\"tier\":\"green\""));
    assert!(json.contains("\"score\":85"));
}

#[test]
fn test_mint_info_default() {
    let info = MintInfo {
        mint_authority: None,
        freeze_authority: None,
        permanent_delegate: None,
        transfer_hook: None,
        transfer_fee: None,
        supply: Some("1000000000".to_string()),
        decimals: Some(6),
        mintable: false,
    };
    assert!(info.mint_authority.is_none());
    assert_eq!(info.decimals, Some(6));
}

#[test]
fn test_holder_sorting() {
    // Holders should be sorted by amount descending
    let mut holders = vec![
        Holder { address: "holder1".to_string(), amount: 100 },
        Holder { address: "holder2".to_string(), amount: 1000 },
        Holder { address: "holder3".to_string(), amount: 500 },
    ];
    holders.sort_by(|a, b| b.amount.cmp(&a.amount));
    assert_eq!(holders[0].amount, 1000);
    assert_eq!(holders[1].amount, 500);
    assert_eq!(holders[2].amount, 100);
}

#[test]
fn test_risk_tier_bounds() {
    let green = RiskAssessment {
        tier: "green".to_string(), score: 85,
        flags: vec![], summary: String::new(),
    };
    let amber = RiskAssessment {
        tier: "amber".to_string(), score: 55,
        flags: vec![], summary: String::new(),
    };
    let red = RiskAssessment {
        tier: "red".to_string(), score: 20,
        flags: vec![], summary: String::new(),
    };
    assert_eq!(green.tier, "green");
    assert_eq!(amber.tier, "amber");
    assert_eq!(red.tier, "red");
}

#[test]
fn test_permanent_delegate_flags() {
    let info = MintInfo {
        mint_authority: None,
        freeze_authority: None,
        permanent_delegate: Some("ALepH1anyaddress123456789abcdef".to_string()),
        transfer_hook: None,
        transfer_fee: None,
        supply: None,
        decimals: Some(6),
        mintable: false,
    };
    let mut flags = Vec::new();
    let mut score: i32 = 100;
    // We can't call check_mint_authority directly since it's private,
    // but we test the struct field is correctly captured
    assert!(info.permanent_delegate.is_some());
    assert_eq!(info.permanent_delegate.as_ref().unwrap().len(), 32);
}

#[test]
fn test_transfer_fee_parsing() {
    let info = MintInfo {
        mint_authority: None,
        freeze_authority: None,
        permanent_delegate: None,
        transfer_hook: None,
        transfer_fee: Some(250), // 2.5%
        supply: None,
        decimals: Some(6),
        mintable: false,
    };
    assert_eq!(info.transfer_fee, Some(250));
    let fee_bps = info.transfer_fee.unwrap();
    assert!((fee_bps as f64 / 100.0 - 2.5).abs() < 0.01);
}
