use token_risk_check::core::{
    assess_risk, compute_concentration, decode_mint_account, format_summary, validate_mint_address,
    Config, HolderBalance, RiskLevel, DEFAULT_RPC_URL,
};
use std::collections::HashMap;

fn fake_mint_account(
    mint_authority_present: bool,
    freeze_authority_present: bool,
    supply: u64,
    decimals: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; 82];
    data[0..4].copy_from_slice(&(mint_authority_present as u32).to_le_bytes());
    data[36..44].copy_from_slice(&supply.to_le_bytes());
    data[44] = decimals;
    data[45] = 1;
    data[46..50].copy_from_slice(&(freeze_authority_present as u32).to_le_bytes());
    data
}

#[test]
fn decode_mint_account_reads_authorities_supply_and_decimals() {
    let data = fake_mint_account(true, false, 1_000_000_000, 9);
    let info = decode_mint_account(&data).expect("valid mint account");
    assert!(info.mint_authority_present);
    assert!(!info.freeze_authority_present);
    assert_eq!(info.supply, 1_000_000_000);
    assert_eq!(info.decimals, 9);
}

#[test]
fn decode_mint_account_rejects_short_data() {
    let data = vec![0u8; 40];
    let result = decode_mint_account(&data);
    assert!(result.is_err());
}

#[test]
fn concentration_handles_empty_and_zero_supply_safely() {
    let stats = compute_concentration(&[], 1_000);
    assert_eq!(stats.top1_pct, 0.0);
    assert_eq!(stats.top10_pct, 0.0);

    let holders = vec![HolderBalance { amount: 500 }];
    let stats = compute_concentration(&holders, 0);
    assert_eq!(stats.top1_pct, 0.0);
}

#[test]
fn concentration_computes_top1_and_top10_percentages() {
    let holders = vec![
        HolderBalance { amount: 500 },
        HolderBalance { amount: 200 },
        HolderBalance { amount: 100 },
    ];
    let stats = compute_concentration(&holders, 1_000);
    assert_eq!(stats.top1_pct, 50.0);
    assert_eq!(stats.top10_pct, 80.0);
}

#[test]
fn assess_risk_is_green_when_authorities_renounced_and_distributed() {
    let mint = decode_mint_account(&fake_mint_account(false, false, 1_000_000, 6)).unwrap();
    let concentration = compute_concentration(
        &[
            HolderBalance { amount: 50_000 },
            HolderBalance { amount: 40_000 },
        ],
        1_000_000,
    );
    let verdict = assess_risk(&mint, &concentration);
    assert_eq!(verdict.level, RiskLevel::Green);
}

#[test]
fn assess_risk_is_red_when_freeze_authority_present_even_if_distribution_is_fine() {
    let mint = decode_mint_account(&fake_mint_account(false, true, 1_000_000, 6)).unwrap();
    let concentration = compute_concentration(&[HolderBalance { amount: 10_000 }], 1_000_000);
    let verdict = assess_risk(&mint, &concentration);
    assert_eq!(verdict.level, RiskLevel::Red);
    assert!(verdict.reasons.iter().any(|r| r.contains("freeze authority")));
}

#[test]
fn assess_risk_is_red_when_top_holder_dominates_even_with_no_authorities() {
    let mint = decode_mint_account(&fake_mint_account(false, false, 1_000_000, 6)).unwrap();
    let concentration = compute_concentration(&[HolderBalance { amount: 600_000 }], 1_000_000);
    let verdict = assess_risk(&mint, &concentration);
    assert_eq!(verdict.level, RiskLevel::Red);
}

#[test]
fn assess_risk_is_amber_when_only_mint_authority_present() {
    let mint = decode_mint_account(&fake_mint_account(true, false, 1_000_000, 6)).unwrap();
    let concentration = compute_concentration(&[HolderBalance { amount: 10_000 }], 1_000_000);
    let verdict = assess_risk(&mint, &concentration);
    assert_eq!(verdict.level, RiskLevel::Amber);
}

#[test]
fn format_summary_is_compact_and_includes_verdict_and_reasons() {
    let mint = decode_mint_account(&fake_mint_account(false, true, 1_000_000, 6)).unwrap();
    let concentration = compute_concentration(&[HolderBalance { amount: 10_000 }], 1_000_000);
    let verdict = assess_risk(&mint, &concentration);
    let summary = format_summary("So11111111111111111111111111111111111111112", &mint, &verdict);
    assert!(summary.contains("RED"));
    assert!(summary.contains("freeze authority"));
    assert!(summary.len() < 1000);
}

#[test]
fn validate_mint_address_accepts_well_known_mint() {
    assert!(validate_mint_address("So11111111111111111111111111111111111111112").is_ok());
}

#[test]
fn validate_mint_address_rejects_garbage() {
    assert!(validate_mint_address("not-a-real-address").is_err());
    assert!(validate_mint_address("").is_err());
}

#[test]
fn config_empty_section_falls_back_to_default_rpc() {
    let cfg = Config::from_section(&HashMap::new());
    assert_eq!(cfg.rpc_url, DEFAULT_RPC_URL);
}

#[test]
fn config_reads_custom_rpc_url() {
    let mut section = HashMap::new();
    section.insert("rpc_url".to_string(), "https://my-rpc.example.com".to_string());
    let cfg = Config::from_section(&section);
    assert_eq!(cfg.rpc_url, "https://my-rpc.example.com");
}
