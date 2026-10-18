use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use token_risk_check::{extensions::parse_mint_extensions, risk::{score, ConcentrationSignal}};

fn load_fixture_base64(file_name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(file_name);

    let content = fs::read_to_string(path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    let b64_str = json["result"]["value"]["data"][0].as_str().unwrap();
    STANDARD.decode(b64_str).unwrap()
}

#[test]
fn test_real_mint_14tqdo_matches_live_result() {
    let data = load_fixture_base64("real_mint_14Tqdo.json");
    
    // Parse extensions
    let ext = parse_mint_extensions(&data).unwrap();

    // Verify it parsed active mint/freeze authorities
    assert!(ext.mint_authority.is_some(), "Mint authority should be active");
    assert!(ext.freeze_authority.is_some(), "Freeze authority should be active");
    
    // Score it with 96.2% concentration (9620 bps)
    let assessment = score(
        &ext,
        &[],
        ConcentrationSignal::Calculated(9620),
        None,
        None,
    );

    assert_eq!(assessment.risk, "red");
    
    let reasons_joined = assessment.reasons.join(" | ");
    assert!(reasons_joined.contains(">80% of supply"), "Should flag concentration");
    assert!(reasons_joined.contains("Mint authority is active"), "Should flag mint auth");
    assert!(reasons_joined.contains("Freeze authority is active"), "Should flag freeze auth");
    assert!(!ext.unknown_extensions.is_empty(), "Should have unrecognized extensions");
}

#[test]
fn test_real_mint_usdc_has_no_token2022_extensions() {
    let data = load_fixture_base64("real_mint_usdc.json");
    
    // Parse extensions - it's a legacy SPL token, so it should parse cleanly but have no extensions
    let ext = parse_mint_extensions(&data).unwrap();
    
    assert!(ext.mint_authority.is_none() || ext.mint_authority.is_some()); // either is fine for USDC
    assert!(ext.freeze_authority.is_none() || ext.freeze_authority.is_some());
    assert!(ext.permanent_delegate.is_none());
    assert!(ext.transfer_hook_program_id.is_none());
    assert!(ext.transfer_fee_config.is_none());
    assert!(ext.default_account_state.is_none());
    assert_eq!(ext.unknown_extensions.len(), 0);
}
