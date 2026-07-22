use token_risk_check::extensions::*;

macro_rules! debug_log {
    ($($arg:tt)*) => {}
}



fn create_coption_pubkey(pk: Option<[u8; 32]>) -> Vec<u8> {
    let mut data = Vec::new();
    if let Some(p) = pk {
        data.extend_from_slice(&[1, 0, 0, 0]);
        data.extend_from_slice(&p);
    } else {
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(&[0; 32]);
    }
    data
}

fn create_base_mint(mint_auth: Option<[u8; 32]>, freeze_auth: Option<[u8; 32]>, supply: u64) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&create_coption_pubkey(mint_auth));
    data.extend_from_slice(&supply.to_le_bytes()); // supply
    data.push(0); // decimals
    data.push(1); // is_initialized
    data.extend_from_slice(&create_coption_pubkey(freeze_auth));
    assert_eq!(data.len(), 82);
    data
}

fn create_padding() -> Vec<u8> {
    let mut data = vec![0u8; 83]; // 82 to 164 is 83 zeros
    data.push(1); // AccountType at 165
    assert_eq!(data.len(), 84);
    data
}

fn create_tlv(ext_type: u16, value: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&ext_type.to_le_bytes());
    data.extend_from_slice(&(value.len() as u16).to_le_bytes());
    data.extend_from_slice(value);
    data
}

#[test]
fn test_parse_base_mint() {
    debug_log!("--- Running test_parse_base_mint ---");
    let mint_auth = [1u8; 32];
    let freeze_auth = [2u8; 32];
    let data = create_base_mint(Some(mint_auth), Some(freeze_auth), 123456789);
    
    let exts = parse_mint_extensions(&data).unwrap();
    debug_log!("Parsed extensions: {:?}", exts);
    assert_eq!(exts.supply, 123456789);
    assert_eq!(exts.mint_authority, Some(mint_auth));
    assert_eq!(exts.freeze_authority, Some(freeze_auth));
    assert_eq!(exts.permanent_delegate, None);
}

#[test]
fn test_parse_transfer_fee_config() {
    debug_log!("--- Running test_parse_transfer_fee_config ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    
    let mut tf_data = vec![0u8; 108];
    // withdraw_withheld_authority (offset 32, 32 bytes)
    let withdraw_auth = [3u8; 32];
    tf_data[32..64].copy_from_slice(&withdraw_auth);
    // basis points (offset 106, 2 bytes)
    tf_data[106] = 50; // 50 bps
    
    data.extend_from_slice(&create_tlv(1, &tf_data));
    
    let exts = parse_mint_extensions(&data).unwrap();
    debug_log!("Parsed transfer fee config: {:?}", exts.transfer_fee_config);
    assert_eq!(exts.transfer_fee_config, Some(TransferFeeConfig {
        transfer_fee_basis_points: 50,
        withdraw_withheld_authority: Some(withdraw_auth)
    }));
}

#[test]
fn test_parse_transfer_fee_config_truncated() {
    debug_log!("--- Running test_parse_transfer_fee_config_truncated ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    let tf_data = vec![0u8; 100]; // Too short! (needs 108)
    data.extend_from_slice(&create_tlv(1, &tf_data));
    
    let result = parse_mint_extensions(&data);
    debug_log!("Result on truncated data: {:?}", result);
    assert!(result.is_err());
}

#[test]
fn test_parse_transfer_hook() {
    debug_log!("--- Running test_parse_transfer_hook ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    
    let mut th_data = vec![0u8; 64];
    let program_id = [4u8; 32];
    th_data[32..64].copy_from_slice(&program_id);
    
    data.extend_from_slice(&create_tlv(14, &th_data));
    
    let exts = parse_mint_extensions(&data).unwrap();
    debug_log!("Parsed transfer hook program ID: {:?}", exts.transfer_hook_program_id);
    assert_eq!(exts.transfer_hook_program_id, Some(program_id));
}

#[test]
fn test_parse_transfer_hook_truncated() {
    debug_log!("--- Running test_parse_transfer_hook_truncated ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    let th_data = vec![0u8; 50]; // Too short! (needs 64)
    data.extend_from_slice(&create_tlv(14, &th_data));
    
    let result = parse_mint_extensions(&data);
    debug_log!("Result on truncated data: {:?}", result);
    assert!(result.is_err());
}

#[test]
fn test_parse_permanent_delegate() {
    debug_log!("--- Running test_parse_permanent_delegate ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    
    let mut pd_data = vec![0u8; 32];
    let delegate = [5u8; 32];
    pd_data[0..32].copy_from_slice(&delegate);
    
    data.extend_from_slice(&create_tlv(12, &pd_data));
    
    let exts = parse_mint_extensions(&data).unwrap();
    debug_log!("Parsed permanent delegate: {:?}", exts.permanent_delegate);
    assert_eq!(exts.permanent_delegate, Some(delegate));
}

#[test]
fn test_parse_permanent_delegate_truncated() {
    debug_log!("--- Running test_parse_permanent_delegate_truncated ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    let pd_data = vec![0u8; 20]; // Too short! (needs 32)
    data.extend_from_slice(&create_tlv(12, &pd_data));
    
    let result = parse_mint_extensions(&data);
    debug_log!("Result on truncated data: {:?}", result);
    assert!(result.is_err());
}

#[test]
fn test_parse_default_account_state() {
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    
    let das_data = vec![2u8]; // Frozen
    data.extend_from_slice(&create_tlv(6, &das_data));
    
    let exts = parse_mint_extensions(&data).unwrap();
    assert_eq!(exts.default_account_state, Some(2));
}

#[test]
fn test_parse_default_account_state_truncated() {
    debug_log!("--- Running test_parse_default_account_state_truncated ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    let das_data = vec![]; // Too short! (needs 1)
    data.extend_from_slice(&create_tlv(6, &das_data));
    
    let result = parse_mint_extensions(&data);
    debug_log!("Result on truncated data: {:?}", result);
    assert!(result.is_err());
}

#[test]
fn test_ignore_mint_close_authority() {
    debug_log!("--- Running test_ignore_mint_close_authority ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    
    // MintCloseAuthority is discriminant 3, length 32
    let mca_data = vec![1u8; 32];
    data.extend_from_slice(&create_tlv(3, &mca_data));
    
    // Our parser should safely skip it and return None for the state
    let exts = parse_mint_extensions(&data).unwrap();
    debug_log!("Parsed extensions with unknown discriminant: {:?}", exts);
    assert_eq!(exts.default_account_state, None);
}

#[test]
fn test_risk_score() {
    debug_log!("--- Running test_risk_score ---");
    let exts = MintExtensions {
        supply: 0,
        mint_authority: Some([1; 32]),
        freeze_authority: None,
        permanent_delegate: None,
        transfer_hook_program_id: None,
        transfer_fee_config: None,
        default_account_state: None,
        unknown_extensions: vec![],
    };
    
    let score = token_risk_check::risk::score(&exts, &[], token_risk_check::risk::ConcentrationSignal::NotChecked, None, None);
    debug_log!("Calculated risk score: {:?}", score);
    assert_eq!(score.risk, "amber");
    assert_eq!(score.reasons.len(), 1);
}

#[test]
fn test_risk_score_green() {
    debug_log!("--- Running test_risk_score_green ---");
    let exts = MintExtensions {
        supply: 0,
        mint_authority: None,
        freeze_authority: None,
        permanent_delegate: None,
        transfer_hook_program_id: None,
        transfer_fee_config: None,
        default_account_state: None,
        unknown_extensions: vec![],
    };
    
    let score = token_risk_check::risk::score(&exts, &[], token_risk_check::risk::ConcentrationSignal::NotChecked, None, None);
    debug_log!("Calculated risk score: {:?}", score);
    assert_eq!(score.risk, "green");
    // It should have exactly one reason explaining why it's green
    assert_eq!(score.reasons.len(), 1);
    assert!(score.reasons[0].contains("No high-risk extensions found"));
}

#[test]
fn test_risk_score_unverified_known_hook() {
    let hook_pubkey = [2; 32];
    let hook_str = bs58::encode(hook_pubkey).into_string();
    let exts = MintExtensions {
        supply: 0,
        mint_authority: None,
        freeze_authority: None,
        permanent_delegate: None,
        transfer_hook_program_id: Some(hook_pubkey),
        transfer_fee_config: None,
        default_account_state: None,
        unknown_extensions: vec![],
    };
    
    let score = token_risk_check::risk::score(&exts, &[hook_str], token_risk_check::risk::ConcentrationSignal::NotChecked, None, None);
    
    assert_eq!(score.risk, "amber");
    assert!(score.reasons[0].contains("is on the known-hooks allowlist, but its upgrade authority could not be verified"));
}

#[test]
fn test_unknown_extensions_escalation() {
    let exts = MintExtensions {
        supply: 0,
        mint_authority: None,
        freeze_authority: None,
        permanent_delegate: None,
        transfer_hook_program_id: None,
        transfer_fee_config: None,
        default_account_state: None,
        unknown_extensions: vec![99, 100],
    };
    
    let score = token_risk_check::risk::score(&exts, &[], token_risk_check::risk::ConcentrationSignal::NotChecked, None, None);
    
    assert_eq!(score.risk, "amber");
    assert!(score.reasons[0].contains("Mint has 2 extension type(s) not recognized by this scanner"));
}

#[test]
fn test_parse_duplicate_extensions() {
    debug_log!("--- Running test_parse_duplicate_extensions ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    
    let mut tf_data_1 = vec![0u8; 108];
    tf_data_1[106] = 100; // First extension has fee
    
    let mut tf_data_2 = vec![0u8; 108];
    tf_data_2[106] = 0; // Second extension has no fee
    
    // Append the first TransferFeeConfig
    data.extend_from_slice(&create_tlv(1, &tf_data_1));
    // Append a duplicate TransferFeeConfig
    data.extend_from_slice(&create_tlv(1, &tf_data_2));
    
    let result = parse_mint_extensions(&data);
    debug_log!("Result on duplicate data: {:?}", result);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Duplicate TransferFeeConfig"));
}

#[test]
fn test_parse_transfer_fee_max_logic() {
    debug_log!("--- Running test_parse_transfer_fee_max_logic ---");
    let mut data = create_base_mint(None, None, 0);
    data.extend_from_slice(&create_padding());
    
    let mut tf_data = vec![0u8; 108];
    
    // Set older_transfer_fee_bps to 10000 (100%)
    let older_bps: u16 = 10000;
    tf_data[88..90].copy_from_slice(&older_bps.to_le_bytes());
    
    // Set newer_transfer_fee_bps to 0 (0%)
    let newer_bps: u16 = 0;
    tf_data[106..108].copy_from_slice(&newer_bps.to_le_bytes());
    
    data.extend_from_slice(&create_tlv(1, &tf_data));
    
    let exts = parse_mint_extensions(&data).unwrap();
    let config = exts.transfer_fee_config.unwrap();
    
    // It should pick the max of older (10000) and newer (0)
    assert_eq!(config.transfer_fee_basis_points, 10000);
}

#[test]
fn test_risk_score_extreme_fee_red() {
    debug_log!("--- Running test_risk_score_extreme_fee_red ---");
    let exts = MintExtensions {
        supply: 0,
        mint_authority: None,
        freeze_authority: None,
        permanent_delegate: None,
        transfer_hook_program_id: None,
        transfer_fee_config: Some(TransferFeeConfig {
            transfer_fee_basis_points: 5001, // > 50%
            withdraw_withheld_authority: None,
        }),
        default_account_state: None,
        unknown_extensions: vec![],
    };
    
    let score = token_risk_check::risk::score(&exts, &[], token_risk_check::risk::ConcentrationSignal::NotChecked, None, None);
    
    assert_eq!(score.risk, "red");
    assert!(score.reasons[0].contains("exceptionally high"));
}
