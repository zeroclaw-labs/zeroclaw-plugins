mod common;

use nanosol::{
    mint::{parse_mint_account, MintExtensionType, TOKEN_2022_TLV_OFFSET},
    pubkey::{LEGACY_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID},
    rpc::RpcAccount,
};
use sha2::{Digest, Sha256};
use spl_token_2022_interface::{
    extension::{
        transfer_fee::TransferFeeConfig, BaseStateWithExtensionsMut, ExtensionType,
        PodStateWithExtensionsMut,
    },
    pod::PodMint,
};
use spl_transfer_build::transfer::{execute_component_input, TransferOutput};

use common::{
    account_response, host_inject, mint_data, token_2022_data, valid_args, valid_config,
    MockTransport,
};

#[test]
fn legacy_mint_and_extension_free_token_2022_have_explicit_policy() {
    let legacy = execute_component_input(
        &host_inject(valid_args(), &valid_config()),
        &MockTransport::valid(6),
    );
    assert!(legacy.success, "{:?}", legacy.error);

    let mut disabled_transport = MockTransport::valid(6);
    disabled_transport.mint = account_response(TOKEN_2022_PROGRAM_ID, &mint_data(6));
    let disabled = execute_component_input(
        &host_inject(valid_args(), &valid_config()),
        &disabled_transport,
    );
    assert!(!disabled.success);
    assert!(disabled
        .error
        .as_deref()
        .is_some_and(|error| error.contains("explicitly enable")));

    let mut enabled_config = valid_config();
    enabled_config.insert("allow_token_2022".to_string(), "true".to_string());
    let mut enabled_transport = MockTransport::valid(6);
    enabled_transport.mint = account_response(TOKEN_2022_PROGRAM_ID, &mint_data(6));
    let enabled = execute_component_input(
        &host_inject(valid_args(), &enabled_config),
        &enabled_transport,
    );
    assert!(enabled.success, "{:?}", enabled.error);
}

#[test]
fn token_2022_summary_contains_net_amount_qualifier() {
    const QUALIFIER: &str = "Token-2022: displayed amount is the transfer amount; net received may depend on mint extensions as reported by the configured RPC.";

    let mut token_2022_config = valid_config();
    token_2022_config.insert("allow_token_2022".to_string(), "true".to_string());
    let mut token_2022_transport = MockTransport::valid(6);
    // The independent RPC fixture is the extension-free 82-byte Mint layout.
    token_2022_transport.mint = account_response(TOKEN_2022_PROGRAM_ID, &mint_data(6));
    let token_2022 = execute_component_input(
        &host_inject(valid_args(), &token_2022_config),
        &token_2022_transport,
    );
    assert!(token_2022.success, "{:?}", token_2022.error);
    let token_2022_output: TransferOutput =
        serde_json::from_str(&token_2022.output).expect("Token-2022 output");
    assert!(token_2022_output.summary.contains(QUALIFIER));

    let legacy = execute_component_input(
        &host_inject(valid_args(), &valid_config()),
        &MockTransport::valid(6),
    );
    assert!(legacy.success, "{:?}", legacy.error);
    let legacy_output: TransferOutput =
        serde_json::from_str(&legacy.output).expect("legacy output");
    assert!(!legacy_output.summary.contains(QUALIFIER));
    assert!(!legacy_output.summary.contains("Token-2022:"));
}

/// Generate a Mint account through the official Token-2022 interface rather
/// than reproducing the TLV layout by hand. Oracle: spl-token-2022-interface
/// 3.1.1, source commit e18f9c6f9bf6044b934f48e3090e8e59e4820f02.
fn officially_packed_transfer_fee_mint() -> Vec<u8> {
    let length =
        ExtensionType::try_calculate_account_len::<PodMint>(&[ExtensionType::TransferFeeConfig])
            .expect("official mint length");
    let mut bytes = vec![0; length];
    {
        let mut state = PodStateWithExtensionsMut::<PodMint>::unpack_uninitialized(&mut bytes)
            .expect("official uninitialized mint");
        state.base.decimals = 6;
        state.base.is_initialized = true.into();
        state
            .init_extension::<TransferFeeConfig>(true)
            .expect("official extension initialization");
        state
            .init_account_type()
            .expect("official Mint account type");
    }
    bytes
}

#[test]
fn official_token_2022_packed_fixture_is_parsed_and_refused_by_policy() {
    let bytes = officially_packed_transfer_fee_mint();
    assert_eq!(bytes[165], 1, "official AccountType::Mint offset");
    assert_eq!(
        u16::from_le_bytes([
            bytes[TOKEN_2022_TLV_OFFSET],
            bytes[TOKEN_2022_TLV_OFFSET + 1]
        ]),
        u16::from(ExtensionType::TransferFeeConfig)
    );
    let official_extension_length = std::mem::size_of::<TransferFeeConfig>();
    assert_eq!(
        u16::from_le_bytes([
            bytes[TOKEN_2022_TLV_OFFSET + 2],
            bytes[TOKEN_2022_TLV_OFFSET + 3]
        ]),
        u16::try_from(official_extension_length).expect("extension length")
    );

    let fixture_sha256 = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(
        fixture_sha256, "3cbb482fdcae9086d23a0d76309e4865dc0ece0222d1972bbf4f3275466d0ba1",
        "officially packed fixture changed"
    );
    let parsed = parse_mint_account(&RpcAccount {
        owner: TOKEN_2022_PROGRAM_ID,
        executable: false,
        data: bytes.clone(),
    })
    .expect("nanosol parses official fixture");
    assert_eq!(parsed.decimals, 6);
    assert_eq!(parsed.extensions.len(), 1);
    assert_eq!(
        parsed.extensions[0].extension_type,
        MintExtensionType::TransferFeeConfig
    );
    assert_eq!(
        usize::from(parsed.extensions[0].data_length),
        official_extension_length
    );

    let mut config = valid_config();
    config.insert("allow_token_2022".to_string(), "true".to_string());
    let mut transport = MockTransport::valid(6);
    transport.mint = account_response(TOKEN_2022_PROGRAM_ID, &bytes);
    let result = execute_component_input(&host_inject(valid_args(), &config), &transport);
    assert!(!result.success);
    assert_eq!(result.category, Some("token_2022_policy"));
    assert!(result
        .error
        .as_deref()
        .is_some_and(|error| error.contains("extensions are outside the supported safe subset")));
    assert_eq!(transport.methods(), vec!["getAccountInfo"]);
}

#[test]
fn every_current_extension_discriminant_and_unknown_extensions_fail_closed() {
    let mut config = valid_config();
    config.insert("allow_token_2022".to_string(), "true".to_string());
    for discriminant in 1_u16..=28 {
        let mut transport = MockTransport::valid(6);
        transport.mint = account_response(
            TOKEN_2022_PROGRAM_ID,
            &token_2022_data(6, &[(discriminant, 0)]),
        );
        let result = execute_component_input(&host_inject(valid_args(), &config), &transport);
        assert!(!result.success, "accepted extension {discriminant}");
        assert!(result.output.is_empty());
        assert_eq!(transport.methods(), vec!["getAccountInfo"]);
    }

    let mut unknown = MockTransport::valid(6);
    unknown.mint = account_response(TOKEN_2022_PROGRAM_ID, &token_2022_data(6, &[(9999, 3)]));
    assert!(!execute_component_input(&host_inject(valid_args(), &config), &unknown).success);
}

#[test]
fn malformed_duplicate_wrong_owner_and_uninitialized_mints_are_refused() {
    let mut config = valid_config();
    config.insert("allow_token_2022".to_string(), "true".to_string());

    let mut fixtures = Vec::new();
    let mut malformed = token_2022_data(6, &[(14, 4)]);
    malformed.pop();
    fixtures.push(account_response(TOKEN_2022_PROGRAM_ID, &malformed));
    fixtures.push(account_response(
        TOKEN_2022_PROGRAM_ID,
        &token_2022_data(6, &[(14, 0), (14, 0)]),
    ));
    fixtures.push(account_response(SYSTEM_PROGRAM_ID, &mint_data(6)));
    let mut uninitialized = mint_data(6);
    uninitialized[45] = 0;
    fixtures.push(account_response(LEGACY_TOKEN_PROGRAM_ID, &uninitialized));

    for response in fixtures {
        let mut transport = MockTransport::valid(6);
        transport.mint = response;
        let result = execute_component_input(&host_inject(valid_args(), &config), &transport);
        assert!(!result.success);
        assert_eq!(transport.methods(), vec!["getAccountInfo"]);
    }
}
