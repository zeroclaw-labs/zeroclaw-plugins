mod common;

use nanosol::pubkey::{LEGACY_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID};
use spl_transfer_build::transfer::execute_component_input;

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
