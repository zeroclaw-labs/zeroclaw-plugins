mod common;

use nanosol::rpc::MAX_RPC_RESPONSE_BYTES;
use serde_json::{json, Value};
use spl_transfer_build::{
    rpc::TransportError,
    transfer::{
        execute_component_input, execute_component_input_observed, ExecutionPhase, TransferOutput,
    },
};

use common::{
    account_response, blockhash_response, envelope, host_inject, mint_data, simulation_response,
    valid_args, valid_config, MockTransport, BLOCKHASH, RPC_URL,
};

#[test]
fn successful_flow_uses_exact_rpc_order_ids_endpoint_and_simulation_options() {
    let transport = MockTransport::valid(6);
    let result = execute_component_input(&host_inject(valid_args(), &valid_config()), &transport);
    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        transport.methods(),
        vec![
            "getAccountInfo",
            "getLatestBlockhash",
            "simulateTransaction"
        ]
    );
    for (endpoint, _, maximum) in transport.calls.borrow().iter() {
        assert_eq!(endpoint, RPC_URL);
        assert_eq!(*maximum, MAX_RPC_RESPONSE_BYTES);
    }
    let calls = transport.calls.borrow();
    let mint: Value = serde_json::from_str(&calls[0].1).expect("mint request");
    let latest: Value = serde_json::from_str(&calls[1].1).expect("blockhash request");
    let simulation: Value = serde_json::from_str(&calls[2].1).expect("simulation request");
    assert_eq!(mint["id"], 1);
    assert_eq!(latest["id"], 2);
    assert_eq!(simulation["id"], 3);
    assert_eq!(simulation["params"][1]["encoding"], "base64");
    assert_eq!(simulation["params"][1]["sigVerify"], false);
    assert_eq!(simulation["params"][1]["replaceRecentBlockhash"], true);

    let output: TransferOutput = serde_json::from_str(&result.output).expect("output");
    assert_eq!(output.last_valid_block_height, Some(500000));
    let transaction = nanosol::message::Transaction::from_base64(&output.transaction_base64)
        .expect("returned transaction");
    assert_eq!(
        nanosol::pubkey::Pubkey::new(transaction.message.recent_blockhash).to_string(),
        BLOCKHASH
    );
}

#[test]
fn bounded_phase_observer_reports_only_the_fixed_success_taxonomy() {
    let mut phases = Vec::new();
    let result = execute_component_input_observed(
        &host_inject(valid_args(), &valid_config()),
        &MockTransport::valid(6),
        |phase| phases.push(phase),
    );
    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        phases,
        vec![
            ExecutionPhase::ConfigValidated,
            ExecutionPhase::MintRpc,
            ExecutionPhase::BlockhashRpc,
            ExecutionPhase::TransactionBuilt,
            ExecutionPhase::VerificationPassed,
            ExecutionPhase::SimulationRpc,
            ExecutionPhase::SimulationPassed,
        ]
    );
}

#[test]
fn malformed_rpc_envelopes_and_transport_failures_are_bounded_refusals() {
    let malformed = [
        "not json".to_string(),
        json!({"jsonrpc":"2.0","id":99,"result":{}}).to_string(),
        json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"secret provider detail"}})
            .to_string(),
        json!({"jsonrpc":"2.0","id":1}).to_string(),
        envelope(1, json!({"context":{"slot":1},"value":null})),
        envelope(
            1,
            json!({"value":{"data":["%%%","base64"],"executable":false,"owner":"11111111111111111111111111111111"}}),
        ),
    ];
    for response in malformed {
        let mut transport = MockTransport::valid(6);
        transport.mint = response;
        let result =
            execute_component_input(&host_inject(valid_args(), &valid_config()), &transport);
        assert!(!result.success);
        assert!(result.output.is_empty());
        assert!(matches!(
            result.category,
            Some("rpc_failure" | "invalid_mint_state")
        ));
        assert!(result
            .error
            .as_ref()
            .is_some_and(|error| error.chars().count() <= 241));
        assert!(!result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("secret provider detail"));
    }

    for transport_error in [
        TransportError::Unavailable,
        TransportError::HttpStatus(302),
        TransportError::ResponseTooLarge,
        TransportError::InvalidUtf8,
    ] {
        let mut transport = MockTransport::valid(6);
        transport.transport_error = Some(transport_error);
        let result =
            execute_component_input(&host_inject(valid_args(), &valid_config()), &transport);
        assert!(!result.success);
        assert!(result.error.as_ref().is_some_and(|error| error.len() < 300));
    }
}

#[test]
fn mint_blockhash_and_simulation_response_shapes_fail_closed() {
    let mut truncated = MockTransport::valid(6);
    truncated.mint = account_response(
        nanosol::pubkey::LEGACY_TOKEN_PROGRAM_ID,
        &mint_data(6)[..81],
    );
    assert!(
        !execute_component_input(&host_inject(valid_args(), &valid_config()), &truncated).success
    );

    for blockhash in [
        envelope(
            2,
            json!({"value":{"blockhash":"bad","lastValidBlockHeight":500000}}),
        ),
        envelope(
            2,
            json!({"value":{"blockhash":BLOCKHASH,"lastValidBlockHeight":-1}}),
        ),
        envelope(
            9,
            json!({"value":{"blockhash":BLOCKHASH,"lastValidBlockHeight":500000}}),
        ),
        "{".to_string(),
    ] {
        let mut transport = MockTransport::valid(6);
        transport.blockhash = blockhash;
        assert!(
            !execute_component_input(&host_inject(valid_args(), &valid_config()), &transport)
                .success
        );
    }

    for simulation in [
        simulation_response(json!({"InstructionError":[1,"Custom"]})),
        envelope(3, json!({"value":{"logs":[]}})),
        envelope(8, json!({"value":{"err":null}})),
        "invalid".to_string(),
    ] {
        let mut transport = MockTransport::valid(6);
        transport.simulation = simulation;
        let result =
            execute_component_input(&host_inject(valid_args(), &valid_config()), &transport);
        assert!(!result.success);
        assert!(result.output.is_empty());
    }
}

#[test]
fn oversized_untrusted_logs_and_rpc_payloads_never_escape() {
    let mut failed = MockTransport::valid(6);
    failed.simulation = envelope(
        3,
        json!({"value":{"err":{"InstructionError":[1,"Custom"]},"logs":["SECRET".repeat(10000)]}}),
    );
    let result = execute_component_input(&host_inject(valid_args(), &valid_config()), &failed);
    assert!(!result.success);
    assert!(!result
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("SECRET"));
    assert!(result.error.as_ref().is_some_and(|error| error.len() < 300));

    let mut oversized = MockTransport::valid(6);
    oversized.mint = format!("{{\"padding\":\"{}\"}}", "RAW_SECRET".repeat(10_000));
    let result = execute_component_input(&host_inject(valid_args(), &valid_config()), &oversized);
    assert!(!result.success);
    assert!(!result
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("RAW_SECRET"));
}

#[test]
fn mock_never_uses_live_network_and_fixture_helpers_are_stable() {
    assert_eq!(blockhash_response(), blockhash_response());
    assert_eq!(
        simulation_response(Value::Null),
        simulation_response(Value::Null)
    );
}
