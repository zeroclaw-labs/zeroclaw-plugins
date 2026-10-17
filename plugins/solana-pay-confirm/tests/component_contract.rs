//! The component contract: manifest identity, the T0 read-only boundary, and
//! the absence of anything that could sign or spend.

use serde_json::Value;
use solana_pay_confirm::confirm::{parameters_schema, ConfirmError, Rejection};

const SOURCE: &str = concat!(
    include_str!("../src/lib.rs"),
    include_str!("../src/confirm.rs"),
    include_str!("../src/rpc.rs")
);

#[test]
fn the_manifest_matches_the_component_identity_and_minimal_permissions() {
    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("name = \"solana-pay-confirm\""));
    assert!(manifest.contains("version = \"0.1.0\""));
    assert!(manifest.contains("wasm_path = \"solana_pay_confirm.wasm\""));
    assert!(manifest.contains("capabilities = [\"tool\"]"));
    assert!(manifest.contains("permissions = [\"http_client\", \"config_read\"]"));
    for forbidden in ["filesystem", "shell", "network_raw"] {
        assert!(!manifest.contains(forbidden), "found {forbidden}");
    }

    // `plugin-info` must equal the manifest identity.
    assert!(SOURCE.contains("const PLUGIN_NAME: &str = \"solana-pay-confirm\""));
    assert!(SOURCE.contains("const TOOL_NAME: &str = \"solana_pay_confirm\""));
    assert!(SOURCE.contains("world: \"tool-plugin\""));
}

#[test]
fn the_component_has_no_write_path_of_any_kind() {
    // T0: nothing here builds, signs, or submits. These are the names such a
    // path would have to use, and none of them appear.
    for forbidden in [
        "sendTransaction",
        "simulateTransaction",
        "requestAirdrop",
        "Transaction::new_unsigned",
        "transfer_checked(",
        "Message::compile",
        "signature_bytes",
        "private_key",
        "keypair",
        "sign(",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "found a write-path symbol in a read-only component: {forbidden}"
        );
    }
    for forbidden in ["println!", "eprintln!", "unsafe {", "wasi:logging"] {
        assert!(!SOURCE.contains(forbidden), "found {forbidden}");
    }
    assert!(SOURCE.contains("log_record("));

    // The component reaches the cluster through exactly three read builders.
    for builder in [
        "get_account_info_request",
        "get_signatures_for_address_request",
        "get_transaction_request",
    ] {
        assert!(SOURCE.contains(builder), "missing read builder {builder}");
    }
}

#[test]
fn the_schema_is_closed_and_exposes_no_operator_or_verdict_field() {
    let schema: Value = serde_json::from_str(&parameters_schema()).expect("schema JSON");
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["required"],
        serde_json::json!(["recipient", "amount", "mint", "invoice_id"])
    );
    for forbidden in [
        "reference",
        "__config",
        "rpc_url",
        "rpc_url_secondary",
        "min_commitment",
        "max_signatures_scanned",
        "commitment",
        "signature",
        "paid",
        "decimals",
        "allow_token_2022",
    ] {
        assert!(
            schema["properties"].get(forbidden).is_none(),
            "schema exposes {forbidden}"
        );
    }
}

#[test]
fn refusal_codes_and_verdict_reasons_are_stable_and_bounded() {
    assert_eq!(ConfirmError::InvalidArguments.code(), "invalid_arguments");
    assert_eq!(
        ConfirmError::RecipientNotAllowed.code(),
        "recipient_not_allowed"
    );
    assert_eq!(ConfirmError::MintNotAllowed.code(), "mint_not_allowed");
    assert_eq!(
        ConfirmError::EndpointDisagreement.code(),
        "endpoint_disagreement"
    );
    assert_eq!(ConfirmError::Token2022Disabled.code(), "token_2022_policy");

    // Every verdict reason is our own bounded sentence, not endpoint prose.
    for rejection in [
        Rejection::CommitmentTooWeak,
        Rejection::TransactionFailed,
        Rejection::UndecodableTransaction,
        Rejection::NoTokenTransfer,
        Rejection::MultipleTokenTransfers,
        Rejection::WrongTokenProgram,
        Rejection::WrongDestination,
        Rejection::WrongMint,
        Rejection::WrongDecimals,
        Rejection::WrongInstructionAmount,
        Rejection::ReferenceNotInTransferInstruction,
        Rejection::SlotMismatch,
        Rejection::MissingBalanceRecord,
        Rejection::BalanceDidNotIncrease,
        Rejection::AmountReceivedDiffers,
    ] {
        let reason = rejection.reason();
        assert!(!reason.is_empty());
        assert!(reason.len() < 120, "reason is too long: {reason}");
        assert!(
            reason.chars().all(|character| !character.is_control()),
            "reason contains control characters: {reason}"
        );
    }
}
