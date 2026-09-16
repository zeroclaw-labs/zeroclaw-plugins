//! The cross-plugin contract.
//!
//! `solana-pay-request` puts a reference in a `solana:` URL; this plugin
//! re-derives one from the invoice and looks for it on chain. If those two ever
//! disagreed, every payment made against a request URL would read as unpaid.
//!
//! The constant below is that contract, frozen as a golden vector. The identical
//! constant and inputs are asserted from the request plugin's own suite
//! (`plugins/solana-pay-request/tests/request.rs`,
//! `golden_reference_vector_is_shared_with_solana_pay_confirm`), so a change on
//! either side of the pair fails a test on both sides.
//!
//! Inputs (also frozen):
//!   recipient  FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa
//!   mint       EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v   (6 decimals)
//!   amount     "1.5"   (canonical UI units)
//!   invoice_id "412"

mod common;

use std::collections::HashMap;

use common::{
    fixture_reference, host_inject, output, pubkey, valid_args, valid_config, MockRpc,
    SettledTransfer, AMOUNT, INVOICE, MINT, RECIPIENT,
};
use nanosol::reference::derive_payment_reference;
use solana_pay_confirm::confirm::execute_component_input;

/// Frozen: `sha256("zeroclaw-solana-pay-v1" ‖ recipient ‖ 0x01 ‖ mint
/// ‖ u32be(len(amount)) ‖ amount ‖ u32be(len(invoice)) ‖ invoice)`.
pub const GOLDEN_REFERENCE: &str = "3FrMXf9ucXff2biCaz5ehKYr1yguHjWvwLcy8ALDVEnw";

#[test]
fn the_derived_reference_matches_the_frozen_cross_plugin_vector() {
    let derived =
        derive_payment_reference(&pubkey(RECIPIENT), Some(&pubkey(MINT)), AMOUNT, INVOICE);
    assert_eq!(derived.to_string(), GOLDEN_REFERENCE);
    assert_eq!(fixture_reference().to_string(), GOLDEN_REFERENCE);
}

#[test]
fn the_tool_scans_for_exactly_the_reference_in_the_request_url() {
    // End to end through the component entry point: the reference the tool asks
    // the cluster about is the one a wallet would have attached after scanning
    // the request URL.
    let settled = SettledTransfer::paying(pubkey(GOLDEN_REFERENCE));
    let mock = MockRpc::paid(&settled);
    let value = output(&execute_component_input(
        &host_inject(valid_args(), &valid_config()),
        &mock,
    ));

    assert_eq!(value["paid"], true);
    assert_eq!(value["reference"], GOLDEN_REFERENCE);
    assert_eq!(
        mock.call_bodies("getSignaturesForAddress")[0]["params"][0],
        GOLDEN_REFERENCE
    );
}

#[test]
fn each_invoice_field_changes_the_reference() {
    // Binding is by construction: there is no later comparison step to skip.
    let baseline = fixture_reference();
    let variations = [
        (
            "recipient",
            "9aa1DfPZ4TR9nUqBpGVFhtsFocaqfhpjNiTLuxfJQQmv",
            AMOUNT,
            INVOICE,
        ),
        ("mint", RECIPIENT, AMOUNT, INVOICE),
        ("amount", RECIPIENT, "1.51", INVOICE),
        ("invoice", RECIPIENT, AMOUNT, "413"),
    ];
    let mut seen = HashMap::new();
    seen.insert(baseline.to_string(), "baseline");
    for (label, recipient, amount, invoice) in variations {
        let mint = if label == "mint" {
            pubkey("So11111111111111111111111111111111111111112")
        } else {
            pubkey(MINT)
        };
        let derived = derive_payment_reference(&pubkey(recipient), Some(&mint), amount, invoice);
        assert_ne!(
            derived, baseline,
            "changing {label} did not change the reference"
        );
        assert!(
            seen.insert(derived.to_string(), label).is_none(),
            "two different invoices collided on one reference at {label}"
        );
    }
}
