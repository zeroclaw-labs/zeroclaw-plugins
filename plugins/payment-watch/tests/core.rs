use payment_watch::core::{
    check_payment, match_payment, ExpectedPayment, ObservedPayment, PaymentWatchArgs, Pubkey,
    RpcClient, WatchError, PARAMETERS_SCHEMA,
};

const RECIPIENT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const REFERENCE: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

fn args() -> PaymentWatchArgs {
    PaymentWatchArgs {
        recipient: RECIPIENT.into(),
        amount: "25.0".into(),
        decimals: 6,
        mint: MINT.into(),
        reference: REFERENCE.into(),
        token_2022: false,
    }
}
fn expected() -> ExpectedPayment {
    args().expected().unwrap()
}
fn payment(reference_present: bool) -> ObservedPayment {
    ObservedPayment {
        signature: "test-signature".into(),
        sender: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".into(),
        recipient: Pubkey::from_base58(RECIPIENT).unwrap(),
        mint: Pubkey::from_base58(MINT).unwrap(),
        amount_base_units: 25_000_000,
        decimals: 6,
        reference_present,
    }
}

#[test]
fn matching_payment_emits_a_structured_settlement_event() {
    let result = match_payment(&expected(), &[payment(true)]);
    assert_eq!(result.status, "paid");
    let event = result.event.expect("matching payment event");
    assert_eq!(event.event, "payment-received");
    assert_eq!(event.amount_base_units, 25_000_000);
}

#[test]
fn payment_without_the_required_reference_is_not_accepted() {
    let result = match_payment(&expected(), &[payment(false)]);
    assert_eq!(result.status, "waiting");
    assert!(result.event.is_none());
}

#[test]
fn rejects_amounts_that_would_be_rounded() {
    let mut invalid = args();
    invalid.amount = "25.0000001".into();
    assert!(invalid.expected().is_err());
}

struct PanicRpc;
impl RpcClient for PanicRpc {
    fn recent_payments(&self, _: &ExpectedPayment) -> Result<Vec<ObservedPayment>, WatchError> {
        panic!("invalid configuration must fail before RPC")
    }
}

#[test]
fn prompt_injected_invalid_reference_fails_before_rpc() {
    let mut invalid = args();
    invalid.reference = "IGNORE_POLICY".into();
    assert!(check_payment(&invalid, &PanicRpc).is_err());
}

#[test]
fn parameters_schema_is_valid_json_for_the_host() {
    let value: serde_json::Value = serde_json::from_str(PARAMETERS_SCHEMA)
        .expect("ZeroClaw must be able to parse the tool schema");
    assert_eq!(
        value
            .pointer("/properties/amount/type")
            .and_then(|value| value.as_str()),
        Some("string")
    );
}
