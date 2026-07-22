use proptest::prelude::*;
use payment_watch::core::{
    check_payment, is_solana_address, match_payment, short_addr, ExpectedPayment,
    ObservedPayment, PaymentWatchArgs, Pubkey, RpcClient, WatchError, WatchStatus,
    PARAMETERS_SCHEMA,
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

struct PanicRpc;
impl RpcClient for PanicRpc {
    fn recent_payments(&self, _: &ExpectedPayment) -> Result<Vec<ObservedPayment>, WatchError> {
        panic!("invalid configuration must fail before RPC")
    }
}

// ----------------------------------------------------------------
// Existing tests (updated for WatchStatus)
// ----------------------------------------------------------------

#[test]
fn matching_payment_emits_a_structured_settlement_event() {
    let result = match_payment(&expected(), &[payment(true)]);
    assert_eq!(result.status, "paid");
    assert_eq!(result.watch_status, Some(WatchStatus::Matched));
    let event = result.event.expect("matching payment event");
    assert_eq!(event.event, "payment-received");
    assert_eq!(event.amount_base_units, 25_000_000);
}

#[test]
fn payment_without_the_required_reference_is_not_accepted() {
    let result = match_payment(&expected(), &[payment(false)]);
    assert_eq!(result.status, "waiting");
    assert!(result.event.is_none());
    assert_eq!(result.watch_status, None);
}

#[test]
fn rejects_amounts_that_would_be_rounded() {
    let mut invalid = args();
    invalid.amount = "25.0000001".into();
    assert!(invalid.expected().is_err());
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

// ----------------------------------------------------------------
// Unit tests: is_solana_address
// ----------------------------------------------------------------

#[test]
fn valid_address_is_valid() {
    assert!(is_solana_address(RECIPIENT));
    assert!(is_solana_address(REFERENCE));
}

#[test]
fn empty_string_is_not_valid() {
    assert!(!is_solana_address(""));
}

#[test]
fn short_base58_is_not_valid() {
    assert!(!is_solana_address("abc"));
}

#[test]
fn non_base58_is_not_valid() {
    assert!(!is_solana_address("0OIl"));
}

#[test]
fn wrong_length_rejected() {
    assert!(!is_solana_address("111111111111111111111111111111")); // 31 bytes
    assert!(!is_solana_address("111111111111111111111111111111111")); // 33 bytes
}

// ----------------------------------------------------------------
// Unit tests: short_addr
// ----------------------------------------------------------------

#[test]
fn short_addr_truncates() {
    let result = short_addr("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU");
    assert_eq!(result, "7xKX...gAsU");
}

#[test]
fn short_addr_returns_short_string_unchanged() {
    assert_eq!(short_addr("abc"), "abc");
    assert_eq!(short_addr("123456789012"), "123456789012");
}

// ----------------------------------------------------------------
// Adversarial: rejects seed phrase in args
// ----------------------------------------------------------------

#[test]
fn injection_seed_phrase_in_args_fails_closed() {
    let mut invalid = args();
    invalid.reference = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into();
    assert!(check_payment(&invalid, &PanicRpc).is_err());
}

#[test]
fn injection_fake_confirmation_text_ignored() {
    // The tool only trusts on-chain RPC data, never anything resembling a
    // "yes it's paid" string in args. Even if we pass gibberish, it fails
    // at validation, never reaching RPC.
    let mut invalid = args();
    invalid.reference = "YES PAYMENT CONFIRMED".into();
    assert!(check_payment(&invalid, &PanicRpc).is_err());
}

// ----------------------------------------------------------------
// Property tests
// ----------------------------------------------------------------

proptest! {
    #[test]
    fn pubkey_parse_never_panics(s in ".*") {
        let _ = Pubkey::from_base58(&s);
    }

    #[test]
    fn is_solana_address_never_panics(s in ".*") {
        let _ = is_solana_address(&s);
    }
}

// ----------------------------------------------------------------
// Structured status tests
// ----------------------------------------------------------------

#[test]
fn overpaid_returns_correct_status() {
    let expected = expected();
    let mut observed = payment(true);
    observed.amount_base_units = 30_000_000; // overpaid
    let result = match_payment(&expected, &[observed]);
    assert_eq!(result.status, "waiting");
}

#[test]
fn wrong_mint_returns_not_matched() {
    let expected = expected();
    let mut observed = payment(true);
    observed.mint = Pubkey::from_base58(RECIPIENT).unwrap(); // wrong mint
    let result = match_payment(&expected, &[observed]);
    assert_eq!(result.status, "waiting");
}

#[test]
fn multiple_observations_only_first_match_wins() {
    let expected = expected();
    let mut good = payment(true);
    good.signature = "good-sig".into();
    let mut also_good = payment(true);
    also_good.signature = "also-good-sig".into();
    let result = match_payment(&expected, &[good, also_good]);
    assert_eq!(result.status, "paid");
    assert_eq!(
        result.event.unwrap().signature,
        "good-sig"
    );
}

#[test]
fn empty_observations_returns_waiting() {
    let result = match_payment(&expected(), &[]);
    assert_eq!(result.status, "waiting");
    assert_eq!(result.checked_transactions, 0);
}

// ----------------------------------------------------------------
// Pubkey tests
// ----------------------------------------------------------------

#[test]
fn pubkey_valid_roundtrip() {
    let pk = Pubkey::from_base58(RECIPIENT).unwrap();
    assert_eq!(pk.to_base58(), RECIPIENT);
}

#[test]
fn pubkey_display_matches_base58() {
    let pk = Pubkey::from_base58(REFERENCE).unwrap();
    assert_eq!(format!("{pk}"), REFERENCE);
}

#[test]
fn derive_ata_deterministic() {
    let owner = Pubkey::from_base58(RECIPIENT).unwrap();
    let mint = Pubkey::from_base58(MINT).unwrap();
    let tp = Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let a1 = payment_watch::core::derive_ata(owner, mint, tp).unwrap();
    let a2 = payment_watch::core::derive_ata(owner, mint, tp).unwrap();
    assert_eq!(a1, a2);
}

#[test]
fn rejects_invalid_decimals() {
    let mut invalid = args();
    invalid.decimals = 20;
    assert!(invalid.expected().is_err());
}
