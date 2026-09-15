use serde_json::json;
use sns_resolve::resolve::{
    format, normalize_domain, parse_proxy_response, ResolveError, MAX_OUTPUT_CHARS,
};

const ADDRESS: &str = "Fw1ETanDZafof7xEULsnq9UY6o71Tpds89tNwPkWLb1v";

#[test]
fn normalizes_top_level_sol_domain() {
    assert_eq!(normalize_domain(" Bonfida.SOL ").unwrap(), "bonfida.sol");
}
#[test]
fn rejects_malformed_and_subdomain_input() {
    assert!(matches!(
        normalize_domain("bad domain.sol"),
        Err(ResolveError::InvalidDomain(_))
    ));
    assert!(matches!(
        normalize_domain("x.y.sol"),
        Err(ResolveError::InvalidDomain(_))
    ));
}
#[test]
fn parses_success_fixture() {
    assert_eq!(
        parse_proxy_response(&json!({"s":"ok","result":ADDRESS})).unwrap(),
        ADDRESS
    );
}
#[test]
fn handles_not_found_fixture() {
    assert_eq!(
        parse_proxy_response(&json!({"s":"error","result":"Domain not found"})),
        Err(ResolveError::NotFound)
    );
}
#[test]
fn fails_closed_on_malformed_address_or_status() {
    assert_eq!(
        parse_proxy_response(&json!({"s":"ok","result":"not-an-address"})),
        Err(ResolveError::MalformedResponse)
    );
    assert!(matches!(
        parse_proxy_response(&json!({"s":"maintenance"})),
        Err(ResolveError::Provider(_))
    ));
}
#[test]
fn rejects_non_base58_and_all_zero_decoded_addresses() {
    // Same length as a valid address but with a non-base58 char ('0') swapped in;
    // a plain alphanumeric check would have passed this through.
    assert_eq!(
        parse_proxy_response(&json!({"s":"ok","result":"0w1ETanDZafof7xEULsnq9UY6o71Tpds89tNwPkWLb1v"})),
        Err(ResolveError::MalformedResponse)
    );
    // Decodes to 32 all-zero bytes (the System Program sentinel), not a real resolution.
    assert_eq!(
        parse_proxy_response(&json!({"s":"ok","result":"11111111111111111111111111111111"})),
        Err(ResolveError::MalformedResponse)
    );
}
#[test]
fn output_is_under_200_tokens() {
    let text = format("bonfida.sol", ADDRESS);
    assert!(text.chars().count() <= MAX_OUTPUT_CHARS);
    assert!(text.split_whitespace().count() <= 200);
}
