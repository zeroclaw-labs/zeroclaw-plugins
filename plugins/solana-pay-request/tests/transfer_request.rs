//! Host-run tests over the pure core, through the crate's public API only.
//!
//! These need no wasm toolchain and no network: `cargo test` is the whole
//! command. The unit tests inside `src/` cover the field-by-field validation
//! table; this file covers the four claims the README makes to a reader who
//! never opens the source.

use solana_pay_request::{build_transfer_url, parse_and_validate, render_output};

/// A real native wallet address, used as the recipient throughout.
const RECIPIENT: &str = "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN";
/// Mainnet USDC.
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

#[test]
fn builds_the_url_the_readme_documents() {
    let args = format!(
        r#"{{"recipient":"{RECIPIENT}","amount":"25","spl_token":"{USDC}","memo":"table 4"}}"#
    );
    let validated = parse_and_validate(&args).expect("a well-formed request must validate");

    assert_eq!(
        build_transfer_url(&validated),
        format!("solana:{RECIPIENT}?amount=25&spl-token={USDC}&memo=table%204"),
        "the URL must match the transfer-request grammar the README publishes"
    );
}

#[test]
fn a_hostile_memo_cannot_inject_a_second_recipient() {
    // The whole security claim in one case: free text is percent-encoded at
    // build time, so `&` and `=` inside a memo stay inside the memo VALUE.
    let hostile = "table 4&recipient=Attacker111111111111111111111111111111111&amount=999";
    let args = format!(r#"{{"recipient":"{RECIPIENT}","amount":"25","memo":"{hostile}"}}"#);
    let validated = parse_and_validate(&args).expect("a hostile memo is data, not an error");
    let url = build_transfer_url(&validated);

    assert_eq!(
        url.matches("amount=").count(),
        1,
        "the injected amount must not become a second query parameter: {url}"
    );
    assert!(
        !url.contains("&recipient="),
        "the injected recipient must not become a query parameter: {url}"
    );
    assert!(
        url.starts_with(&format!("solana:{RECIPIENT}?")),
        "the path recipient must remain the validated one: {url}"
    );
    assert!(
        url.contains("%26") && url.contains("%3D"),
        "the ampersand and equals must survive as percent-encoded bytes: {url}"
    );
}

#[test]
fn rejects_a_recipient_that_is_not_a_pubkey() {
    let args = r#"{"recipient":"not-a-real-address"}"#;
    let error = parse_and_validate(args).expect_err("an invalid recipient must fail closed");
    assert!(
        error.to_lowercase().contains("recipient"),
        "the error must name the offending field, got: {error}"
    );
}

#[test]
fn qr_payload_is_byte_identical_to_the_url() {
    // A Solana Pay QR encodes the URL verbatim. The README promises these two
    // fields are equal so a host can render the QR without re-deriving it.
    let args = format!(r#"{{"recipient":"{RECIPIENT}","amount":"1.5"}}"#);
    let validated = parse_and_validate(&args).expect("a well-formed request must validate");
    let rendered = render_output(&validated);

    let parsed: serde_json::Value =
        serde_json::from_str(&rendered).expect("render_output must emit JSON");
    let url = parsed["url"].as_str().expect("url must be a string");
    let qr = parsed["qr_payload"]
        .as_str()
        .expect("qr_payload must be a string");

    assert_eq!(url, qr);
    assert_eq!(url, build_transfer_url(&validated));
}
