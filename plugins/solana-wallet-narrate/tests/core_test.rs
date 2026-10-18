
use solana_wallet_narrate::core::narrate::{narrate, tx_to_sentence};
use solana_wallet_narrate::core::shape::format_narration;

const SOL_TX: &str = r#"{"result":{"meta":{"err":null},"transaction":{"message":{"instructions":[{"program":"system","parsed":{"type":"transfer","info":{"source":"7xKmNabc","destination":"9zLpQdef","lamports":1000000000}}}]}}}}"#;
const SPL_TX: &str = r#"{"result":{"meta":{"err":null},"transaction":{"message":{"instructions":[{"program":"spl-token","parsed":{"type":"transferChecked","info":{"source":"7xKmNabc","destination":"9zLpQdef","tokenAmount":{"uiAmountString":"25.0","decimals":6}}}}]}}}}"#;
const SIGS: &str = r#"{"result":[{"signature":"sig1","slot":100},{"signature":"sig2","slot":99}]}"#;
const EMPTY_SIGS: &str = r#"{"result":[]}"#;

#[test]
fn sol_send_narrated() {
    let sentence = tx_to_sentence("7xKmNabc", SOL_TX);
    assert!(sentence.contains("SOL"), "expected SOL: {}", sentence);
    assert!(sentence.contains("Sent"), "expected Sent: {}", sentence);
}

#[test]
fn sol_receive_narrated() {
    let sentence = tx_to_sentence("9zLpQdef", SOL_TX);
    assert!(sentence.contains("Received"), "expected Received: {}", sentence);
}

#[test]
fn spl_transfer_narrated() {
    let sentence = tx_to_sentence("7xKmNabc", SPL_TX);
    assert!(sentence.contains("tokens"), "expected tokens: {}", sentence);
}

#[test]
fn narrate_uses_mocked_rpc() {
    let sentences = narrate(
        "7xKmNabc",
        SIGS,
        |sig| {
            if sig == "sig1" { Ok(SOL_TX.to_string()) }
            else { Ok(SPL_TX.to_string()) }
        },
    );
    assert_eq!(sentences.len(), 2);
    println!("{:?}", sentences);
}

#[test]
fn empty_sigs_handled() {
    let sentences = narrate("7xKmNabc", EMPTY_SIGS, |_| Ok("{}".to_string()));
    assert!(!sentences.is_empty());
    assert!(sentences[0].contains("No recent"));
}

#[test]
fn output_is_short() {
    let sentences = narrate("7xKmNabc", SIGS, |_| Ok(SOL_TX.to_string()));
    let out = format_narration("7xKmNabcXXXX", &sentences);
    assert!(out.len() < 500, "output too long: {} chars", out.len());
    println!("{}", out);
}
