//! Host-run tests over the pure account core against a mock RPC — no wasm
//! toolchain, no live network. Includes the flood/injection cases: caller
//! input must never blow up the output, and a hostile node's data is bounded.

use std::collections::HashMap;

use serde_json::{json, Value};
use solana_account::account::{account_brief, AccountArgs, AccountConfig};
use zeroclaw_solana_core::rpc::HttpTransport;

const WALLET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SYSTEM: &str = "11111111111111111111111111111111";

/// Mock node: dispatches by JSON-RPC method (and, for token accounts, by the
/// queried program id) so one struct serves the whole brief.
struct MockRpc {
    account: Option<(String, u64)>, // (owner, lamports); None => getAccountInfo null
    spl_holdings: Vec<(String, u64, u8)>, // (mint, amount, decimals) for SPL Token
    sigs: Vec<(String, bool)>,      // (signature, failed)
    token_fails: bool,
}

impl Default for MockRpc {
    fn default() -> Self {
        Self {
            account: Some((SYSTEM.to_string(), 1_500_000_000)), // 1.5 SOL, wallet
            spl_holdings: vec![
                (USDC.to_string(), 250_000_000, 6),          // 250 USDC
                ("MintZZZ11111111111111111111111111111111111".to_string(), 12_500_000, 6),
            ],
            sigs: vec![
                ("sigA".to_string(), false),
                ("sigB".to_string(), false),
                ("sigC".to_string(), true),
            ],
            token_fails: false,
        }
    }
}

impl HttpTransport for MockRpc {
    fn post_json(&self, _url: &str, body: &str) -> Result<String, String> {
        let req: Value = serde_json::from_str(body).unwrap();
        let method = req["method"].as_str().unwrap();
        let result = match method {
            "getAccountInfo" => match &self.account {
                None => json!({"value": Value::Null}),
                Some((owner, lamports)) => json!({"value": {
                    "owner": owner, "lamports": lamports, "data": ["", "base64"]
                }}),
            },
            "getTokenAccountsByOwner" => {
                if self.token_fails {
                    return Ok(json!({"jsonrpc":"2.0","id":1,
                        "error":{"code":-32000,"message":"token read unavailable"}})
                    .to_string());
                }
                let program = req["params"][1]["programId"].as_str().unwrap_or("");
                // Return SPL Token holdings for the classic program; none for 2022.
                let entries: Vec<Value> = if program.starts_with("Tokenkeg") {
                    self.spl_holdings
                        .iter()
                        .map(|(mint, amount, dec)| {
                            json!({"account": {"data": {"parsed": {"info": {
                                "mint": mint,
                                "tokenAmount": {"amount": amount.to_string(), "decimals": dec}
                            }}}}})
                        })
                        .collect()
                } else {
                    vec![]
                };
                json!({ "value": entries })
            }
            "getSignaturesForAddress" => json!(self
                .sigs
                .iter()
                .map(|(sig, failed)| json!({
                    "signature": sig, "slot": 1u64,
                    "err": if *failed { json!({"InstructionError": []}) } else { Value::Null },
                    "confirmationStatus": "confirmed"
                }))
                .collect::<Vec<_>>()),
            other => return Err(format!("unexpected method {other}")),
        };
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string())
    }
}

fn cfg() -> AccountConfig {
    AccountConfig::from_section(&HashMap::new())
}
fn args(a: &str) -> AccountArgs {
    AccountArgs {
        address: a.to_string(),
    }
}

#[test]
fn brief_for_a_funded_wallet() {
    let res = account_brief(&MockRpc::default(), &args(WALLET), &cfg()).unwrap();
    let t = &res.text;
    assert!(t.contains("wallet"), "type: {t}");
    assert!(t.contains("1.5"), "sol: {t}");
    assert!(t.contains("250 USDC"), "known mint symbol: {t}");
    assert!(t.contains("Tokens (2)"), "holdings count: {t}");
    assert!(t.contains("Recent activity: 2/3"), "activity: {t}");
    assert!(t.contains("solscan.io/account/"), "explorer: {t}");
    assert!(t.len() < 1024, "brief must stay bounded, got {}", t.len());
}

#[test]
fn unused_account_reports_not_found() {
    let mut rpc = MockRpc::default();
    rpc.account = None;
    let res = account_brief(&rpc, &args(WALLET), &cfg()).unwrap();
    assert!(res.text.contains("account not found"), "got: {}", res.text);
    assert!(!res.text.contains("Tokens ("), "no holdings line for a missing account");
}

#[test]
fn program_owned_account_is_labeled() {
    let mut rpc = MockRpc::default();
    rpc.account = Some((USDC.to_string(), 2_039_280)); // owner != system program
    let res = account_brief(&rpc, &args(WALLET), &cfg()).unwrap();
    assert!(res.text.contains("program-owned"), "got: {}", res.text);
}

#[test]
fn a_token_read_failure_is_tolerated() {
    let mut rpc = MockRpc::default();
    rpc.token_fails = true;
    let res = account_brief(&rpc, &args(WALLET), &cfg()).unwrap();
    // SOL + activity still reported; the tokens line is simply omitted.
    assert!(res.text.contains("SOL balance"));
    assert!(res.text.contains("Recent activity"));
    assert!(!res.text.contains("Tokens ("), "tokens line should be omitted, got: {}", res.text);
}

#[test]
fn invalid_address_is_refused() {
    let err = account_brief(&MockRpc::default(), &args("not-base58!!"), &cfg()).unwrap_err();
    assert!(err.contains("refused"), "got: {err}");
    assert!(err.contains("valid"));
}

#[test]
fn oversized_address_is_refused_short() {
    // A flood attempt through the one caller-controlled field must be bounded
    // in the pure core, so the error stays short — not only clamped at the shim.
    let err = account_brief(&MockRpc::default(), &args(&"Z".repeat(5000)), &cfg()).unwrap_err();
    assert!(err.contains("too long"), "got: {err}");
    assert!(err.len() < 100, "core error must stay short, got {} chars", err.len());
}

#[test]
fn output_stays_bounded_with_many_holdings() {
    // A hostile node returning a wallet stuffed with tokens cannot make the
    // brief scale: only the top few are listed, the rest summarized as "+N".
    let mut rpc = MockRpc::default();
    rpc.spl_holdings = (0..40)
        .map(|i| (format!("Mint{i:0>39}"), 1_000 * (i + 1) as u64, 0))
        .collect();
    let res = account_brief(&rpc, &args(WALLET), &cfg()).unwrap();
    assert!(res.text.contains("Tokens (40)"), "count shown: {}", res.text);
    assert!(res.text.contains("more"), "rest summarized: {}", res.text);
    assert!(res.text.len() < 1024, "brief must stay bounded, got {}", res.text.len());
}

#[test]
fn custom_known_mint_symbols_render() {
    let mut m = HashMap::new();
    m.insert(
        "known_mints".to_string(),
        "MintZZZ11111111111111111111111111111111111:brz".to_string(),
    );
    let c = AccountConfig::from_section(&m);
    let res = account_brief(&MockRpc::default(), &args(WALLET), &c).unwrap();
    assert!(res.text.contains("BRZ"), "custom symbol upper-cased: {}", res.text);
}
