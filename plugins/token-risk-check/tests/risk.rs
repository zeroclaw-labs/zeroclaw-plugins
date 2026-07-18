//! Host-run tests over the pure risk core against a mock RPC — no wasm
//! toolchain, no live network. Also pins the context-window budget: a report
//! must stay a few hundred characters no matter what the RPC returns.

use std::collections::HashMap;

use serde_json::{json, Value};
use token_risk_check::risk::{assess_mint, RiskConfig, Verdict};
use zeroclaw_solana_core::pubkey::{token_2022_program, token_program, Pubkey};
use zeroclaw_solana_core::rpc::HttpTransport;

fn mint_addr() -> Pubkey {
    Pubkey([5u8; 32])
}

struct MockRpc {
    account: Option<(Pubkey, Vec<u8>)>,
    holders: Vec<(Pubkey, u64)>,
    fail_largest: bool,
}

impl MockRpc {
    fn new(owner: &Pubkey, data: Vec<u8>) -> Self {
        Self {
            account: Some((*owner, data)),
            holders: Vec::new(),
            fail_largest: false,
        }
    }

    fn with_holders(mut self, holders: &[u64]) -> Self {
        self.holders = holders
            .iter()
            .enumerate()
            .map(|(i, amount)| (Pubkey([i as u8 + 100; 32]), *amount))
            .collect();
        self
    }
}

impl HttpTransport for MockRpc {
    fn post_json(&self, _url: &str, body: &str) -> Result<String, String> {
        let req: Value = serde_json::from_str(body).unwrap();
        let result = match req["method"].as_str().unwrap() {
            "getAccountInfo" => match &self.account {
                Some((owner, data)) => json!({"context": {"slot": 1}, "value": {
                    "owner": owner.to_base58(),
                    "data": [zeroclaw_solana_core::encoding::to_base64(data), "base64"],
                    "lamports": 2_000_000u64
                }}),
                None => json!({"context": {"slot": 1}, "value": null}),
            },
            "getTokenLargestAccounts" => {
                if self.fail_largest {
                    return Ok(
                        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "throttled"}})
                            .to_string(),
                    );
                }
                let entries: Vec<Value> = self
                    .holders
                    .iter()
                    .map(|(addr, amount)| {
                        json!({"address": addr.to_base58(), "amount": amount.to_string(),
                               "decimals": 6, "uiAmountString": "x"})
                    })
                    .collect();
                json!({"context": {"slot": 1}, "value": entries})
            }
            other => return Err(format!("mock rpc: unexpected method {other}")),
        };
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string())
    }
}

/// Serialized mint data; supply 1_000_000 units of a 6-decimal token.
fn mint_data(mint_authority: bool, freeze_authority: bool, tlv: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut data = Vec::new();
    if mint_authority {
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&[3u8; 32]);
    } else {
        data.extend_from_slice(&[0u8; 36]);
    }
    data.extend_from_slice(&1_000_000_000_000u64.to_le_bytes());
    data.push(6);
    data.push(1);
    if freeze_authority {
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&[4u8; 32]);
    } else {
        data.extend_from_slice(&[0u8; 36]);
    }
    if !tlv.is_empty() {
        data.resize(165, 0);
        data.push(1);
        for (ext_type, value) in tlv {
            data.extend_from_slice(&ext_type.to_le_bytes());
            data.extend_from_slice(&(value.len() as u16).to_le_bytes());
            data.extend_from_slice(value);
        }
    }
    data
}

fn cfg() -> RiskConfig {
    RiskConfig::from_section(&HashMap::new())
}

fn assess(rpc: &MockRpc) -> token_risk_check::risk::RiskReport {
    assess_mint(rpc, &mint_addr().to_base58(), &cfg()).unwrap()
}

#[test]
fn clean_dispersed_token_is_green() {
    let rpc = MockRpc::new(&token_program(), mint_data(false, false, &[])).with_holders(&[
        30_000_000_000,
        20_000_000_000,
        10_000_000_000,
    ]);
    let report = assess(&rpc);
    assert_eq!(report.verdict, Verdict::Green);
    assert!(report.text.starts_with("RISK: GREEN"));
    assert!(report.text.contains("#1 holds 3.00%"));
    assert!(report.text.contains("supply 1000000"));
}

#[test]
fn active_authorities_are_amber_with_reasons() {
    let rpc =
        MockRpc::new(&token_program(), mint_data(true, true, &[])).with_holders(&[10_000_000_000]);
    let report = assess(&rpc);
    assert_eq!(report.verdict, Verdict::Amber);
    assert!(report.text.contains("supply can be inflated"));
    assert!(report.text.contains("can be frozen"));
}

#[test]
fn permanent_delegate_is_red() {
    let rpc = MockRpc::new(
        &token_2022_program(),
        mint_data(false, false, &[(12u16, vec![8u8; 32])]),
    );
    let report = assess(&rpc);
    assert_eq!(report.verdict, Verdict::Red);
    assert!(report.text.contains("permanent delegate"));
    assert!(report.text.contains("ANY holder's tokens"));
}

#[test]
fn transfer_hook_and_default_frozen_are_red() {
    let hook_value = [vec![0u8; 32], vec![9u8; 32]].concat();
    let rpc = MockRpc::new(
        &token_2022_program(),
        mint_data(false, false, &[(14u16, hook_value), (6u16, vec![2u8])]),
    );
    let report = assess(&rpc);
    assert_eq!(report.verdict, Verdict::Red);
    assert!(report.text.contains("transfer hook"));
    assert!(report.text.contains("FROZEN"));
}

#[test]
fn transfer_fee_severity_scales() {
    let fee = |bps: u16| {
        let mut v = vec![0u8; 108];
        v[106..108].copy_from_slice(&bps.to_le_bytes());
        (1u16, v)
    };
    let amber = assess(&MockRpc::new(
        &token_2022_program(),
        mint_data(false, false, &[fee(100)]),
    ));
    assert_eq!(amber.verdict, Verdict::Amber);
    assert!(amber.text.contains("100bps"));

    let red = assess(&MockRpc::new(
        &token_2022_program(),
        mint_data(false, false, &[fee(900)]),
    ));
    assert_eq!(red.verdict, Verdict::Red);
}

#[test]
fn whale_concentration_is_red() {
    // One account holds 60% of the 1e12 base-unit supply.
    let rpc = MockRpc::new(&token_program(), mint_data(false, false, &[]))
        .with_holders(&[600_000_000_000, 100_000_000_000]);
    let report = assess(&rpc);
    assert_eq!(report.verdict, Verdict::Red);
    assert!(report.text.contains("one account holds 60.00%"));
}

#[test]
fn throttled_largest_accounts_degrades_gracefully() {
    let mut rpc = MockRpc::new(&token_program(), mint_data(false, false, &[]));
    rpc.fail_largest = true;
    let report = assess(&rpc);
    assert_eq!(report.verdict, Verdict::Green);
    assert!(report.text.contains("unavailable"));
}

#[test]
fn non_mint_inputs_fail_with_short_errors() {
    // Account doesn't exist.
    let mut rpc = MockRpc::new(&token_program(), Vec::new());
    rpc.account = None;
    let err = assess_mint(&rpc, &mint_addr().to_base58(), &cfg()).unwrap_err();
    assert!(err.contains("does not exist"));

    // Account owned by a non-token program.
    let rpc = MockRpc::new(&zeroclaw_solana_core::pubkey::SYSTEM_PROGRAM, vec![0u8; 82]);
    let err = assess_mint(&rpc, &mint_addr().to_base58(), &cfg()).unwrap_err();
    assert!(err.contains("not a token mint"));

    // Not even an address.
    assert!(assess_mint(&MockRpc::new(&token_program(), Vec::new()), "lol", &cfg()).is_err());
}

#[test]
fn report_never_floods_the_context_window() {
    // Even a worst-case token (every extension, authorities, whale holders)
    // must stay far under a kilobyte — the whole point of this tool.
    let hook_value = [vec![0u8; 32], vec![9u8; 32]].concat();
    let mut fee = vec![0u8; 108];
    fee[106..108].copy_from_slice(&900u16.to_le_bytes());
    let rpc = MockRpc::new(
        &token_2022_program(),
        mint_data(
            true,
            true,
            &[
                (12u16, vec![8u8; 32]),
                (14u16, hook_value),
                (6u16, vec![2u8]),
                (9u16, Vec::new()),
                (1u16, fee),
                (3u16, Vec::new()),
                (26u16, Vec::new()),
                (10u16, Vec::new()),
            ],
        ),
    )
    .with_holders(&[900_000_000_000, 50_000_000_000]);
    let report = assess(&rpc);
    assert_eq!(report.verdict, Verdict::Red);
    assert!(
        report.text.len() < 1000,
        "report is {} chars:\n{}",
        report.text.len(),
        report.text
    );
}

#[test]
fn hostile_rpc_duplicate_extension_flood_stays_bounded() {
    // A compromised node returns a mint account padded with 5000 duplicate
    // PermanentDelegate TLVs to blow up the agent's context. The report must
    // collapse the duplicates and stay small — the exact scenario the README
    // threat model claims immunity to.
    let flood: Vec<(u16, Vec<u8>)> = (0..5000).map(|_| (12u16, vec![8u8; 32])).collect();
    let rpc = MockRpc::new(&token_2022_program(), mint_data(false, false, &flood));
    let report = assess(&rpc);
    assert_eq!(report.verdict, Verdict::Red);
    assert!(
        report.text.len() < 2100,
        "flood report is {} chars — must stay bounded",
        report.text.len()
    );
    // Only one delegate line survives, plus the malformed-mint flag.
    assert_eq!(report.text.matches("permanent delegate").count(), 1);
    assert!(report.text.contains("malformed mint"));
}
