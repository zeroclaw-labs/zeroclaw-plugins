//! Solana transaction decoder — pure Rust core (no wasm dependency).
//!
//! Fetches a transaction by signature via JSON-RPC and returns a
//! human-readable summary suitable for display in a chat window.
#![allow(dead_code)]

use serde::Serialize;

/// Result returned to the agent.
#[derive(Debug, Serialize)]
pub struct TxDecodeReport {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub success: bool,
    pub fee: u64,
    pub accounts: Vec<String>,
    pub instructions: Vec<InstructionSummary>,
    pub sol_transfers: Vec<SolTransfer>,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct InstructionSummary {
    pub program: String,
    pub label: String,
    pub accounts_used: usize,
}

#[derive(Debug, Serialize)]
pub struct SolTransfer {
    pub from: String,
    pub to: String,
    pub amount_sol: f64,
}

/// Known program IDs to human-readable names.
const KNOWN_PROGRAMS: &[(&str, &str)] = &[
    ("11111111111111111111111111111111", "System Program"),
    ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "Token Program"),
    ("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "Token-2022"),
    ("ATokenGPvbt7iBfnoMryHPKcqwBXnxGn4TpyheAw1", "Associated Token Account"),
    ("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s", "Metaplex Token Metadata"),
    ("SSwpkEEcbUqx4vtoEByFjSkhKdCT862DNVb52nZg1UZ", "Jupiter Aggregator"),
    ("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", "Orca Whirlpool"),
    ("CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK", "Raydium CLMM"),
    ("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", "Raydium AMM"),
    ("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", "Pump.fun"),
    ("JUP6LkbZbjS1jKKwapdH5vYFCW3dHMJh8n3UVgRvSxW", "Jupiter"),
    ("ComputeBudget111111111111111111111111111111", "Compute Budget"),
    ("MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD", "Marinade"),
    ("DriftR7HkLXYBSFvD7Jcnf8MWcPqohK6bEckqLzLC", "Drift"),
    ("KAMMoM3GjLxoDQTo7nY9hZTXGr2xszCgMRaUc59qP1w", "Kamino"),
];

/// Trait for HTTP POST.
pub trait HttpClient {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
}

/// Decode a signed transaction by its signature.
pub fn decode_transaction(
    client: &dyn HttpClient,
    rpc_url: &str,
    signature: &str,
) -> Result<TxDecodeReport, String> {
    let v = rpc_call(
        client,
        rpc_url,
        "getTransaction",
        serde_json::json!([signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}]),
    )?;

    let tx = &v["result"];
    if tx.is_null() {
        return Err(format!("transaction not found: {signature}"));
    }

    let slot = tx["slot"].as_u64().unwrap_or(0);
    let block_time = tx["blockTime"].as_i64();
    let meta = &tx["meta"];
    let success = meta["err"].is_null();
    let fee = meta["fee"].as_u64().unwrap_or(0);

    // Accounts
    let account_keys = tx["transaction"]["message"]["accountKeys"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|a| {
                    a["pubkey"]
                        .as_str()
                        .unwrap_or("?")
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default();

    // Instructions
    let instructions = parse_instructions(tx);
    let sol_transfers = parse_sol_transfers(meta);

    // Human-readable summary
    let status_emoji = if success { "✅" } else { "❌" };
    let sol_flow: String = if sol_transfers.is_empty() {
        String::new()
    } else {
        let parts: Vec<String> = sol_transfers
            .iter()
            .map(|t| format!("{:.4} SOL {} → {}", t.amount_sol, short_pubkey(&t.from), short_pubkey(&t.to)))
            .collect();
        format!("\n  💰 {}", parts.join(", "))
    };

    let instr_list: String = instructions
        .iter()
        .map(|i| format!("\n  • {} ({})", i.label, i.program))
        .collect();

    let summary = format!(
        "{status_emoji} TX {sig} | slot {slot}{sol_flow}\n  Instructions:{instr_list}\n  Fee: {fee_lamports} lamports",
        status_emoji = status_emoji,
        sig = short_sig(signature),
        sol_flow = sol_flow,
        instr_list = instr_list,
        fee_lamports = fee,
    );

    Ok(TxDecodeReport {
        signature: signature.to_string(),
        slot,
        block_time,
        success,
        fee,
        accounts: account_keys,
        instructions,
        sol_transfers,
        summary,
    })
}

fn parse_instructions(tx: &serde_json::Value) -> Vec<InstructionSummary> {
    let msg = &tx["transaction"]["message"];
    let instructions = msg["instructions"].as_array();

    match instructions {
        Some(instrs) => instrs
            .iter()
            .map(|ix| {
                let program_id = ix["programId"].as_str().unwrap_or("unknown");
                let accounts_count = ix["accounts"].as_array().map(|a| a.len()).unwrap_or(0);
                let label = program_label(program_id);
                InstructionSummary {
                    program: program_id.to_string(),
                    label,
                    accounts_used: accounts_count,
                }
            })
            .collect(),
        None => Vec::new(),
    }
}

fn parse_sol_transfers(meta: &serde_json::Value) -> Vec<SolTransfer> {
    let pre = &meta["preTokenBalances"];
    let post = &meta["postTokenBalances"];
    let _ = (pre, post); // SPL token balance changes — future enhancement

    // Native SOL transfers from pre/post balances
    let pre_balances = meta["preBalances"].as_array();
    let post_balances = meta["postBalances"].as_array();

    let (pre, post) = match (pre_balances, post_balances) {
        (Some(pre), Some(post)) if pre.len() == post.len() => (pre, post),
        _ => return Vec::new(),
    };

    let mut transfers = Vec::new();
    for (i, (pre_val, post_val)) in pre.iter().zip(post.iter()).enumerate() {
        let pre_lamports = pre_val.as_u64().unwrap_or(0);
        let post_lamports = post_val.as_u64().unwrap_or(0);

        if post_lamports > pre_lamports {
            // This account received SOL
            let amount = (post_lamports - pre_lamports) as f64 / 1_000_000_000.0;
            transfers.push(SolTransfer {
                from: "unknown".to_string(),
                to: format!("account[{i}]"),
                amount_sol: amount,
            });
        } else if pre_lamports > post_lamports {
            // This account sent SOL
            let amount = (pre_lamports - post_lamports) as f64 / 1_000_000_000.0;
            transfers.push(SolTransfer {
                from: format!("account[{i}]"),
                to: "unknown".to_string(),
                amount_sol: amount,
            });
        }
    }

    transfers
}

fn program_label(program_id: &str) -> String {
    for (id, name) in KNOWN_PROGRAMS {
        if id == &program_id {
            return name.to_string();
        }
    }
    let short = short_pubkey(program_id);
    format!("Unknown ({short})")
}

fn short_pubkey(pk: &str) -> String {
    if pk.len() <= 12 {
        pk.to_string()
    } else {
        format!("{}...{}", &pk[..4], &pk[pk.len() - 4..])
    }
}

fn short_sig(sig: &str) -> String {
    short_pubkey(sig)
}

fn rpc_call(
    client: &dyn HttpClient,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();

    let resp = client.post_json(rpc_url, &body)?;
    serde_json::from_str(&resp).map_err(|e| format!("RPC parse error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct MockClient {
        responses: RefCell<VecDeque<String>>,
    }

    impl MockClient {
        fn new(responses: Vec<String>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
            }
        }
    }

    impl HttpClient for MockClient {
        fn post_json(&self, _url: &str, _body: &str) -> Result<String, String> {
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| "no mock response".into())
        }
    }

    #[test]
    fn test_decode_successful_tx() {
        let tx_json = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "slot": 320000000,
                "blockTime": 1715800000,
                "meta": {
                    "err": null,
                    "fee": 5000,
                    "preBalances": [1000000000, 0],
                    "postBalances": [999000000, 1000000],
                    "preTokenBalances": [],
                    "postTokenBalances": []
                },
                "transaction": {
                    "message": {
                        "accountKeys": [
                            {"pubkey": "SENDER1111111111111111111111111111111111111111"},
                            {"pubkey": "RECEIVER11111111111111111111111111111111111111"}
                        ],
                        "instructions": [
                            {
                                "programId": "11111111111111111111111111111111",
                                "accounts": [0, 1],
                                "data": ""
                            }
                        ]
                    }
                }
            },
            "id": 1
        }).to_string();

        let client = MockClient::new(vec![tx_json]);
        let report = decode_transaction(
            &client,
            "http://localhost",
            "5VERIFIEDTXSIG111111111111111111111111111111111111111111111111111",
        )
        .expect("should succeed");

        assert!(report.success);
        assert_eq!(report.slot, 320000000);
        assert_eq!(report.fee, 5000);
        assert!(report.summary.contains("✅"));
        assert!(report.summary.contains("System Program"));
    }

    #[test]
    fn test_failed_tx() {
        let tx_json = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "slot": 320000001,
                "blockTime": null,
                "meta": {
                    "err": {"InstructionError": [0, "Custom"]},
                    "fee": 5000,
                    "preBalances": [1000000000],
                    "postBalances": [1000000000],
                    "preTokenBalances": [],
                    "postTokenBalances": []
                },
                "transaction": {
                    "message": {
                        "accountKeys": [
                            {"pubkey": "SENDER1111111111111111111111111111111111111111"}
                        ],
                        "instructions": []
                    }
                }
            },
            "id": 1
        }).to_string();

        let client = MockClient::new(vec![tx_json]);
        let report = decode_transaction(
            &client,
            "http://localhost",
            "FAILEDTXSIG11111111111111111111111111111111111111111111111111111",
        )
        .expect("should succeed");

        assert!(!report.success);
        assert!(report.summary.contains("❌"));
    }

    #[test]
    fn test_tx_not_found() {
        let tx_json = r#"{"jsonrpc":"2.0","result":null,"id":1}"#.to_string();

        let client = MockClient::new(vec![tx_json]);
        let result = decode_transaction(
            &client,
            "http://localhost",
            "NONEXISTENT111111111111111111111111111111111111111111111111111",
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_program_label_known() {
        assert_eq!(
            program_label("11111111111111111111111111111111"),
            "System Program"
        );
        assert_eq!(
            program_label("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            "Token Program"
        );
    }

    #[test]
    fn test_program_label_unknown() {
        let label = program_label("UnknownProg111111111111111111111111111111");
        assert!(label.contains("Unknown"));
        assert!(label.contains("Unkn"));
    }
}
