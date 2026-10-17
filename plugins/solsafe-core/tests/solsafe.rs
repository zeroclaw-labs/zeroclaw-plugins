use std::collections::HashMap;

use base64::Engine;
use serde_json::{json, Value};
use solsafe_core::*;

fn key(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}

fn compact(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        out.push(((n & 0x7f) as u8) | 0x80);
        out.push((n >> 7) as u8);
    }
}

fn addr_bytes(addr: &str) -> Vec<u8> {
    bs58::decode(addr).into_vec().unwrap()
}

fn tx(program: &str, accounts: Vec<String>, ix_accounts: Vec<u8>, data: Vec<u8>) -> String {
    let mut all_accounts = accounts;
    all_accounts.push(program.to_string());
    let program_idx = (all_accounts.len() - 1) as u8;
    let mut b = Vec::new();
    compact(1, &mut b);
    b.extend([0u8; 64]);
    b.extend([1, 0, 1]);
    compact(all_accounts.len(), &mut b);
    for a in &all_accounts {
        b.extend(addr_bytes(a));
    }
    b.extend([9u8; 32]);
    compact(1, &mut b);
    b.push(program_idx);
    compact(ix_accounts.len(), &mut b);
    b.extend(ix_accounts);
    compact(data.len(), &mut b);
    b.extend(data);
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn system_transfer(lamports: u64, recipient: &str) -> String {
    let mut data = Vec::new();
    data.extend(2u32.to_le_bytes());
    data.extend(lamports.to_le_bytes());
    tx(
        SYSTEM_PROGRAM,
        vec![key(1), recipient.to_string()],
        vec![0, 1],
        data,
    )
}

fn jupiter_route_tx(signer: &str) -> String {
    tx(
        JUPITER_V6_PROGRAM,
        vec![signer.to_string()],
        Vec::new(),
        vec![1],
    )
}

fn token_ix(tag: u8) -> String {
    tx(
        SPL_TOKEN_PROGRAM,
        vec![key(1), key(2), key(3)],
        vec![0, 1, 2],
        vec![tag],
    )
}

fn token_transfer(amount: u64, recipient: &str) -> String {
    let mut data = vec![3u8];
    data.extend(amount.to_le_bytes());
    tx(
        SPL_TOKEN_PROGRAM,
        vec![key(1), recipient.to_string(), key(3)],
        vec![0, 1, 2],
        data,
    )
}

fn v0_lookup_tx() -> String {
    let mut b = Vec::new();
    compact(1, &mut b);
    b.extend([0u8; 64]);
    b.push(0x80);
    b.extend([1, 0, 1]);
    compact(2, &mut b);
    b.extend(addr_bytes(&key(1)));
    b.extend(addr_bytes(JUPITER_V6_PROGRAM));
    b.extend([9u8; 32]);
    compact(1, &mut b);
    b.push(1);
    compact(0, &mut b);
    compact(1, &mut b);
    b.push(1);
    compact(1, &mut b);
    b.extend([8u8; 32]);
    compact(0, &mut b);
    compact(0, &mut b);
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn base64_bytes(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[derive(Default)]
struct MockRpc {
    values: HashMap<String, Value>,
    fail: bool,
}

impl RpcClient for MockRpc {
    fn call(&self, method: &str, _params: Value) -> Result<Value, SolSafeError> {
        if self.fail {
            return Err(SolSafeError::Rpc("mock failure".to_string()));
        }
        self.values
            .get(method)
            .cloned()
            .ok_or_else(|| SolSafeError::Rpc(format!("missing mock {method}")))
    }
}

#[derive(Clone)]
struct MockJupiter {
    quote: QuoteResponse,
    swap: SwapResponse,
}

impl JupiterClient for MockJupiter {
    fn get_quote(&self, _request: QuoteRequest) -> Result<QuoteResponse, SolSafeError> {
        Ok(self.quote.clone())
    }

    fn build_swap(&self, _request: SwapRequest) -> Result<SwapResponse, SolSafeError> {
        Ok(self.swap.clone())
    }
}

#[test]
fn valid_legacy_sol_transfer_is_green_with_declared_recipient() {
    let recipient = key(2);
    let args = json!({
        "transaction_base64": system_transfer(1, &recipient),
        "declared_intent": {
            "action": "transfer",
            "expected_recipient": recipient,
            "expected_signer": key(1)
        },
        "options": {"simulate": false, "strict": true}
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("\"verdict\":\"GREEN\""));
}

#[test]
fn malformed_json_is_rejected() {
    let err = audit_json("{", None).unwrap_err().to_string();
    assert!(err.contains("invalid JSON"));
}

#[test]
fn invalid_base58_in_intent_is_rejected() {
    let args = json!({
        "transaction_base64": system_transfer(1, &key(2)),
        "declared_intent": {"action": "transfer", "expected_recipient": "not_base58!"}
    });
    assert!(audit_json(&args.to_string(), None)
        .unwrap_err()
        .to_string()
        .contains("base58"));
}

#[test]
fn malformed_base64_returns_red_report() {
    let args = json!({"transaction_base64": "%%%bad%%%"});
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("\"verdict\":\"RED\""));
    assert!(out.contains("MALFORMED_TRANSACTION"));
}

#[test]
fn oversized_transaction_is_red() {
    let mut cfg = HashMap::new();
    cfg.insert("max_transaction_bytes".to_string(), "8".to_string());
    let args = json!({
        "transaction_base64": system_transfer(1, &key(2)),
        "__config": cfg
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("MALFORMED_TRANSACTION"));
}

#[test]
fn truncated_transaction_is_red() {
    let args = json!({"transaction_base64": base64_bytes(&[1, 0, 0])});
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("truncated payload"));
}

#[test]
fn invalid_compact_u16_is_red() {
    let args = json!({"transaction_base64": base64_bytes(&[0x80, 0x80, 0x80])});
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("invalid compact-u16"));
}

#[test]
fn unsupported_version_is_red() {
    let mut b = Vec::new();
    compact(0, &mut b);
    b.push(0x81);
    let args = json!({"transaction_base64": base64_bytes(&b)});
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("unsupported transaction version"));
}

#[test]
fn invalid_account_index_is_red() {
    let mut b = Vec::new();
    compact(0, &mut b);
    b.extend([0, 0, 0]);
    compact(1, &mut b);
    b.extend(addr_bytes(&key(1)));
    b.extend([9u8; 32]);
    compact(1, &mut b);
    b.push(9);
    compact(0, &mut b);
    compact(0, &mut b);
    let args = json!({"transaction_base64": base64_bytes(&b)});
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("program account index is invalid"));
}

#[test]
fn unexpected_sol_transfer_is_red_for_swap_intent() {
    let args = json!({
        "transaction_base64": system_transfer(2_000_000_000, &key(3)),
        "declared_intent": {"action": "swap", "expected_signer": key(1)},
        "options": {"simulate": false, "strict": true}
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("\"verdict\":\"RED\""));
    assert!(out.contains("UNEXPECTED_SOL_TRANSFER"));
}

#[test]
fn unexpected_spl_transfer_and_recipient_are_red() {
    let args = json!({
        "transaction_base64": token_transfer(5, &key(4)),
        "declared_intent": {"action": "transfer", "expected_recipient": key(5)},
        "options": {"simulate": false, "strict": true}
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("UNEXPECTED_RECIPIENT"));
}

#[test]
fn unexpected_signer_is_red() {
    let args = json!({
        "transaction_base64": jupiter_route_tx(&key(1)),
        "declared_intent": {"action": "swap", "expected_signer": key(2)},
        "options": {"simulate": false, "strict": true}
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("EXPECTED_SIGNER_MISSING"));
}

#[test]
fn sol_transfer_amount_cap_is_red() {
    let mut cfg = HashMap::new();
    cfg.insert("max_sol_transfer_lamports".to_string(), "1".to_string());
    let args = json!({
        "transaction_base64": system_transfer(2, &key(2)),
        "declared_intent": {"action": "transfer", "expected_recipient": key(2)},
        "__config": cfg,
        "options": {"simulate": false}
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("SOL_TRANSFER_ABOVE_LIMIT"));
}

#[test]
fn token_delegate_approval_is_red() {
    let mut data = vec![4u8];
    data.extend(10u64.to_le_bytes());
    let args = json!({
        "transaction_base64": tx(SPL_TOKEN_PROGRAM, vec![key(1), key(2), key(3)], vec![0, 1, 2], data),
        "options": {"simulate": false, "strict": true}
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("DELEGATE_APPROVAL"));
    assert!(out.contains("\"verdict\":\"RED\""));
}

#[test]
fn token_security_instructions_are_reported() {
    for (tag, code) in [
        (6, "AUTHORITY_CHANGE"),
        (7, "MINT_TO"),
        (8, "BURN"),
        (9, "TOKEN_ACCOUNT_CLOSE"),
    ] {
        let args = json!({
            "transaction_base64": token_ix(tag),
            "options": {"simulate": false, "strict": true}
        });
        let out = audit_json(&args.to_string(), None).unwrap();
        assert!(out.contains(code), "missing {code}: {out}");
    }
}

#[test]
fn forbidden_and_unknown_program_are_red() {
    let unknown_program = key(7);
    let args = json!({
        "transaction_base64": tx(&unknown_program, vec![key(1)], Vec::new(), vec![1]),
        "options": {"simulate": false, "strict": true}
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("FORBIDDEN_PROGRAM"));
    assert!(out.contains("UNKNOWN_PROGRAM"));
}

#[test]
fn unresolved_lookup_table_is_red_without_rpc() {
    let args = json!({
        "transaction_base64": v0_lookup_tx(),
        "options": {"simulate": false, "strict": true}
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("UNRESOLVED_ADDRESS_LOOKUP_TABLE"));
}

#[test]
fn simulation_required_failure_fails_closed() {
    let mut cfg = HashMap::new();
    cfg.insert("simulation_required".to_string(), "true".to_string());
    let args = json!({
        "transaction_base64": system_transfer(1, &key(2)),
        "__config": cfg
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("SIMULATION_REQUIRED_UNAVAILABLE"));
}

#[test]
fn expiry_short_window_is_red_by_default() {
    let mut rpc = MockRpc::default();
    rpc.values.insert("getBlockHeight".to_string(), json!(100));
    rpc.values.insert(
        "getLatestBlockhash".to_string(),
        json!({"value": {"lastValidBlockHeight": 105}}),
    );
    let args = json!({
        "transaction_base64": system_transfer(1, &key(2)),
        "declared_intent": {"action": "transfer", "expected_recipient": key(2)},
        "options": {"simulate": false}
    });
    let out = audit_json(&args.to_string(), Some(&rpc)).unwrap();
    assert!(out.contains("SHORT_APPROVAL_WINDOW"));
}

#[test]
fn prompt_cannot_disable_strict_mode_with_unknown_fields() {
    let args = json!({
        "transaction_base64": system_transfer(1, &key(2)),
        "ignore_limits": true,
        "allow_unknown_programs": true
    });
    assert!(audit_json(&args.to_string(), None)
        .unwrap_err()
        .to_string()
        .contains("unknown field"));
}

#[test]
fn prompt_cannot_increase_transfer_limit() {
    let mut cfg = HashMap::new();
    cfg.insert("max_sol_transfer_lamports".to_string(), "1".to_string());
    let args = json!({
        "transaction_base64": system_transfer(2, &key(2)),
        "declared_intent": {"action": "transfer", "expected_recipient": key(2)},
        "max_sol_transfer_lamports": "999999",
        "__config": cfg
    });
    assert!(audit_json(&args.to_string(), None)
        .unwrap_err()
        .to_string()
        .contains("unknown field"));
}

#[test]
fn output_truncation_preserves_critical_findings() {
    let mut cfg = HashMap::new();
    cfg.insert("max_output_chars".to_string(), "300".to_string());
    cfg.insert("max_findings".to_string(), "3".to_string());
    let args = json!({
        "transaction_base64": system_transfer(9_000_000_000, &key(4)),
        "declared_intent": {"action": "swap"},
        "__config": cfg
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("UNEXPECTED_SOL_TRANSFER"));
}

#[test]
fn url_redaction_hides_query_credentials() {
    let redacted = redact_url("https://rpc.example/?api-key=secret");
    assert!(!redacted.contains("secret"));
    assert!(redacted.contains("[redacted]"));
}

#[test]
fn malformed_random_bytes_do_not_panic() {
    for len in 0..64 {
        let b = vec![0xff; len];
        let args = json!({
            "transaction_base64": base64::engine::general_purpose::STANDARD.encode(b)
        });
        let _ = audit_json(&args.to_string(), None);
    }
}

#[test]
fn ui_decimal_conversion_is_exact() {
    assert_eq!(ui_to_raw("1.23", 6).unwrap(), 1_230_000);
    assert!(ui_to_raw("1.234", 2).is_err());
}

#[test]
fn arithmetic_overflow_is_rejected() {
    assert!(ui_to_raw("340282366920938463463374607431768211455", 1).is_err());
}

#[test]
fn valid_guarded_jupiter_swap_can_be_green() {
    let input_mint = key(8);
    let output_mint = key(9);
    let mock = MockJupiter {
        quote: QuoteResponse {
            input_mint: input_mint.clone(),
            output_mint: output_mint.clone(),
            in_amount: "1".to_string(),
            out_amount: "10".to_string(),
            other_amount_threshold: "9".to_string(),
            price_impact_pct: "0".to_string(),
            route_plan: vec![RouteLeg {
                input_mint: Some(input_mint.clone()),
                output_mint: Some(output_mint.clone()),
                amm_key: None,
                label: Some("mock".to_string()),
            }],
            raw: json!({}),
        },
        swap: SwapResponse {
            swap_transaction: jupiter_route_tx(&key(1)),
        },
    };
    let args = json!({
        "user_public_key": key(1),
        "input_mint": input_mint,
        "output_mint": output_mint,
        "amount": "1",
        "amount_type": "raw",
        "slippage_bps": 50
    });
    let out = jupiter_build_json(&args.to_string(), &mock, None).unwrap();
    assert!(out.contains("\"verdict\":\"GREEN\""), "{out}");
    assert!(!out.contains("\"unsigned_transaction_base64\":null"));
}

#[test]
fn guarded_jupiter_swap_rejects_prompt_amount_over_cap() {
    let input_mint = key(8);
    let output_mint = key(9);
    let mut cfg = HashMap::new();
    cfg.insert(
        "max_raw_amount_by_mint".to_string(),
        format!("{{\"{}\":\"250\"}}", input_mint),
    );
    let args = json!({
        "user_public_key": key(1),
        "input_mint": input_mint,
        "output_mint": output_mint,
        "amount": "100000",
        "amount_type": "raw",
        "slippage_bps": 50,
        "__config": cfg
    });
    let mock = MockJupiter {
        quote: QuoteResponse {
            input_mint: key(8),
            output_mint: key(9),
            in_amount: "100000".to_string(),
            out_amount: "1".to_string(),
            other_amount_threshold: "1".to_string(),
            price_impact_pct: "0".to_string(),
            route_plan: Vec::new(),
            raw: json!({}),
        },
        swap: SwapResponse {
            swap_transaction: system_transfer(1, &key(2)),
        },
    };
    assert!(jupiter_build_json(&args.to_string(), &mock, None)
        .unwrap_err()
        .to_string()
        .contains("exceeds configured maximum"));
}

#[test]
fn jupiter_input_policy_rejections() {
    let input_mint = key(8);
    let output_mint = key(9);
    let mock = MockJupiter {
        quote: QuoteResponse {
            input_mint: input_mint.clone(),
            output_mint: output_mint.clone(),
            in_amount: "1".to_string(),
            out_amount: "1".to_string(),
            other_amount_threshold: "1".to_string(),
            price_impact_pct: "0".to_string(),
            route_plan: Vec::new(),
            raw: json!({}),
        },
        swap: SwapResponse {
            swap_transaction: jupiter_route_tx(&key(1)),
        },
    };
    for args in [
        json!({"user_public_key": key(1), "input_mint": input_mint, "output_mint": input_mint, "amount": "1", "amount_type": "raw", "slippage_bps": 50}),
        json!({"user_public_key": key(1), "input_mint": key(8), "output_mint": key(9), "amount": "0", "amount_type": "raw", "slippage_bps": 50}),
        json!({"user_public_key": key(1), "input_mint": key(8), "output_mint": key(9), "amount": "nope", "amount_type": "raw", "slippage_bps": 50}),
        json!({"user_public_key": key(1), "input_mint": key(8), "output_mint": key(9), "amount": "1", "amount_type": "raw", "slippage_bps": 101, "__config": {"max_slippage_bps": "100"}}),
    ] {
        assert!(jupiter_build_json(&args.to_string(), &mock, None).is_err());
    }
}

#[test]
fn ui_amount_conversion_uses_rpc_decimals() {
    let input_mint = key(8);
    let output_mint = key(9);
    let mut rpc = MockRpc::default();
    rpc.values.insert(
        "getTokenSupply".to_string(),
        json!({"value": {"decimals": 6}}),
    );
    rpc.values.insert(
        "simulateTransaction".to_string(),
        json!({"value": {"err": null, "unitsConsumed": 10}}),
    );
    rpc.values.insert("getBlockHeight".to_string(), json!(100));
    rpc.values.insert(
        "getLatestBlockhash".to_string(),
        json!({"value": {"lastValidBlockHeight": 200}}),
    );
    let mock = MockJupiter {
        quote: QuoteResponse {
            input_mint: input_mint.clone(),
            output_mint: output_mint.clone(),
            in_amount: "1230000".to_string(),
            out_amount: "1".to_string(),
            other_amount_threshold: "1".to_string(),
            price_impact_pct: "0".to_string(),
            route_plan: Vec::new(),
            raw: json!({}),
        },
        swap: SwapResponse {
            swap_transaction: jupiter_route_tx(&key(1)),
        },
    };
    let args = json!({
        "user_public_key": key(1),
        "input_mint": input_mint,
        "output_mint": output_mint,
        "amount": "1.23",
        "amount_type": "ui",
        "slippage_bps": 50
    });
    let out = jupiter_build_json(&args.to_string(), &mock, Some(&rpc)).unwrap();
    assert!(out.contains("\"verdict\":\"GREEN\""));
}

#[test]
fn jupiter_quote_policy_rejections() {
    let input_mint = key(8);
    let output_mint = key(9);
    let base_args = json!({
        "user_public_key": key(1),
        "input_mint": input_mint,
        "output_mint": output_mint,
        "amount": "1",
        "amount_type": "raw",
        "slippage_bps": 50,
        "__config": {
            "max_price_impact_pct": "1.0",
            "max_route_hops": "1",
            "allowed_intermediate_mints": key(10)
        }
    });
    for quote in [
        QuoteResponse {
            input_mint: key(8),
            output_mint: key(9),
            in_amount: "1".to_string(),
            out_amount: "1".to_string(),
            other_amount_threshold: "1".to_string(),
            price_impact_pct: "2.0".to_string(),
            route_plan: Vec::new(),
            raw: json!({}),
        },
        QuoteResponse {
            input_mint: key(8),
            output_mint: key(9),
            in_amount: "1".to_string(),
            out_amount: "1".to_string(),
            other_amount_threshold: "1".to_string(),
            price_impact_pct: "0".to_string(),
            route_plan: vec![
                RouteLeg {
                    input_mint: Some(key(8)),
                    output_mint: Some(key(10)),
                    amm_key: None,
                    label: None,
                },
                RouteLeg {
                    input_mint: Some(key(10)),
                    output_mint: Some(key(9)),
                    amm_key: None,
                    label: None,
                },
            ],
            raw: json!({}),
        },
        QuoteResponse {
            input_mint: key(8),
            output_mint: key(9),
            in_amount: "1".to_string(),
            out_amount: "1".to_string(),
            other_amount_threshold: "1".to_string(),
            price_impact_pct: "0".to_string(),
            route_plan: vec![RouteLeg {
                input_mint: Some(key(11)),
                output_mint: Some(key(9)),
                amm_key: None,
                label: None,
            }],
            raw: json!({}),
        },
        QuoteResponse {
            input_mint: key(12),
            output_mint: key(9),
            in_amount: "1".to_string(),
            out_amount: "1".to_string(),
            other_amount_threshold: "1".to_string(),
            price_impact_pct: "0".to_string(),
            route_plan: Vec::new(),
            raw: json!({}),
        },
    ] {
        let mock = MockJupiter {
            quote,
            swap: SwapResponse {
                swap_transaction: jupiter_route_tx(&key(1)),
            },
        };
        assert!(jupiter_build_json(&base_args.to_string(), &mock, None).is_err());
    }
}

#[test]
fn missing_or_malformed_swap_transaction_is_rejected_or_red() {
    let input_mint = key(8);
    let output_mint = key(9);
    let quote = QuoteResponse {
        input_mint: input_mint.clone(),
        output_mint: output_mint.clone(),
        in_amount: "1".to_string(),
        out_amount: "1".to_string(),
        other_amount_threshold: "1".to_string(),
        price_impact_pct: "0".to_string(),
        route_plan: Vec::new(),
        raw: json!({}),
    };
    let args = json!({
        "user_public_key": key(1),
        "input_mint": input_mint,
        "output_mint": output_mint,
        "amount": "1",
        "amount_type": "raw",
        "slippage_bps": 50
    });
    let empty = MockJupiter {
        quote: quote.clone(),
        swap: SwapResponse {
            swap_transaction: String::new(),
        },
    };
    assert!(jupiter_build_json(&args.to_string(), &empty, None).is_err());
    let malformed = MockJupiter {
        quote,
        swap: SwapResponse {
            swap_transaction: "bad".to_string(),
        },
    };
    let out = jupiter_build_json(&args.to_string(), &malformed, None).unwrap();
    assert!(out.contains("\"verdict\":\"RED\""));
    assert!(out.contains("\"unsigned_transaction_base64\":null"));
}

#[test]
fn jupiter_audit_catches_unexpected_signer_and_token_authority() {
    let input_mint = key(8);
    let output_mint = key(9);
    for swap_transaction in [jupiter_route_tx(&key(2)), token_ix(6), token_ix(4)] {
        let mock = MockJupiter {
            quote: QuoteResponse {
                input_mint: input_mint.clone(),
                output_mint: output_mint.clone(),
                in_amount: "1".to_string(),
                out_amount: "1".to_string(),
                other_amount_threshold: "1".to_string(),
                price_impact_pct: "0".to_string(),
                route_plan: Vec::new(),
                raw: json!({"large": ["raw response should not appear"]}),
            },
            swap: SwapResponse { swap_transaction },
        };
        let args = json!({
            "user_public_key": key(1),
            "input_mint": input_mint,
            "output_mint": output_mint,
            "amount": "1",
            "amount_type": "raw",
            "slippage_bps": 50
        });
        let out = jupiter_build_json(&args.to_string(), &mock, None).unwrap();
        assert!(out.contains("\"verdict\":\"RED\""));
        assert!(out.contains("\"unsigned_transaction_base64\":null"));
        assert!(!out.contains("raw response should not appear"));
    }
}

#[test]
fn jupiter_required_simulation_failure_is_red() {
    let input_mint = key(8);
    let output_mint = key(9);
    let args = json!({
        "user_public_key": key(1),
        "input_mint": input_mint,
        "output_mint": output_mint,
        "amount": "1",
        "amount_type": "raw",
        "slippage_bps": 50,
        "__config": {"simulation_required": "true"}
    });
    let mock = MockJupiter {
        quote: QuoteResponse {
            input_mint: key(8),
            output_mint: key(9),
            in_amount: "1".to_string(),
            out_amount: "1".to_string(),
            other_amount_threshold: "1".to_string(),
            price_impact_pct: "0".to_string(),
            route_plan: Vec::new(),
            raw: json!({}),
        },
        swap: SwapResponse {
            swap_transaction: jupiter_route_tx(&key(1)),
        },
    };
    let out = jupiter_build_json(&args.to_string(), &mock, None).unwrap();
    assert!(out.contains("SIMULATION_REQUIRED_UNAVAILABLE"));
}

#[test]
fn guarded_jupiter_swap_returns_no_transaction_after_red_audit() {
    let input_mint = key(8);
    let output_mint = key(9);
    let args = json!({
        "user_public_key": key(1),
        "input_mint": input_mint,
        "output_mint": output_mint,
        "amount": "1",
        "amount_type": "raw",
        "slippage_bps": 50
    });
    let mock = MockJupiter {
        quote: QuoteResponse {
            input_mint: key(8),
            output_mint: key(9),
            in_amount: "1".to_string(),
            out_amount: "10".to_string(),
            other_amount_threshold: "9".to_string(),
            price_impact_pct: "0".to_string(),
            route_plan: vec![RouteLeg {
                input_mint: Some(key(8)),
                output_mint: Some(key(9)),
                amm_key: None,
                label: Some("mock".to_string()),
            }],
            raw: json!({}),
        },
        swap: SwapResponse {
            swap_transaction: system_transfer(2_000_000_000, &key(7)),
        },
    };
    let out = jupiter_build_json(&args.to_string(), &mock, None).unwrap();
    assert!(out.contains("\"verdict\":\"RED\""));
    assert!(out.contains("\"unsigned_transaction_base64\":null"));
}
