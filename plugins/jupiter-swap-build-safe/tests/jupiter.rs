use base64::Engine;
use jupiter_swap_build_safe::*;
use serde_json::{json, Value};

fn key(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}

fn compact(n: usize, out: &mut Vec<u8>) {
    out.push(n as u8);
}

fn transfer_tx(recipient: &str) -> String {
    let signer = key(1);
    let mut b = Vec::new();
    compact(1, &mut b);
    b.extend([0u8; 64]);
    b.extend([1, 0, 1]);
    compact(3, &mut b);
    for a in [&signer, recipient, SYSTEM_PROGRAM] {
        b.extend(bs58::decode(a).into_vec().unwrap());
    }
    b.extend([9u8; 32]);
    compact(1, &mut b);
    b.push(2);
    compact(2, &mut b);
    b.extend([0, 1]);
    let mut data = Vec::new();
    data.extend(2u32.to_le_bytes());
    data.extend(2_000_000_000u64.to_le_bytes());
    compact(data.len(), &mut b);
    b.extend(data);
    base64::engine::general_purpose::STANDARD.encode(b)
}

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
fn plugin_crate_reexports_guarded_jupiter_core() {
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
            route_plan: Vec::new(),
            raw: Value::Null,
        },
        swap: SwapResponse {
            swap_transaction: transfer_tx(&key(7)),
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
    assert!(out.contains("\"verdict\":\"RED\""));
    assert!(out.contains("\"unsigned_transaction_base64\":null"));
}

#[test]
fn parameters_schema_is_valid_json() {
    let schema: serde_json::Value = serde_json::from_str(&parameters_schema_json()).unwrap();
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("user_public_key")));
}
