//! Pure payment-watch logic — balance checking, status evaluation.
//!
//! Host-testable: no wasm dependency, compiles and tests on the host
//! with a plain `cargo test`.
//!
//! # T0 implementation
//!
//! Checks the current balance of an address against an expected amount.
//! For SOL, queries the account lamports. For SPL tokens, queries
//! token accounts by owner. Returns a structured JSON status string.

use solana_core::SolanaRpc;

/// Evaluate payment status purely from balance data (no RPC needed).
///
/// Returns a JSON string with one of three statuses:
/// - `CONFIRMED` — balance meets or exceeds expected
/// - `PENDING` — partial balance detected, shortfall reported
/// - `NOT_FOUND` — zero balance, no payment detected
pub fn evaluate_payment(
    address: &str,
    current_balance: f64,
    expected_amount: f64,
    expected_mint: &str,
    reference: Option<&str>,
) -> String {
    let ref_json = reference
        .map(|r| format!(r#","reference":"{r}""#))
        .unwrap_or_default();

    if current_balance >= expected_amount {
        format!(
            r#"{{"status":"CONFIRMED","address":"{address}","mint":"{expected_mint}","balance":{current_balance},"expected":{expected_amount}{ref_json}}}"#
        )
    } else if current_balance > 0.0 {
        let shortfall = expected_amount - current_balance;
        let shortfall = (shortfall * 1_000_000.0).round() / 1_000_000.0;
        format!(
            r#"{{"status":"PENDING","address":"{address}","mint":"{expected_mint}","balance":{current_balance},"expected":{expected_amount},"shortfall":{shortfall}{ref_json}}}"#
        )
    } else {
        format!(
            r#"{{"status":"NOT_FOUND","address":"{address}","mint":"{expected_mint}","expected":{expected_amount}{ref_json}}}"#
        )
    }
}

/// Check if a payment has been received at the given address.
///
/// Connects to the Solana RPC at `rpc_url` to query the current balance,
/// then evaluates whether the expected payment has arrived.
///
/// For SOL: checks the account lamports (converted to SOL).
/// For SPL tokens: queries token accounts by owner for the given mint.
pub fn check_payment(
    address: &str,
    expected_amount: f64,
    expected_mint: &str,
    reference: Option<&str>,
    rpc_url: &str,
) -> Result<String, String> {
    let rpc = SolanaRpc::new(rpc_url);

    let current_balance = if expected_mint.eq_ignore_ascii_case("SOL") {
        get_sol_balance(&rpc, address)?
    } else {
        get_token_balance(&rpc, address, expected_mint)?
    };

    Ok(evaluate_payment(
        address,
        current_balance,
        expected_amount,
        expected_mint,
        reference,
    ))
}

/// Fetch SOL balance (lamports -> SOL).
fn get_sol_balance(rpc: &SolanaRpc, address: &str) -> Result<f64, String> {
    let info = rpc.get_account_info(address)?;
    Ok(info.lamports as f64 / 1_000_000_000.0)
}

/// Fetch SPL token balance for a specific mint at an address.
fn get_token_balance(rpc: &SolanaRpc, address: &str, mint: &str) -> Result<f64, String> {
    let params: Vec<serde_json::Value> = vec![
        serde_json::json!(address),
        serde_json::json!({ "mint": mint }),
        serde_json::json!({ "encoding": "jsonParsed", "commitment": "confirmed" }),
    ];

    #[derive(serde::Deserialize)]
    struct TokenAmount {
        #[serde(rename = "uiAmount")]
        ui_amount: Option<f64>,
        amount: String,
        decimals: u8,
    }

    #[derive(serde::Deserialize)]
    struct TokenAccountInfo {
        #[serde(rename = "tokenAmount")]
        token_amount: TokenAmount,
    }

    #[derive(serde::Deserialize)]
    struct ParsedData {
        info: TokenAccountInfo,
    }

    #[derive(serde::Deserialize)]
    struct AccountData {
        #[serde(rename = "parsed")]
        parsed: Option<ParsedData>,
    }

    #[derive(serde::Deserialize)]
    struct TokenAccountEntry {
        account: AccountData,
    }

    #[derive(serde::Deserialize)]
    struct TokenAccountsResult {
        value: Vec<TokenAccountEntry>,
    }

    let result: TokenAccountsResult = rpc.call("getTokenAccountsByOwner", params)?;

    let total: f64 = result
        .value
        .iter()
        .filter_map(|entry| entry.account.parsed.as_ref())
        .filter_map(|parsed| parsed.info.token_amount.ui_amount)
        .sum();

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sol_lamports_conversion() {
        let lamports = 1_500_000_000u64;
        let sol = lamports as f64 / 1_000_000_000.0;
        assert!((sol - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_evaluate_confirmed_exact() {
        let json =
            evaluate_payment("abc123", 1.0, 1.0, "SOL", None);
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["status"], "CONFIRMED");
        assert_eq!(val["address"], "abc123");
        assert_eq!(val["balance"].as_f64().unwrap(), 1.0);
        assert_eq!(val["expected"].as_f64().unwrap(), 1.0);
        assert_eq!(val["mint"], "SOL");
        assert!(val.get("shortfall").is_none());
        assert!(val.get("reference").is_none());
    }

    #[test]
    fn test_evaluate_confirmed_overpayment() {
        let json = evaluate_payment(
            "xyz789",
            5.0,
            1.0,
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            None,
        );
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["status"], "CONFIRMED");
        assert_eq!(val["balance"].as_f64().unwrap(), 5.0);
    }

    #[test]
    fn test_evaluate_pending_partial() {
        let json = evaluate_payment("def456", 0.5, 1.0, "SOL", None);
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["status"], "PENDING");
        assert_eq!(val["balance"].as_f64().unwrap(), 0.5);
        assert_eq!(val["shortfall"].as_f64().unwrap(), 0.5);
    }

    #[test]
    fn test_evaluate_not_found() {
        let json = evaluate_payment("ghi789", 0.0, 1.0, "SOL", None);
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["status"], "NOT_FOUND");
        assert!(val.get("balance").is_none());
        assert!(val.get("shortfall").is_none());
    }

    #[test]
    fn test_evaluate_with_reference() {
        let json = evaluate_payment(
            "abc123",
            2.0,
            1.0,
            "SOL",
            Some("refKey123"),
        );
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["status"], "CONFIRMED");
        assert_eq!(val["reference"], "refKey123");
    }

    #[test]
    fn test_evaluate_pending_with_reference() {
        let json = evaluate_payment(
            "def456",
            0.3,
            1.0,
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            Some("myRef"),
        );
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["status"], "PENDING");
        assert_eq!(val["shortfall"].as_f64().unwrap(), 0.7);
        assert_eq!(val["reference"], "myRef");
    }

    #[test]
    fn test_evaluate_not_found_with_reference() {
        let json = evaluate_payment(
            "ghi789",
            0.0,
            1.0,
            "SOL",
            Some("xyzRef"),
        );
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["status"], "NOT_FOUND");
        assert_eq!(val["reference"], "xyzRef");
    }

    #[test]
    fn test_float_precision_trimming() {
        let json = evaluate_payment("addr", 0.123456789, 1.0, "SOL", None);
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["status"], "PENDING");
        let shortfall = val["shortfall"].as_f64().unwrap();
        assert!((shortfall - 0.876543).abs() < 0.000_001);
    }
}