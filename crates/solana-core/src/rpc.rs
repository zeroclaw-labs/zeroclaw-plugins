//! Solana JSON-RPC request construction and response-envelope parsing.
//!
//! This module is pure: it builds the `serde_json::Value` request bodies and
//! parses the `Value` responses. The actual HTTP round-trip is done by the
//! plugin's `wasm`-only shim over `waki` (`wasi:http`), so the wire format lives
//! here where it is host-testable with fixtures and no network.

use serde_json::{json, Value};

/// Build a JSON-RPC 2.0 request body for `method` with `params`.
///
/// The id is fixed at 1: a plugin issues one request per call and reads one
/// response, so there is nothing to correlate.
pub fn request(method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
}

/// Extract the `result` field from a JSON-RPC response, turning a JSON-RPC
/// `error` object into a readable `Err` string.
pub fn result(response: &Value) -> Result<&Value, String> {
    if let Some(err) = response.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown RPC error");
        return Err(format!("RPC error {code}: {msg}"));
    }
    response
        .get("result")
        .ok_or_else(|| "RPC response missing both `result` and `error`".to_string())
}

/// Params for `getAccountInfo` with base64 encoding at `confirmed` commitment.
pub fn get_account_info_params(address: &str) -> Value {
    json!([address, { "encoding": "base64", "commitment": "confirmed" }])
}

/// Params for `getTokenLargestAccounts` at `confirmed` commitment.
pub fn get_token_largest_accounts_params(mint: &str) -> Value {
    json!([mint, { "commitment": "confirmed" }])
}

/// Params for `getTokenAccountsByOwner`, filtered to a token program, base64.
pub fn get_token_accounts_by_owner_params(owner: &str, program_id: &str) -> Value {
    json!([
        owner,
        { "programId": program_id },
        { "encoding": "base64", "commitment": "confirmed" }
    ])
}

/// A decoded `getAccountInfo` result: the raw account bytes plus context the
/// caller needs (which token program owns it, whether it exists).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountData {
    /// Base58 program id that owns the account (e.g. the SPL Token program).
    pub owner: String,
    /// Raw account data bytes (base64-decoded).
    pub data: Vec<u8>,
    /// Lamport balance of the account.
    pub lamports: u64,
    /// Whether the account is marked executable.
    pub executable: bool,
}

/// Parse the `value` object of a `getAccountInfo` result into [`AccountData`].
///
/// `result` here is the inner `.result.value` (the account object), which is
/// `null` when the account does not exist. `Ok(None)` means "no such account",
/// distinct from `Err(_)` which means the response was malformed.
pub fn parse_account(value: &Value) -> Result<Option<AccountData>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("account missing `owner`")?
        .to_string();
    let lamports = value.get("lamports").and_then(Value::as_u64).unwrap_or(0);
    let executable = value
        .get("executable")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let data_field = value.get("data").ok_or("account missing `data`")?;
    let data = decode_account_data(data_field)?;

    Ok(Some(AccountData {
        owner,
        data,
        lamports,
        executable,
    }))
}

/// Decode the `data` field of an account. Solana returns base64-encoded account
/// data as `[ "<base64>", "base64" ]`.
pub fn decode_account_data(data_field: &Value) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let arr = data_field
        .as_array()
        .ok_or("account `data` is not the expected [base64, encoding] array")?;
    let b64 = arr
        .first()
        .and_then(Value::as_str)
        .ok_or("account `data[0]` is not a string")?;
    STANDARD
        .decode(b64)
        .map_err(|e| format!("account data is not valid base64: {e}"))
}

/// Unwrap a result that is wrapped in a `{ context, value }` envelope (as
/// `getAccountInfo`, `getTokenLargestAccounts`, `getTokenAccountsByOwner` are),
/// returning the inner `value`.
pub fn value_field(result: &Value) -> Result<&Value, String> {
    result
        .get("value")
        .ok_or_else(|| "RPC result missing `value` envelope field".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_jsonrpc_envelope() {
        let req = request("getAccountInfo", get_account_info_params("So111"));
        assert_eq!(req["jsonrpc"], "2.0");
        assert_eq!(req["method"], "getAccountInfo");
        assert_eq!(req["params"][0], "So111");
        assert_eq!(req["params"][1]["encoding"], "base64");
    }

    #[test]
    fn surfaces_rpc_errors_as_readable_strings() {
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "error": { "code": -32602, "message": "Invalid param" }
        });
        let err = result(&resp).unwrap_err();
        assert!(err.contains("-32602"));
        assert!(err.contains("Invalid param"));
    }

    #[test]
    fn extracts_result_when_present() {
        let resp = json!({ "jsonrpc": "2.0", "id": 1, "result": { "value": 42 } });
        assert_eq!(result(&resp).unwrap()["value"], 42);
    }

    #[test]
    fn errors_when_neither_result_nor_error() {
        let resp = json!({ "jsonrpc": "2.0", "id": 1 });
        assert!(result(&resp).is_err());
    }

    #[test]
    fn parses_a_present_account() {
        // base64("hi") == "aGk="
        let value = json!({
            "owner": crate::programs::SPL_TOKEN,
            "lamports": 2039280u64,
            "executable": false,
            "data": ["aGk=", "base64"],
        });
        let acct = parse_account(&value).unwrap().unwrap();
        assert_eq!(acct.owner, crate::programs::SPL_TOKEN);
        assert_eq!(acct.lamports, 2039280);
        assert_eq!(acct.data, b"hi");
    }

    #[test]
    fn null_account_is_none_not_error() {
        assert_eq!(parse_account(&Value::Null).unwrap(), None);
    }

    #[test]
    fn malformed_account_is_error() {
        let value = json!({ "lamports": 1 }); // no owner, no data
        assert!(parse_account(&value).is_err());
    }
}
