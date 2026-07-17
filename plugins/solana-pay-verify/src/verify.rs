//! Pure settlement-verification core. HTTP is deliberately absent: the WASI
//! shim supplies JSON values, while host tests supply deterministic fixtures.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const DEFAULT_MAX_SIGNATURES: usize = 8;
const MAX_SIGNATURES_LIMIT: usize = 20;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifyArgs {
    pub reference: String,
    pub recipient: String,
    pub amount: String,
    #[serde(default)]
    pub spl_token: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedVerification {
    pub reference: String,
    pub recipient: String,
    pub amount: String,
    pub spl_token: Option<String>,
    pub memo: Option<String>,
    pub rpc_url: String,
    pub commitment: String,
    pub max_signatures: usize,
    pub network: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PaymentMatch {
    pub signature: String,
    pub slot: u64,
    pub received_amount: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VerifyOutput {
    pub status: &'static str,
    pub reference: String,
    pub recipient: String,
    pub expected_amount: String,
    pub asset: String,
    pub custody_tier: &'static str,
    pub signatures_scanned: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
    pub summary: String,
}

pub fn prepare(args: VerifyArgs) -> Result<PreparedVerification, String> {
    validate_pubkey("reference", &args.reference)?;
    validate_pubkey("recipient", &args.recipient)?;
    if args.reference == args.recipient {
        return Err("reference must be distinct from recipient".to_string());
    }
    if let Some(mint) = args.spl_token.as_deref() {
        validate_pubkey("spl_token", mint)?;
        if mint == args.reference || mint == args.recipient {
            return Err("spl_token must be distinct from reference and recipient".to_string());
        }
    }
    let amount = canonical_amount(&args.amount)?;
    if let Some(memo) = args.memo.as_deref() {
        if memo.is_empty() || memo.len() > 128 || memo.contains('\0') {
            return Err("memo must be 1..=128 UTF-8 bytes and contain no NUL".to_string());
        }
    }

    for key in args.config.keys() {
        if !matches!(
            key.as_str(),
            "rpc_url" | "commitment" | "max_signatures" | "network"
        ) {
            return Err(format!("unknown config key: {key}"));
        }
    }

    let rpc_url = args
        .config
        .get("rpc_url")
        .map(String::as_str)
        .unwrap_or(DEFAULT_RPC_URL);
    validate_rpc_url(rpc_url)?;
    let commitment = args
        .config
        .get("commitment")
        .map(String::as_str)
        .unwrap_or("confirmed");
    if !matches!(commitment, "confirmed" | "finalized") {
        return Err("commitment must be confirmed or finalized".to_string());
    }
    let max_signatures = args
        .config
        .get("max_signatures")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "max_signatures must be an integer".to_string())
        })
        .transpose()?
        .unwrap_or(DEFAULT_MAX_SIGNATURES);
    if !(1..=MAX_SIGNATURES_LIMIT).contains(&max_signatures) {
        return Err(format!("max_signatures must be 1..={MAX_SIGNATURES_LIMIT}"));
    }
    let network = args
        .config
        .get("network")
        .cloned()
        .unwrap_or_else(|| "mainnet-beta".to_string());
    if !matches!(
        network.as_str(),
        "mainnet-beta" | "devnet" | "testnet" | "custom"
    ) {
        return Err("network must be mainnet-beta, devnet, testnet, or custom".to_string());
    }

    Ok(PreparedVerification {
        reference: args.reference,
        recipient: args.recipient,
        amount,
        spl_token: args.spl_token,
        memo: args.memo,
        rpc_url: rpc_url.trim_end_matches('/').to_string(),
        commitment: commitment.to_string(),
        max_signatures,
        network,
    })
}

pub fn signatures_request(prepared: &PreparedVerification) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            prepared.reference,
            {
                "commitment": prepared.commitment,
                "limit": prepared.max_signatures
            }
        ]
    })
}

pub fn transaction_request(prepared: &PreparedVerification, signature: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "getTransaction",
        "params": [
            signature,
            {
                "commitment": prepared.commitment,
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0
            }
        ]
    })
}

pub fn parse_signatures(response: &Value, limit: usize) -> Result<Vec<String>, String> {
    reject_rpc_error(response)?;
    let entries = response
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| "getSignaturesForAddress returned no result array".to_string())?;
    Ok(entries
        .iter()
        .filter(|entry| entry.get("err").map(Value::is_null).unwrap_or(false))
        .filter(|entry| {
            matches!(
                entry.get("confirmationStatus").and_then(Value::as_str),
                Some("confirmed" | "finalized")
            )
        })
        .filter_map(|entry| entry.get("signature").and_then(Value::as_str))
        .take(limit)
        .map(str::to_string)
        .collect())
}

pub fn verify_transaction(
    response: &Value,
    signature: &str,
    prepared: &PreparedVerification,
) -> Result<Option<PaymentMatch>, String> {
    reject_rpc_error(response)?;
    let Some(result) = response.get("result").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let slot = result.get("slot").and_then(Value::as_u64).unwrap_or(0);
    let Some(meta) = result.get("meta") else {
        return Ok(None);
    };
    if !meta.get("err").map(Value::is_null).unwrap_or(false) {
        return Ok(None);
    }
    let Some(message) = result.pointer("/transaction/message") else {
        return Ok(None);
    };
    let account_keys = parse_account_keys(message.get("accountKeys"));
    if !account_keys.iter().any(|key| key == &prepared.reference)
        || !account_keys.iter().any(|key| key == &prepared.recipient)
    {
        return Ok(None);
    }
    if let Some(expected_memo) = prepared.memo.as_deref() {
        if !transaction_has_memo(message, expected_memo) {
            return Ok(None);
        }
    }

    let (received_units, decimals) = if let Some(mint) = prepared.spl_token.as_deref() {
        match token_balance_delta(meta, &prepared.recipient, mint) {
            Some(delta) => delta,
            None => return Ok(None),
        }
    } else {
        let Some(index) = account_keys
            .iter()
            .position(|key| key == &prepared.recipient)
        else {
            return Ok(None);
        };
        let Some(pre) = meta
            .get("preBalances")
            .and_then(Value::as_array)
            .and_then(|values| values.get(index))
            .and_then(Value::as_u64)
        else {
            return Ok(None);
        };
        let Some(post) = meta
            .get("postBalances")
            .and_then(Value::as_array)
            .and_then(|values| values.get(index))
            .and_then(Value::as_u64)
        else {
            return Ok(None);
        };
        (u128::from(post.saturating_sub(pre)), 9)
    };

    let expected_units = decimal_to_units(&prepared.amount, decimals)?;
    if received_units < expected_units {
        return Ok(None);
    }
    Ok(Some(PaymentMatch {
        signature: signature.to_string(),
        slot,
        received_amount: units_to_decimal(received_units, decimals),
    }))
}

pub fn output(
    prepared: &PreparedVerification,
    found: Option<PaymentMatch>,
    scanned: usize,
) -> VerifyOutput {
    let asset = prepared
        .spl_token
        .clone()
        .unwrap_or_else(|| "SOL".to_string());
    match found {
        Some(payment) => {
            let explorer_url = match prepared.network.as_str() {
                "mainnet-beta" => Some(format!(
                    "https://explorer.solana.com/tx/{}",
                    payment.signature
                )),
                "devnet" | "testnet" => Some(format!(
                    "https://explorer.solana.com/tx/{}?cluster={}",
                    payment.signature, prepared.network
                )),
                _ => None,
            };
            VerifyOutput {
                status: "paid",
                reference: prepared.reference.clone(),
                recipient: prepared.recipient.clone(),
                expected_amount: prepared.amount.clone(),
                asset,
                custody_tier: "T0-read-only",
                signatures_scanned: scanned,
                signature: Some(payment.signature),
                slot: Some(payment.slot),
                received_amount: Some(payment.received_amount),
                explorer_url,
                summary: "Invoice paid: reference, recipient, asset, amount, and optional memo verified on-chain"
                    .to_string(),
            }
        }
        None => VerifyOutput {
            status: "pending",
            reference: prepared.reference.clone(),
            recipient: prepared.recipient.clone(),
            expected_amount: prepared.amount.clone(),
            asset,
            custody_tier: "T0-read-only",
            signatures_scanned: scanned,
            signature: None,
            slot: None,
            received_amount: None,
            explorer_url: None,
            summary: "No confirmed transaction matched every invoice constraint".to_string(),
        },
    }
}

fn parse_account_keys(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter_map(|key| {
                    key.as_str()
                        .or_else(|| key.get("pubkey").and_then(Value::as_str))
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn transaction_has_memo(message: &Value, expected: &str) -> bool {
    message
        .get("instructions")
        .and_then(Value::as_array)
        .map(|instructions| {
            instructions.iter().any(|instruction| {
                let program = instruction.get("program").and_then(Value::as_str);
                let program_id = instruction.get("programId").and_then(Value::as_str);
                let is_memo = program == Some("spl-memo")
                    || matches!(
                        program_id,
                        Some("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
                            | Some("Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo")
                    );
                is_memo
                    && instruction
                        .get("parsed")
                        .and_then(Value::as_str)
                        .map(|memo| memo == expected)
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn token_balance_delta(meta: &Value, owner: &str, mint: &str) -> Option<(u128, u32)> {
    let post_entries = meta.get("postTokenBalances")?.as_array()?;
    let matching_post: Vec<&Value> = post_entries
        .iter()
        .filter(|entry| entry.get("owner").and_then(Value::as_str) == Some(owner))
        .filter(|entry| entry.get("mint").and_then(Value::as_str) == Some(mint))
        .collect();
    if matching_post.is_empty() {
        return None;
    }
    let decimals_u64 = matching_post
        .first()?
        .pointer("/uiTokenAmount/decimals")?
        .as_u64()?;
    if decimals_u64 > 18 {
        return None;
    }
    let decimals = decimals_u64 as u32;
    let post = sum_token_entries(&matching_post, decimals)?;
    let pre_entries: Vec<&Value> = meta
        .get("preTokenBalances")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| entry.get("owner").and_then(Value::as_str) == Some(owner))
                .filter(|entry| entry.get("mint").and_then(Value::as_str) == Some(mint))
                .collect()
        })
        .unwrap_or_default();
    let pre = sum_token_entries(&pre_entries, decimals).unwrap_or(0);
    Some((post.saturating_sub(pre), decimals))
}

fn sum_token_entries(entries: &[&Value], decimals: u32) -> Option<u128> {
    let mut sum = 0u128;
    for entry in entries {
        let entry_decimals = entry.pointer("/uiTokenAmount/decimals")?.as_u64()?;
        if entry_decimals != u64::from(decimals) {
            return None;
        }
        let amount = entry
            .pointer("/uiTokenAmount/amount")?
            .as_str()?
            .parse::<u128>()
            .ok()?;
        sum = sum.checked_add(amount)?;
    }
    Some(sum)
}

pub fn decimal_to_units(amount: &str, decimals: u32) -> Result<u128, String> {
    let amount = canonical_amount(amount)?;
    let (integer, fraction) = amount.split_once('.').unwrap_or((&amount, ""));
    if fraction.len() > decimals as usize {
        return Err(format!(
            "amount exceeds asset precision of {decimals} decimals"
        ));
    }
    let scale = 10u128
        .checked_pow(decimals)
        .ok_or_else(|| "asset precision is too large".to_string())?;
    let whole = integer
        .parse::<u128>()
        .map_err(|_| "amount is too large".to_string())?
        .checked_mul(scale)
        .ok_or_else(|| "amount is too large".to_string())?;
    let fractional = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u128>()
            .map_err(|_| "invalid fractional amount".to_string())?
            .checked_mul(10u128.pow(decimals - fraction.len() as u32))
            .ok_or_else(|| "amount is too large".to_string())?
    };
    whole
        .checked_add(fractional)
        .ok_or_else(|| "amount is too large".to_string())
}

pub fn units_to_decimal(units: u128, decimals: u32) -> String {
    if decimals == 0 {
        return units.to_string();
    }
    let scale = 10u128.pow(decimals);
    let integer = units / scale;
    let fraction = format!("{:0width$}", units % scale, width = decimals as usize);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        integer.to_string()
    } else {
        format!("{integer}.{fraction}")
    }
}

fn reject_rpc_error(response: &Value) -> Result<(), String> {
    if let Some(error) = response.get("error") {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown RPC error");
        return Err(format!("RPC error {code}: {}", truncate(message, 180)));
    }
    Ok(())
}

fn validate_rpc_url(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 || value.trim() != value {
        return Err("rpc_url must be a non-empty URL of at most 512 characters".to_string());
    }
    let secure = value.starts_with("https://");
    let local = value.starts_with("http://127.0.0.1") || value.starts_with("http://localhost");
    if !secure && !local {
        return Err("rpc_url must use HTTPS (HTTP is allowed only for localhost)".to_string());
    }
    if value.contains(['\n', '\r', '\0']) {
        return Err("rpc_url contains forbidden control characters".to_string());
    }
    Ok(())
}

fn validate_pubkey(field: &str, value: &str) -> Result<(), String> {
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| format!("{field} must be valid base58"))?;
    if decoded.len() != 32 {
        return Err(format!("{field} must decode to exactly 32 bytes"));
    }
    Ok(())
}

fn canonical_amount(value: &str) -> Result<String, String> {
    if value.is_empty() || value.trim() != value || value.starts_with(['+', '-']) {
        return Err("amount must be an unsigned plain decimal string".to_string());
    }
    let mut parts = value.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("amount must be an unsigned plain decimal string".to_string());
    }
    let fraction = match fraction {
        Some("") => return Err("amount must not end with a decimal point".to_string()),
        Some(value) if !value.bytes().all(|byte| byte.is_ascii_digit()) => {
            return Err("amount must be an unsigned plain decimal string".to_string());
        }
        value => value.unwrap_or_default(),
    };
    if integer.len() > 20 || fraction.len() > 18 {
        return Err("amount supports at most 20 integer and 18 fractional digits".to_string());
    }
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer };
    let fraction = fraction.trim_end_matches('0');
    if integer == "0" && fraction.is_empty() {
        return Err("amount must be greater than zero".to_string());
    }
    Ok(if fraction.is_empty() {
        integer.to_string()
    } else {
        format!("{integer}.{fraction}")
    })
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}
