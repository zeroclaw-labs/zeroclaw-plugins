//! Pure Solana payment verification logic.
//!
//! No WIT or HTTP dependency is used here. Tests feed captured-shaped RPC JSON
//! into the same parser used by the WebAssembly component.

use std::{
    collections::{BTreeMap, HashMap},
    net::{Ipv4Addr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const MAX_TIMEOUT_SECS: u64 = 30;
const MAX_SAFE_TOKEN_DECIMALS: u8 = 19;
const MEMO_PROGRAM_IDS: [&str; 2] = [
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteArgs {
    pub signature: String,
    pub recipient: String,
    pub amount: String,
    pub asset: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default)]
    pub amount_policy: AmountPolicy,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

impl ExecuteArgs {
    pub fn into_expectation(self) -> Result<PaymentExpectation, String> {
        PaymentExpectation::new(
            self.signature,
            self.recipient,
            self.amount,
            self.asset,
            self.reference,
            self.memo,
            self.amount_policy,
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AmountPolicy {
    #[default]
    Exact,
    AtLeast,
}

#[derive(Debug)]
pub struct PaymentExpectation {
    pub signature: String,
    pub recipient: String,
    pub amount: String,
    pub asset: Asset,
    pub reference: Option<String>,
    pub memo: Option<String>,
    pub amount_policy: AmountPolicy,
}

impl PaymentExpectation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signature: String,
        recipient: String,
        amount: String,
        asset: String,
        reference: Option<String>,
        memo: Option<String>,
        amount_policy: AmountPolicy,
    ) -> Result<Self, String> {
        validate_base58_len(&signature, 64, "signature")?;
        validate_base58_len(&recipient, 32, "recipient")?;
        validate_decimal(&amount)?;

        let asset = if asset.eq_ignore_ascii_case("SOL") {
            Asset::Sol
        } else {
            validate_base58_len(&asset, 32, "asset mint")?;
            Asset::Spl { mint: asset }
        };

        let reference = normalize_optional(reference, "reference", 128)?;
        if let Some(value) = &reference {
            validate_base58_len(value, 32, "reference")?;
        }
        let memo = normalize_optional(memo, "memo", 256)?;

        Ok(Self {
            signature,
            recipient,
            amount,
            asset,
            reference,
            memo,
            amount_policy,
        })
    }
}

#[derive(Debug)]
pub enum Asset {
    Sol,
    Spl { mint: String },
}

impl Asset {
    fn label(&self) -> &str {
        match self {
            Self::Sol => "SOL",
            Self::Spl { mint } => mint,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcConfig {
    pub rpc_url: String,
    pub commitment: String,
    pub timeout_secs: u64,
}

impl RpcConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let rpc_url = section
            .get("rpc_url")
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        validate_rpc_url(&rpc_url)?;

        let commitment = section
            .get("commitment")
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "finalized".to_string());
        if commitment != "finalized" && commitment != "confirmed" {
            return Err("commitment must be finalized or confirmed".to_string());
        }

        let timeout_secs = section
            .get("timeout_secs")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| "timeout_secs must be an integer")
            })
            .transpose()?
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        if timeout_secs == 0 || timeout_secs > MAX_TIMEOUT_SECS {
            return Err(format!(
                "timeout_secs must be between 1 and {MAX_TIMEOUT_SECS}"
            ));
        }

        Ok(Self {
            rpc_url,
            commitment,
            timeout_secs,
        })
    }
}

fn validate_rpc_url(value: &str) -> Result<(), String> {
    if value.len() > 512 {
        return Err("rpc_url must be at most 512 characters".to_string());
    }
    let parsed = Url::parse(value).map_err(|_| "rpc_url must be a valid URL".to_string())?;
    if parsed.scheme() != "https" {
        return Err("rpc_url must use https".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("rpc_url must not contain credentials".to_string());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("rpc_url must not contain a query or fragment".to_string());
    }
    match parsed
        .host()
        .ok_or_else(|| "rpc_url must include a public host".to_string())?
    {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            let special_suffixes = [
                "localhost",
                "local",
                "internal",
                "home.arpa",
                "test",
                "example",
                "invalid",
            ];
            if !domain.contains('.')
                || special_suffixes
                    .iter()
                    .any(|suffix| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
            {
                return Err("rpc_url host must be a public DNS name".to_string());
            }
        }
        Host::Ipv4(address) if !is_public_ipv4(address) => {
            return Err("rpc_url must not use a private or special-purpose IP".to_string());
        }
        Host::Ipv6(address) if !is_public_ipv6(address) => {
            return Err("rpc_url must not use a private or special-purpose IP".to_string());
        }
        Host::Ipv4(_) | Host::Ipv6(_) => {}
    }
    Ok(())
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || (a == 255 && b == 255 && c == 255 && d == 255))
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = address.segments();
    let is_global_unicast = (segments[0] & 0xe000) == 0x2000;
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let is_special_2001 = segments[0] == 0x2001 && segments[1] < 0x0200;
    let is_six_to_four = segments[0] == 0x2002;
    is_global_unicast && !is_documentation && !is_special_2001 && !is_six_to_four
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Paid,
    NotFound,
    Failed,
    Mismatch,
    InvalidResponse,
}

impl VerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Paid => "paid",
            Self::NotFound => "not_found",
            Self::Failed => "failed",
            Self::Mismatch => "mismatch",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub valid: bool,
    pub status: VerificationStatus,
    pub signature: String,
    pub slot: Option<u64>,
    pub recipient: String,
    pub asset: String,
    pub expected_amount: String,
    pub observed_amount: Option<String>,
    pub amount_policy: AmountPolicy,
    pub reference_matched: Option<bool>,
    pub memo_matched: Option<bool>,
    pub checks: Vec<String>,
    pub summary: String,
}

pub fn parse_execute_args(json: &str) -> Result<ExecuteArgs, String> {
    serde_json::from_str(json).map_err(|error| error.to_string())
}

pub fn verify_rpc_response(expected: &PaymentExpectation, response: &Value) -> VerificationReport {
    let Some(result) = response.get("result") else {
        return base_report(
            expected,
            VerificationStatus::InvalidResponse,
            None,
            None,
            vec!["rpc_result_missing".to_string()],
        );
    };
    if result.is_null() {
        return base_report(
            expected,
            VerificationStatus::NotFound,
            None,
            None,
            vec!["transaction_not_found_at_required_commitment".to_string()],
        );
    }

    let slot = result.get("slot").and_then(Value::as_u64);
    let Some(meta) = result.get("meta") else {
        return base_report(
            expected,
            VerificationStatus::InvalidResponse,
            slot,
            None,
            vec!["transaction_meta_missing".to_string()],
        );
    };
    if meta.get("err").is_none() {
        return base_report(
            expected,
            VerificationStatus::InvalidResponse,
            slot,
            None,
            vec!["transaction_error_field_missing".to_string()],
        );
    }
    if !meta.get("err").is_some_and(Value::is_null) {
        return base_report(
            expected,
            VerificationStatus::Failed,
            slot,
            None,
            vec!["transaction_execution_failed".to_string()],
        );
    }

    let Some(message) = result.pointer("/transaction/message") else {
        return base_report(
            expected,
            VerificationStatus::InvalidResponse,
            slot,
            None,
            vec!["transaction_message_missing".to_string()],
        );
    };
    let account_keys = account_keys(message);
    if account_keys.is_empty() {
        return base_report(
            expected,
            VerificationStatus::InvalidResponse,
            slot,
            None,
            vec!["account_keys_missing".to_string()],
        );
    }

    let observed = match &expected.asset {
        Asset::Sol => sol_received(expected, meta, &account_keys),
        Asset::Spl { mint } => spl_received(expected, meta, mint),
    };
    let (observed_raw, decimals) = match observed {
        Ok(value) => value,
        Err(reason) => {
            let status = observation_error_status(&reason);
            return base_report(expected, status, slot, None, vec![reason]);
        }
    };
    let expected_raw = match decimal_to_raw(&expected.amount, decimals) {
        Ok(value) => value,
        Err(reason) => {
            return base_report(
                expected,
                VerificationStatus::Mismatch,
                slot,
                Some(raw_to_decimal(observed_raw, decimals)),
                vec![format!("amount_precision_invalid:{reason}")],
            );
        }
    };

    let mut checks = vec![
        "transaction_succeeded".to_string(),
        "recipient_matched".to_string(),
    ];
    let amount_matches = match expected.amount_policy {
        AmountPolicy::Exact => observed_raw == expected_raw,
        AmountPolicy::AtLeast => observed_raw >= expected_raw,
    };
    if amount_matches {
        checks.push("amount_matched".to_string());
    } else if observed_raw < expected_raw {
        checks.push("amount_underpaid".to_string());
    } else {
        checks.push("amount_overpaid_exact_policy".to_string());
    }

    let reference_matched = expected.reference.as_ref().map(|reference| {
        let matched = account_keys.iter().any(|key| key == reference);
        checks.push(if matched {
            "reference_matched".to_string()
        } else {
            "reference_missing".to_string()
        });
        matched
    });

    let memos = extract_memos(message, meta);
    let memo_matched = expected.memo.as_ref().map(|memo| {
        let matched = memos.iter().any(|candidate| candidate == memo);
        checks.push(if matched {
            "memo_matched".to_string()
        } else {
            "memo_missing".to_string()
        });
        matched
    });

    let valid = amount_matches && reference_matched.unwrap_or(true) && memo_matched.unwrap_or(true);
    VerificationReport {
        valid,
        status: if valid {
            VerificationStatus::Paid
        } else {
            VerificationStatus::Mismatch
        },
        signature: expected.signature.clone(),
        slot,
        recipient: expected.recipient.clone(),
        asset: expected.asset.label().to_string(),
        expected_amount: expected.amount.clone(),
        observed_amount: Some(raw_to_decimal(observed_raw, decimals)),
        amount_policy: expected.amount_policy,
        reference_matched,
        memo_matched,
        summary: if valid {
            format!(
                "Verified {} {} received by {}.",
                raw_to_decimal(observed_raw, decimals),
                expected.asset.label(),
                shorten(&expected.recipient)
            )
        } else {
            "Transaction exists but does not satisfy the invoice policy.".to_string()
        },
        checks,
    }
}

fn observation_error_status(reason: &str) -> VerificationStatus {
    if reason.ends_with("_missing")
        && reason != "recipient_account_missing"
        && reason != "recipient_token_account_missing"
        || reason.ends_with("_invalid")
        || reason.ends_with("_overflow")
        || reason.contains("decimals")
    {
        VerificationStatus::InvalidResponse
    } else {
        VerificationStatus::Mismatch
    }
}

fn base_report(
    expected: &PaymentExpectation,
    status: VerificationStatus,
    slot: Option<u64>,
    observed_amount: Option<String>,
    checks: Vec<String>,
) -> VerificationReport {
    let summary = match status {
        VerificationStatus::NotFound => "Transaction not found at the configured commitment.",
        VerificationStatus::Failed => "Transaction executed with an on-chain error.",
        VerificationStatus::Mismatch => "Transaction does not satisfy the invoice policy.",
        VerificationStatus::InvalidResponse => "RPC response was missing required fields.",
        VerificationStatus::Paid => "Payment verified.",
    }
    .to_string();

    VerificationReport {
        valid: false,
        status,
        signature: expected.signature.clone(),
        slot,
        recipient: expected.recipient.clone(),
        asset: expected.asset.label().to_string(),
        expected_amount: expected.amount.clone(),
        observed_amount,
        amount_policy: expected.amount_policy,
        reference_matched: expected.reference.as_ref().map(|_| false),
        memo_matched: expected.memo.as_ref().map(|_| false),
        checks,
        summary,
    }
}

fn sol_received(
    expected: &PaymentExpectation,
    meta: &Value,
    account_keys: &[String],
) -> Result<(u64, u8), String> {
    let index = account_keys
        .iter()
        .position(|key| key == &expected.recipient)
        .ok_or_else(|| "recipient_account_missing".to_string())?;
    if index == 0 {
        return Err("recipient_is_fee_payer".to_string());
    }
    let pre = balance_at(meta.get("preBalances"), index)
        .ok_or_else(|| "pre_balance_missing".to_string())?;
    let post = balance_at(meta.get("postBalances"), index)
        .ok_or_else(|| "post_balance_missing".to_string())?;
    let delta = post
        .checked_sub(pre)
        .ok_or_else(|| "recipient_balance_did_not_increase".to_string())?;
    if delta == 0 {
        return Err("recipient_balance_did_not_increase".to_string());
    }
    Ok((delta, 9))
}

fn balance_at(value: Option<&Value>, index: usize) -> Option<u64> {
    value?.as_array()?.get(index)?.as_u64()
}

fn spl_received(
    expected: &PaymentExpectation,
    meta: &Value,
    mint: &str,
) -> Result<(u64, u8), String> {
    let pre = token_balances(meta.get("preTokenBalances"), &expected.recipient, mint)?;
    let post = token_balances(meta.get("postTokenBalances"), &expected.recipient, mint)?;
    let decimals = match (pre.decimals, post.decimals) {
        (Some(left), Some(right)) if left != right => {
            return Err("token_decimals_changed".to_string());
        }
        (Some(value), _) | (_, Some(value)) => value,
        (None, None) => return Err("recipient_token_account_missing".to_string()),
    };
    let delta = post
        .raw
        .checked_sub(pre.raw)
        .ok_or_else(|| "recipient_token_balance_did_not_increase".to_string())?;
    if delta == 0 {
        return Err("recipient_token_balance_did_not_increase".to_string());
    }
    Ok((delta, decimals))
}

#[derive(Default)]
struct TokenTotal {
    raw: u64,
    decimals: Option<u8>,
}

fn token_balances(
    value: Option<&Value>,
    recipient: &str,
    mint: &str,
) -> Result<TokenTotal, String> {
    let Some(entries) = value.and_then(Value::as_array) else {
        return Ok(TokenTotal::default());
    };
    let mut by_index = BTreeMap::<u64, (u64, u8)>::new();
    for entry in entries {
        if entry.get("owner").and_then(Value::as_str) != Some(recipient)
            || entry.get("mint").and_then(Value::as_str) != Some(mint)
        {
            continue;
        }
        let index = entry
            .get("accountIndex")
            .and_then(Value::as_u64)
            .ok_or_else(|| "token_account_index_missing".to_string())?;
        let amount = entry
            .pointer("/uiTokenAmount/amount")
            .and_then(Value::as_str)
            .ok_or_else(|| "token_raw_amount_missing".to_string())?
            .parse::<u64>()
            .map_err(|_| "token_raw_amount_invalid".to_string())?;
        let decimals = entry
            .pointer("/uiTokenAmount/decimals")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| "token_decimals_missing".to_string())?;
        if decimals > MAX_SAFE_TOKEN_DECIMALS {
            return Err("token_decimals_out_of_range".to_string());
        }
        by_index.insert(index, (amount, decimals));
    }

    let mut total = TokenTotal::default();
    for (_, (amount, decimals)) in by_index {
        if total.decimals.is_some_and(|known| known != decimals) {
            return Err("inconsistent_token_decimals".to_string());
        }
        total.decimals = Some(decimals);
        total.raw = total
            .raw
            .checked_add(amount)
            .ok_or_else(|| "token_balance_overflow".to_string())?;
    }
    Ok(total)
}

fn account_keys(message: &Value) -> Vec<String> {
    message
        .get("accountKeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .as_str()
                .or_else(|| entry.get("pubkey").and_then(Value::as_str))
                .map(str::to_string)
        })
        .collect()
}

fn extract_memos(message: &Value, meta: &Value) -> Vec<String> {
    let mut memos = Vec::new();
    if let Some(instructions) = message.get("instructions").and_then(Value::as_array) {
        collect_memos(instructions, &mut memos);
    }
    if let Some(groups) = meta.get("innerInstructions").and_then(Value::as_array) {
        for group in groups {
            if let Some(instructions) = group.get("instructions").and_then(Value::as_array) {
                collect_memos(instructions, &mut memos);
            }
        }
    }
    memos
}

fn collect_memos(instructions: &[Value], output: &mut Vec<String>) {
    for instruction in instructions {
        let is_memo = instruction.get("program").and_then(Value::as_str) == Some("spl-memo")
            || instruction
                .get("programId")
                .and_then(Value::as_str)
                .is_some_and(|id| MEMO_PROGRAM_IDS.contains(&id));
        if !is_memo {
            continue;
        }
        if let Some(parsed) = instruction.get("parsed").and_then(Value::as_str) {
            output.push(parsed.to_string());
            continue;
        }
        if let Some(data) = instruction.get("data").and_then(Value::as_str) {
            if let Ok(bytes) = bs58::decode(data).into_vec() {
                if let Ok(text) = String::from_utf8(bytes) {
                    output.push(text);
                }
            }
        }
    }
}

fn validate_base58_len(value: &str, expected_len: usize, field: &str) -> Result<(), String> {
    if value.len() > 128 {
        return Err(format!("{field} is too long"));
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| format!("{field} must be valid base58"))?;
    if decoded.len() != expected_len {
        return Err(format!("{field} must decode to {expected_len} bytes"));
    }
    Ok(())
}

fn normalize_optional(
    value: Option<String>,
    field: &str,
    max_len: usize,
) -> Result<Option<String>, String> {
    match value {
        Some(value) if value.is_empty() => Ok(None),
        Some(value) if value.len() > max_len => Err(format!("{field} is too long")),
        other => Ok(other),
    }
}

fn validate_decimal(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 40 {
        return Err("amount must contain between 1 and 40 characters".to_string());
    }
    let mut dots = 0;
    for character in value.chars() {
        match character {
            '0'..='9' => {}
            '.' if dots == 0 => dots += 1,
            _ => return Err("amount must be an unsigned decimal string".to_string()),
        }
    }
    if value.starts_with('.') || value.ends_with('.') {
        return Err("amount must have digits on both sides of a decimal point".to_string());
    }
    if value
        .chars()
        .all(|character| character == '0' || character == '.')
    {
        return Err("amount must be greater than zero".to_string());
    }
    Ok(())
}

fn decimal_to_raw(value: &str, decimals: u8) -> Result<u64, String> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > usize::from(decimals) {
        return Err(format!("asset supports at most {decimals} decimal places"));
    }
    let scale = 10_u64
        .checked_pow(u32::from(decimals))
        .ok_or_else(|| "decimal scale overflow".to_string())?;
    let whole_raw = whole
        .parse::<u64>()
        .map_err(|_| "amount is too large".to_string())?
        .checked_mul(scale)
        .ok_or_else(|| "amount is too large".to_string())?;
    let mut fraction_padded = fraction.to_string();
    fraction_padded.extend(std::iter::repeat_n(
        '0',
        usize::from(decimals) - fraction.len(),
    ));
    let fraction_raw = if fraction_padded.is_empty() {
        0
    } else {
        fraction_padded
            .parse::<u64>()
            .map_err(|_| "fraction is too large".to_string())?
    };
    whole_raw
        .checked_add(fraction_raw)
        .ok_or_else(|| "amount is too large".to_string())
}

fn raw_to_decimal(raw: u64, decimals: u8) -> String {
    if decimals == 0 {
        return raw.to_string();
    }
    let scale = 10_u64.pow(u32::from(decimals));
    let whole = raw / scale;
    let fraction = raw % scale;
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:0width$}", width = usize::from(decimals));
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

fn shorten(value: &str) -> String {
    if value.len() <= 12 {
        return value.to_string();
    }
    format!("{}...{}", &value[..6], &value[value.len() - 4..])
}
