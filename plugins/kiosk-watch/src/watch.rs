//! Pure verification core. No wasm dependency — compiles and tests on the host
//! with RPC mocked through [`kiosk_core::rpc::RpcTransport`].
//!
//! Custody: T0. This module holds no key and signs nothing. It performs
//! read-only Solana JSON-RPC calls to answer one question the actuation SOP
//! gates on: *did the expected payment land on-chain?* — and a companion
//! question: *is the device's attestation heartbeat fresh?*
//!
//! The single load-bearing invariant: **an RPC or decode failure is NEVER
//! reported as Paid.** Every network/shape error returns `Err`, so the shim
//! maps it to `success:false` and the relay stays shut. The only path to a
//! `Paid` verdict is a fully parsed transaction that credits the exact
//! `expected_amount` of the operator's `usdc_mint` to the operator's
//! `merchant_address` and references this charge.

use std::collections::HashMap;

use kiosk_core::b58;
use kiosk_core::rpc::{RpcClient, RpcError, RpcTransport};
use kiosk_core::shape;
use serde_json::{json, Value};

/// Mainnet USDC mint — the shipped default. Operators override in config
/// (e.g. devnet USDC); never the model.
pub const DEFAULT_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const USDC_DECIMALS: u8 = 6;
/// How many recent signatures to pull on the reference / device address.
const SIG_LIMIT: u64 = 10;

/// Operator configuration, injected by the host as `__config`. Fail closed:
/// without an RPC endpoint and a valid merchant address the plugin refuses.
#[derive(Debug)]
pub struct WatchConfig {
    pub rpc_url: String,
    pub merchant_address: String,
    pub usdc_mint: String,
    /// Solana commitment gating the answer: processed | confirmed | finalized.
    pub finality: String,
}

impl WatchConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, WatchError> {
        let rpc_url = section
            .get("rpc_url")
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or_else(|| WatchError::Config("rpc_url is required".into()))?;
        let merchant_address = section
            .get("merchant_address")
            .cloned()
            .ok_or_else(|| WatchError::Config("merchant_address is required".into()))?;
        if b58::decode_pubkey(&merchant_address).is_none() {
            return Err(WatchError::Config(
                "merchant_address is not a valid 32-byte base58 pubkey".into(),
            ));
        }
        let usdc_mint = section
            .get("usdc_mint")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_USDC_MINT.to_string());
        if b58::decode_pubkey(&usdc_mint).is_none() {
            return Err(WatchError::Config("usdc_mint is not a valid pubkey".into()));
        }
        let finality = section
            .get("finality")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "confirmed".to_string());
        if !matches!(finality.as_str(), "processed" | "confirmed" | "finalized") {
            return Err(WatchError::Config(
                "finality must be processed, confirmed, or finalized".into(),
            ));
        }
        Ok(Self {
            rpc_url,
            merchant_address,
            usdc_mint,
            finality,
        })
    }
}

/// Model-facing arguments. `deny_unknown_fields` makes smuggled keys
/// (`rpc_url`, `merchant_address`, …) a hard deserialization error. Every
/// field is optional at the serde layer; presence is enforced per mode in the
/// core, so one struct serves both payment and heartbeat calls.
#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct WatchArgs {
    /// `"heartbeat"` selects heartbeat mode; absent/`"payment"` = payment mode.
    pub mode: Option<String>,
    /// Payment mode: the Solana Pay reference pubkey from the charge.
    pub reference: Option<String>,
    /// Payment mode: expected amount as a decimal USDC string (e.g. "1.5").
    pub expected_amount: Option<String>,
    /// Payment mode: acceptance window in seconds; a matching signature older
    /// than this before `now` is treated as Expired, not Paid.
    pub window_s: Option<u64>,
    /// Heartbeat mode: the device/attestation address to scan.
    pub device_address: Option<String>,
    /// Heartbeat mode: max seconds since the newest tx before it is Stale.
    pub max_silence_s: Option<u64>,
}

/// Payment verification outcome. Only `Paid` may gate actuation.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Paid {
        payer: String,
        signature: String,
        slot: u64,
    },
    /// No matching signature yet — the SOP should keep polling.
    Pending,
    /// A matching signature exists but landed outside the acceptance window.
    Expired,
    /// A transaction was found but does not match the expected payment.
    Mismatch { reason: String },
}

/// Heartbeat outcome for the device's attestation address.
#[derive(Debug, PartialEq)]
pub enum Heartbeat {
    Live { signature: String, age_s: u64 },
    Stale { signature: String, age_s: u64 },
    Missing,
}

/// Failure taxonomy. `Rpc` and `Decode` exist so a network or shape failure is
/// structurally distinct from a verdict — and can NEVER be a `Paid`.
#[derive(Debug, PartialEq)]
pub enum WatchError {
    Config(String),
    Args(String),
    Rpc(String),
    Decode(String),
}

impl core::fmt::Display for WatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WatchError::Config(m) => write!(f, "config error: {m}"),
            WatchError::Args(m) => write!(f, "invalid request: {m}"),
            WatchError::Rpc(m) => write!(f, "rpc error: {m}"),
            WatchError::Decode(m) => write!(f, "malformed rpc response: {m}"),
        }
    }
}

impl From<RpcError> for WatchError {
    fn from(e: RpcError) -> Self {
        match e {
            RpcError::Transport(m) => WatchError::Rpc(m),
            RpcError::Rpc { code, message } => WatchError::Rpc(format!("{code}: {message}")),
            RpcError::Decode(m) => WatchError::Decode(m),
        }
    }
}

impl Verdict {
    /// Human/LLM-facing summary, token-budgeted (trap #3).
    pub fn summary(&self) -> String {
        let s = match self {
            Verdict::Paid { payer, signature, slot } => format!(
                "PAID. Payment verified on-chain at slot {slot}, signature {signature}, payer {payer}. Safe to deliver."
            ),
            Verdict::Pending => {
                "PENDING. No matching payment on-chain yet. Do not deliver; check again shortly.".into()
            }
            Verdict::Expired => {
                "EXPIRED. A matching signature exists but is older than the acceptance window; not delivering.".into()
            }
            Verdict::Mismatch { reason } => {
                format!("MISMATCH. A transaction was found but does not match the charge: {reason}. Do not deliver.")
            }
        };
        shape::clamp(&s, shape::DEFAULT_BUDGET_TOKENS)
    }

    /// True only for a verified payment — the single condition the relay gates on.
    pub fn is_paid(&self) -> bool {
        matches!(self, Verdict::Paid { .. })
    }
}

impl Heartbeat {
    pub fn summary(&self) -> String {
        let s = match self {
            Heartbeat::Live { age_s, signature } => {
                format!("LIVE. Newest device attestation is {age_s}s old (signature {signature}).")
            }
            Heartbeat::Stale { age_s, signature } => format!(
                "STALE. Newest device attestation is {age_s}s old, past the silence threshold (signature {signature}). Alert the operator."
            ),
            Heartbeat::Missing => {
                "MISSING. No attestations found for the device address. Alert the operator.".into()
            }
        };
        shape::clamp(&s, shape::DEFAULT_BUDGET_TOKENS)
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Heartbeat::Live { .. })
    }
}

/// Verify the expected payment on-chain. Returns `Err` (never `Paid`) on any
/// RPC or decode failure. `now` is unix seconds, supplied by the shim/test so
/// the core stays deterministic.
pub fn verify_payment<T: RpcTransport>(
    args: &WatchArgs,
    cfg: &WatchConfig,
    transport: T,
    now: u64,
) -> Result<Verdict, WatchError> {
    let reference = args
        .reference
        .as_deref()
        .filter(|r| b58::decode_pubkey(r).is_some())
        .ok_or_else(|| WatchError::Args("reference must be a valid pubkey".into()))?;
    let expected_amount = args
        .expected_amount
        .as_deref()
        .ok_or_else(|| WatchError::Args("expected_amount is required".into()))?;
    let expected_units = decimal_to_base_units(expected_amount, USDC_DECIMALS)
        .ok_or_else(|| WatchError::Args("expected_amount is not a valid USDC decimal".into()))?;

    let client = RpcClient::new(transport);

    // 1. Any signatures referencing this charge?
    let sigs = client.call(
        "getSignaturesForAddress",
        json!([reference, { "commitment": cfg.finality, "limit": SIG_LIMIT }]),
    )?;
    let sig_list = sigs.as_array().ok_or_else(|| {
        WatchError::Decode("getSignaturesForAddress did not return an array".into())
    })?;
    let newest = match sig_list.first() {
        Some(s) => s,
        None => return Ok(Verdict::Pending),
    };
    let signature = newest
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| WatchError::Decode("signature entry missing `signature`".into()))?
        .to_string();

    // 2. Acceptance window: a matching signature too old to trust => Expired.
    if let (Some(window), Some(bt)) = (
        args.window_s,
        newest.get("blockTime").and_then(Value::as_i64),
    ) {
        if bt >= 0 && now > (bt as u64).saturating_add(window) {
            return Ok(Verdict::Expired);
        }
    }

    // 3. Fetch and inspect the transaction. Malformed => Err (never Paid).
    let txv = client.call(
        "getTransaction",
        json!([signature, {
            "commitment": cfg.finality,
            "encoding": "jsonParsed",
            "maxSupportedTransactionVersion": 0
        }]),
    )?;

    inspect_transaction(&txv, reference, &signature, cfg, expected_units)
}

/// Turn a getTransaction result into a [`Verdict`]. Missing structural fields
/// are decode errors (fail closed); business mismatches are `Mismatch`.
fn inspect_transaction(
    txv: &Value,
    reference: &str,
    signature: &str,
    cfg: &WatchConfig,
    expected_units: u128,
) -> Result<Verdict, WatchError> {
    let meta = txv
        .get("meta")
        .ok_or_else(|| WatchError::Decode("transaction has no meta".into()))?;

    // On-chain failure: funds did not move.
    if !meta.get("err").map(Value::is_null).unwrap_or(false) {
        return Ok(Verdict::Mismatch {
            reason: "on-chain transaction failed".into(),
        });
    }

    let account_keys = txv
        .get("transaction")
        .and_then(|t| t.get("message"))
        .and_then(|m| m.get("accountKeys"))
        .and_then(Value::as_array)
        .ok_or_else(|| WatchError::Decode("transaction has no accountKeys".into()))?;
    let keys: Vec<&str> = account_keys.iter().filter_map(account_key_pubkey).collect();

    // The tx must reference this charge (defense in depth beyond the lookup):
    // getSignaturesForAddress(reference) should only ever return txs touching
    // the reference, but we re-verify rather than trust the node's index.
    if !keys.contains(&reference) {
        return Ok(Verdict::Mismatch {
            reason: "transaction does not reference this charge".into(),
        });
    }

    let slot = txv.get("slot").and_then(Value::as_u64).unwrap_or_default();
    let payer = keys.first().map(|s| s.to_string()).unwrap_or_default();

    // Credit to the operator's merchant in the operator's mint.
    let pre = token_balances(meta, "preTokenBalances");
    let post = token_balances(meta, "postTokenBalances");

    let credited = post
        .iter()
        .find(|b| b.owner == cfg.merchant_address && b.mint == cfg.usdc_mint);
    let credited = match credited {
        Some(b) => b,
        None => {
            let reason = if post.iter().any(|b| b.mint == cfg.usdc_mint) {
                "payment credited a different recipient"
            } else if post.iter().any(|b| b.owner == cfg.merchant_address) {
                "payment used a different mint"
            } else {
                "no USDC credit to the merchant was found"
            };
            return Ok(Verdict::Mismatch {
                reason: reason.into(),
            });
        }
    };
    let before = pre
        .iter()
        .find(|b| b.account_index == credited.account_index)
        .map(|b| b.amount)
        .unwrap_or(0);
    let delta = credited.amount.saturating_sub(before);
    if delta != expected_units {
        return Ok(Verdict::Mismatch {
            reason: format!(
                "amount mismatch: credited {delta} base units, expected {expected_units}"
            ),
        });
    }

    Ok(Verdict::Paid {
        payer,
        signature: signature.to_string(),
        slot,
    })
}

/// Verify the device attestation heartbeat: scan the newest signature on the
/// device address and classify by age. RPC failure => `Err` (never `Live`).
pub fn verify_heartbeat<T: RpcTransport>(
    args: &WatchArgs,
    cfg: &WatchConfig,
    transport: T,
    now: u64,
) -> Result<Heartbeat, WatchError> {
    let device = args
        .device_address
        .as_deref()
        .filter(|d| b58::decode_pubkey(d).is_some())
        .ok_or_else(|| WatchError::Args("device_address must be a valid pubkey".into()))?;
    let max_silence = args
        .max_silence_s
        .ok_or_else(|| WatchError::Args("max_silence_s is required".into()))?;

    let client = RpcClient::new(transport);
    let sigs = client.call(
        "getSignaturesForAddress",
        json!([device, { "commitment": cfg.finality, "limit": 1 }]),
    )?;
    let sig_list = sigs.as_array().ok_or_else(|| {
        WatchError::Decode("getSignaturesForAddress did not return an array".into())
    })?;
    let newest = match sig_list.first() {
        Some(s) => s,
        None => return Ok(Heartbeat::Missing),
    };
    let signature = newest
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| WatchError::Decode("signature entry missing `signature`".into()))?
        .to_string();
    let bt = newest
        .get("blockTime")
        .and_then(Value::as_i64)
        .filter(|t| *t >= 0)
        .ok_or_else(|| WatchError::Decode("signature entry missing blockTime".into()))?
        as u64;
    let age_s = now.saturating_sub(bt);
    if age_s > max_silence {
        Ok(Heartbeat::Stale { signature, age_s })
    } else {
        Ok(Heartbeat::Live { signature, age_s })
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

struct TokenBalance {
    account_index: u64,
    owner: String,
    mint: String,
    amount: u128,
}

fn token_balances(meta: &Value, key: &str) -> Vec<TokenBalance> {
    meta.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|b| {
                    Some(TokenBalance {
                        account_index: b.get("accountIndex").and_then(Value::as_u64)?,
                        owner: b.get("owner").and_then(Value::as_str)?.to_string(),
                        mint: b.get("mint").and_then(Value::as_str)?.to_string(),
                        amount: b
                            .get("uiTokenAmount")
                            .and_then(|u| u.get("amount"))
                            .and_then(Value::as_str)
                            .and_then(|s| s.parse::<u128>().ok())?,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// accountKeys entries are `"pubkey"` (base58) or `{ "pubkey": "..." }`
/// depending on encoding; accept both.
fn account_key_pubkey(v: &Value) -> Option<&str> {
    v.as_str()
        .or_else(|| v.get("pubkey").and_then(Value::as_str))
}

/// Parse a decimal string to integer base units (e.g. "1.5", 6 -> 1_500_000).
/// Digits only, at most `decimals` fraction places; rejects signs / exponents.
fn decimal_to_base_units(s: &str, decimals: u8) -> Option<u128> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut parts = s.splitn(2, '.');
    let int = parts.next().unwrap_or("");
    let frac = parts.next().unwrap_or("");
    if int.is_empty() && frac.is_empty() {
        return None;
    }
    if !int.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if frac.len() > decimals as usize {
        return None;
    }
    let mut combined = String::new();
    combined.push_str(if int.is_empty() { "0" } else { int });
    let mut f = frac.to_string();
    while f.len() < decimals as usize {
        f.push('0');
    }
    combined.push_str(&f);
    combined.parse::<u128>().ok()
}
