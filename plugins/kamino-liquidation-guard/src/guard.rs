//! Pure Kamino liquidation-risk core.
//!
//! This module has no WIT, WASI, or HTTP dependency. The component shim owns
//! transport; this core validates the API evidence and classifies it.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CRITICAL_HEALTH_BPS: u32 = 11_500;
pub const DEFAULT_WATCH_HEALTH_BPS: u32 = 12_500;
pub const DEFAULT_MAX_DATA_AGE_SECONDS: u64 = 300;
pub const DEFAULT_SOLANA_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const SOLANA_MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
pub const MAX_OBLIGATIONS: usize = 6;
// Pinned KLend mainnet identity and Obligation layout:
// https://github.com/Kamino-Finance/klend/blob/c06001927d68895be487482bdd82dcf6e88e6348/libs/klend-interface/src/state/obligation.rs
pub const KLEND_PROGRAM_ID: &str = "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD";
pub const OBLIGATION_ACCOUNT_SIZE: u64 = 3_344;
pub const OBLIGATION_DATA_SLICE_BYTES: usize = 96;
pub const OBLIGATION_DISCRIMINATOR_B58: &str = "VEdzkJnDweW";

const DECIMAL_DIGITS: usize = 18;
const DECIMAL_SCALE: u128 = 1_000_000_000_000_000_000;
const MAX_CURRENT_LTV_SCALED: u128 = 100 * DECIMAL_SCALE;
const MAX_CLOCK_SKEW_MS: u64 = 30_000;
const OBLIGATION_DISCRIMINATOR: [u8; 8] = [0xa8, 0xce, 0x8d, 0x6a, 0x58, 0x4c, 0xac, 0xa7];
// 0=Vanilla, 1=Multiply, 2=Lending, 3=Leverage:
// https://github.com/Kamino-Finance/klend-sdk/blob/573d0bf52421cf22e930a5a4d73d1722a36ad6d9/src/utils/ObligationType.ts
const MAX_SUPPORTED_OBLIGATION_TAG: u64 = 3;
const MAX_BORROWS_PER_OBLIGATION: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardConfig {
    pub critical_health_bps: u32,
    pub watch_health_bps: u32,
    pub max_data_age_seconds: u64,
    pub solana_rpc_url: String,
}

impl GuardConfig {
    /// Parse the operator-owned, host-injected config section.
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, GuardError> {
        for key in section.keys() {
            if !matches!(
                key.as_str(),
                "critical_health_bps"
                    | "watch_health_bps"
                    | "max_data_age_seconds"
                    | "solana_rpc_url"
            ) {
                return Err(GuardError::new(
                    "invalid_config",
                    "config contains an unsupported key",
                ));
            }
        }
        let critical_health_bps = parse_config_u32(
            section,
            "critical_health_bps",
            DEFAULT_CRITICAL_HEALTH_BPS,
            10_001,
            20_000,
        )?;
        let watch_health_bps = parse_config_u32(
            section,
            "watch_health_bps",
            DEFAULT_WATCH_HEALTH_BPS,
            10_002,
            30_000,
        )?;
        if watch_health_bps <= critical_health_bps {
            return Err(GuardError::new(
                "invalid_config",
                "watch threshold must exceed critical threshold",
            ));
        }
        let max_data_age_seconds = parse_config_u64(
            section,
            "max_data_age_seconds",
            DEFAULT_MAX_DATA_AGE_SECONDS,
            30,
            3_600,
        )?;
        let solana_rpc_url = match section.get("solana_rpc_url") {
            None => DEFAULT_SOLANA_RPC_URL.to_string(),
            Some(value) => validate_rpc_url(value)?.to_string(),
        };
        Ok(Self {
            critical_health_bps,
            watch_health_bps,
            max_data_age_seconds,
            solana_rpc_url,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObligationRef {
    pub obligation: String,
    pub market: String,
    pub tag: u8,
    /// Exact 16-byte KLend `LastUpdate` snapshot (slot, stale flag, price
    /// status, and reserved bytes).
    pub last_update: [u8; 16],
}

impl ObligationRef {
    fn last_update_slot(&self) -> u64 {
        u64::from_le_bytes(
            self.last_update[..8]
                .try_into()
                .expect("fixed KLend LastUpdate slot width"),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryEvidence {
    pub obligations: Vec<ObligationRef>,
    pub solana_slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardError {
    pub code: &'static str,
    pub message: &'static str,
}

impl GuardError {
    pub const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardStatus {
    NoDebt,
    Safe,
    Watch,
    Critical,
    Liquidatable,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuardReport {
    pub status: GuardStatus,
    pub reason: &'static str,
    pub obligations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_factor_bps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liquidation_buffer_bps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worst_obligation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_age_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solana_slot: Option<u64>,
}

impl GuardReport {
    pub fn no_debt(data_age_seconds: Option<u64>, solana_slot: Option<u64>) -> Self {
        Self {
            status: GuardStatus::NoDebt,
            reason: "no open borrows found across known Kamino KLend obligations",
            obligations: 0,
            health_factor_bps: None,
            liquidation_buffer_bps: None,
            worst_obligation: None,
            data_age_seconds,
            solana_slot,
        }
    }

    pub fn unknown(reason: &'static str) -> Self {
        Self {
            status: GuardStatus::Unknown,
            reason,
            obligations: 0,
            health_factor_bps: None,
            liquidation_buffer_bps: None,
            worst_obligation: None,
            data_age_seconds: None,
            solana_slot: None,
        }
    }
}

#[derive(Deserialize)]
struct RpcResponse {
    jsonrpc: String,
    id: u64,
    result: Option<RpcProgramAccountsResult>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RpcGenesisResponse {
    jsonrpc: String,
    id: u64,
    result: Option<String>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RpcProgramAccountsResult {
    context: RpcContext,
    value: Vec<RpcAccountEntry>,
}

#[derive(Deserialize)]
struct RpcContext {
    slot: u64,
}

#[derive(Deserialize)]
struct RpcAccountEntry {
    pubkey: String,
    account: RpcAccount,
}

#[derive(Deserialize)]
struct RpcAccount {
    data: [String; 2],
    executable: bool,
    owner: String,
    space: u64,
}

#[derive(Deserialize)]
struct LoanResponse {
    #[serde(rename = "loanId")]
    loan_id: String,
    #[serde(rename = "marketId")]
    market_id: String,
    user: String,
    timestamp: u64,
    #[serde(rename = "solanaSlot")]
    solana_slot: u64,
    #[serde(rename = "loanInfo")]
    loan_info: LoanInfo,
}

#[derive(Deserialize)]
struct LoanInfo {
    #[serde(rename = "currentLtv")]
    current_ltv: serde_json::Number,
    #[serde(rename = "liquidationLtv")]
    liquidation_ltv: serde_json::Number,
    debt: LoanDebt,
}

#[derive(Deserialize)]
struct LoanDebt {
    borrows: Vec<LoanBorrow>,
}

#[derive(Deserialize)]
struct LoanBorrow {
    #[serde(rename = "tokenMint")]
    token_mint: String,
    #[serde(rename = "tokenAmount")]
    token_amount: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveLoanEvidence {
    obligation: String,
    liquidatable: bool,
    current_ltv_scaled: u128,
    liquidation_ltv_scaled: u128,
    health_factor_bps: u32,
    liquidation_buffer_bps: u32,
    age_seconds: u64,
    solana_slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EvaluatedLoan {
    Closed { age_seconds: u64, solana_slot: u64 },
    Active(ActiveLoanEvidence),
}

impl EvaluatedLoan {
    fn age_seconds(&self) -> u64 {
        match self {
            Self::Closed { age_seconds, .. } => *age_seconds,
            Self::Active(value) => value.age_seconds,
        }
    }

    fn solana_slot(&self) -> u64 {
        match self {
            Self::Closed { solana_slot, .. } => *solana_slot,
            Self::Active(value) => value.solana_slot,
        }
    }
}

/// Validate a Solana public key without accepting whitespace or alternate
/// encodings. Valid keys decode from base58 to exactly 32 bytes.
pub fn validate_public_key(value: &str) -> bool {
    decode_public_key(value).is_some()
}

/// Require an operator-supplied RPC to identify the Solana mainnet-beta
/// genesis before its account set can influence a report.
pub fn validate_mainnet_genesis(body: &[u8]) -> Result<(), GuardError> {
    let response: RpcGenesisResponse = serde_json::from_slice(body).map_err(|_| {
        GuardError::new(
            "invalid_rpc",
            "Solana genesis response is not valid expected JSON",
        )
    })?;
    if response.jsonrpc != "2.0"
        || response.id != 0
        || response.error.is_some()
        || response.result.as_deref() != Some(SOLANA_MAINNET_GENESIS_HASH)
    {
        return Err(GuardError::new(
            "wrong_cluster",
            "Solana RPC is not verified as mainnet-beta",
        ));
    }
    Ok(())
}

fn decode_public_key(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() > 44 || value.trim() != value || !value.is_ascii() {
        return None;
    }
    let decoded = bs58::decode(value).into_vec().ok()?;
    (decoded.len() == 32).then_some(decoded)
}

/// Append one transport chunk without ever allowing the accumulated body to
/// cross `limit`. The WASM shim uses this for both content-length and chunked
/// responses.
pub fn append_bounded(body: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<(), GuardError> {
    if chunk.is_empty() {
        return Err(GuardError::new(
            "invalid_body_chunk",
            "remote response contained an invalid empty chunk",
        ));
    }
    let new_len = body
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| GuardError::new("oversized_response", "response length overflows"))?;
    if new_len > limit {
        return Err(GuardError::new(
            "oversized_response",
            "response exceeds the configured safety bound",
        ));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// Parse a `getProgramAccounts` response and return the complete, bounded set
/// of known KLend obligations owned by the requested wallet at the RPC
/// context slot.
pub fn discover_obligations(body: &[u8], wallet: &str) -> Result<DiscoveryEvidence, GuardError> {
    let response: RpcResponse = serde_json::from_slice(body).map_err(|_| {
        GuardError::new(
            "invalid_rpc",
            "Solana RPC response is not valid expected JSON",
        )
    })?;
    if response.jsonrpc != "2.0" || response.id != 1 || response.error.is_some() {
        return Err(GuardError::new(
            "invalid_rpc",
            "Solana RPC response envelope is invalid or contains an error",
        ));
    }
    let result = response.result.ok_or_else(|| {
        GuardError::new(
            "invalid_rpc",
            "Solana RPC response has no program-account result",
        )
    })?;
    if result.context.slot == 0 {
        return Err(GuardError::new(
            "invalid_rpc",
            "Solana RPC response has no valid context slot",
        ));
    }
    if result.value.len() > MAX_OBLIGATIONS {
        return Err(GuardError::new(
            "too_many_obligations",
            "obligation count exceeds the fail-closed bound",
        ));
    }

    let wallet_bytes = decode_public_key(wallet).ok_or_else(|| {
        GuardError::new(
            "invalid_wallet",
            "wallet is not a 32-byte base58 public key",
        )
    })?;
    let mut unique = BTreeMap::<String, (String, u8, [u8; 16])>::new();
    for item in result.value {
        if !validate_public_key(&item.pubkey)
            || item.account.owner != KLEND_PROGRAM_ID
            || item.account.executable
            || item.account.space < OBLIGATION_ACCOUNT_SIZE
            || item.account.data[1] != "base64"
        {
            return Err(GuardError::new(
                "invalid_rpc_account",
                "Solana RPC returned invalid or undersized obligation metadata",
            ));
        }
        let data = BASE64_STANDARD.decode(&item.account.data[0]).map_err(|_| {
            GuardError::new(
                "invalid_rpc_account",
                "Solana RPC obligation data is not valid base64",
            )
        })?;
        if data.len() != OBLIGATION_DATA_SLICE_BYTES
            || data[..8] != OBLIGATION_DISCRIMINATOR
            || data[64..96] != wallet_bytes
        {
            return Err(GuardError::new(
                "invalid_rpc_account",
                "Solana RPC obligation data has an invalid layout or owner",
            ));
        }
        let tag = u64::from_le_bytes(
            data[8..16]
                .try_into()
                .map_err(|_| GuardError::new("invalid_rpc_account", "invalid obligation tag"))?,
        );
        if tag > MAX_SUPPORTED_OBLIGATION_TAG {
            return Err(GuardError::new(
                "unsupported_obligation",
                "wallet has an unsupported KLend obligation type",
            ));
        }
        let tag = u8::try_from(tag)
            .map_err(|_| GuardError::new("invalid_rpc_account", "invalid obligation tag"))?;
        let last_update: [u8; 16] = data[16..32]
            .try_into()
            .map_err(|_| GuardError::new("invalid_rpc_account", "invalid last-update state"))?;
        let last_update_slot = u64::from_le_bytes(
            last_update[..8]
                .try_into()
                .map_err(|_| GuardError::new("invalid_rpc_account", "invalid last-update slot"))?,
        );
        if last_update_slot > result.context.slot {
            return Err(GuardError::new(
                "invalid_rpc_account",
                "obligation LastUpdate is ahead of the RPC context",
            ));
        }
        let market = bs58::encode(&data[32..64]).into_string();
        if !validate_public_key(&market) {
            return Err(GuardError::new(
                "invalid_rpc_account",
                "Solana RPC obligation has an invalid lending market",
            ));
        }
        if let Some((existing_market, existing_tag, existing_last_update)) =
            unique.insert(item.pubkey.clone(), (market.clone(), tag, last_update))
        {
            if existing_market != market
                || existing_tag != tag
                || existing_last_update != last_update
            {
                return Err(GuardError::new(
                    "contradictory_rpc",
                    "one obligation has contradictory on-chain state",
                ));
            }
        }
    }

    Ok(DiscoveryEvidence {
        obligations: unique
            .into_iter()
            .map(|(obligation, (market, tag, last_update))| ObligationRef {
                obligation,
                market,
                tag,
                last_update,
            })
            .collect(),
        solana_slot: result.context.slot,
    })
}

/// Require the second discovery read to be at least as recent as the first
/// and to observe the exact same identity plus KLend `LastUpdate` state.
pub fn validate_discovery_transition(
    initial: &DiscoveryEvidence,
    final_evidence: &DiscoveryEvidence,
) -> Result<(), GuardError> {
    if final_evidence.solana_slot < initial.solana_slot {
        return Err(GuardError::new(
            "regressed_rpc",
            "final Solana RPC context predates the initial snapshot",
        ));
    }
    if final_evidence.obligations != initial.obligations {
        return Err(GuardError::new(
            "changed_obligations",
            "KLend obligation state changed during the assessment",
        ));
    }
    Ok(())
}

/// Evaluate one loan-detail response against its on-chain-discovered identity
/// and the caller's wallet.
fn evaluate_loan(
    wallet: &str,
    expected: &ObligationRef,
    body: &[u8],
    now_ms: u64,
    minimum_solana_slot: u64,
    maximum_solana_slot: u64,
    cfg: &GuardConfig,
) -> Result<EvaluatedLoan, GuardError> {
    let loan: LoanResponse = serde_json::from_slice(body)
        .map_err(|_| GuardError::new("invalid_loan", "loan response is not valid expected JSON"))?;
    if loan.loan_id != expected.obligation
        || loan.market_id != expected.market
        || loan.user != wallet
    {
        return Err(GuardError::new(
            "identity_mismatch",
            "loan identity does not match the requested wallet and on-chain discovery",
        ));
    }
    if loan.solana_slot == 0 {
        return Err(GuardError::new(
            "invalid_loan",
            "loan response has no valid Solana slot",
        ));
    }
    if loan.solana_slot < minimum_solana_slot.max(expected.last_update_slot())
        || loan.solana_slot > maximum_solana_slot
    {
        return Err(GuardError::new(
            "inconsistent_slot",
            "loan snapshot falls outside the supporting on-chain slot window",
        ));
    }
    if loan.timestamp > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
        return Err(GuardError::new(
            "future_data",
            "loan timestamp is ahead of the local clock",
        ));
    }
    let age_ms = now_ms.saturating_sub(loan.timestamp);
    if age_ms > cfg.max_data_age_seconds.saturating_mul(1_000) {
        return Err(GuardError::new(
            "stale_data",
            "loan response is older than the operator freshness policy",
        ));
    }

    let current = parse_decimal_scaled(&loan.loan_info.current_ltv.to_string())?;
    let liquidation = parse_decimal_scaled(&loan.loan_info.liquidation_ltv.to_string())?;
    if current > MAX_CURRENT_LTV_SCALED || liquidation > DECIMAL_SCALE {
        return Err(GuardError::new(
            "invalid_ltv",
            "loan LTV values are outside the accepted range",
        ));
    }
    if loan.loan_info.debt.borrows.is_empty() {
        if current != 0 {
            return Err(GuardError::new(
                "contradictory_loan",
                "loan has no borrows but reports a nonzero current LTV",
            ));
        }
        return Ok(EvaluatedLoan::Closed {
            age_seconds: age_ms / 1_000,
            solana_slot: loan.solana_slot,
        });
    }
    if current == 0 || liquidation == 0 {
        return Err(GuardError::new(
            "invalid_ltv",
            "open loan LTV values must be nonzero",
        ));
    }
    if loan.loan_info.debt.borrows.len() > MAX_BORROWS_PER_OBLIGATION {
        return Err(GuardError::new(
            "invalid_loan",
            "loan borrow count exceeds the KLend account bound",
        ));
    }

    let mut borrow_mints = BTreeSet::new();
    for borrow in &loan.loan_info.debt.borrows {
        if !validate_public_key(&borrow.token_mint)
            || !is_positive_plain_decimal(&borrow.token_amount)
            || !borrow_mints.insert(&borrow.token_mint)
        {
            return Err(GuardError::new(
                "invalid_loan",
                "loan contains an invalid or duplicate borrow position",
            ));
        }
    }

    let health_factor_bps = mul_div_u32(liquidation, 10_000, current)?;
    let liquidation_buffer_bps = if current >= liquidation {
        0
    } else {
        mul_div_u32(liquidation - current, 10_000, liquidation)?
    };
    Ok(EvaluatedLoan::Active(ActiveLoanEvidence {
        obligation: expected.obligation.clone(),
        liquidatable: current >= liquidation,
        current_ltv_scaled: current,
        liquidation_ltv_scaled: liquidation,
        health_factor_bps,
        liquidation_buffer_bps,
        age_seconds: age_ms / 1_000,
        solana_slot: loan.solana_slot,
    }))
}

/// Evaluate every discovered loan. Any missing, stale, malformed, or
/// contradictory response fails the complete report closed.
pub fn evaluate_loans(
    wallet: &str,
    discovery: &DiscoveryEvidence,
    loan_bodies: &[Vec<u8>],
    now_ms: u64,
    cfg: &GuardConfig,
) -> Result<GuardReport, GuardError> {
    evaluate_loans_in_window(
        wallet,
        discovery.solana_slot,
        discovery,
        loan_bodies,
        now_ms,
        cfg,
    )
}

/// Evaluate every discovered loan inside an explicit assessment slot window.
/// Each API snapshot must be no older than the initial discovery and no newer
/// than the final discovery.
pub fn evaluate_loans_in_window(
    wallet: &str,
    initial_solana_slot: u64,
    discovery: &DiscoveryEvidence,
    loan_bodies: &[Vec<u8>],
    now_ms: u64,
    cfg: &GuardConfig,
) -> Result<GuardReport, GuardError> {
    if discovery.obligations.len() != loan_bodies.len()
        || discovery.obligations.len() > MAX_OBLIGATIONS
        || initial_solana_slot == 0
        || initial_solana_slot > discovery.solana_slot
        || discovery.solana_slot == 0
    {
        return Err(GuardError::new(
            "incomplete_evidence",
            "not every discovered obligation has one response",
        ));
    }

    let mut evaluated = Vec::with_capacity(discovery.obligations.len());
    for (expected, body) in discovery.obligations.iter().zip(loan_bodies) {
        evaluated.push(evaluate_loan(
            wallet,
            expected,
            body,
            now_ms,
            initial_solana_slot,
            discovery.solana_slot,
            cfg,
        )?);
    }
    if evaluated.is_empty() {
        return Ok(GuardReport::no_debt(None, Some(discovery.solana_slot)));
    }
    let oldest_age_seconds = evaluated
        .iter()
        .map(EvaluatedLoan::age_seconds)
        .max()
        .ok_or_else(|| GuardError::new("incomplete_evidence", "no loan evidence available"))?;
    let minimum_evidence_slot = evaluated
        .iter()
        .map(EvaluatedLoan::solana_slot)
        .chain(std::iter::once(discovery.solana_slot))
        .min()
        .ok_or_else(|| GuardError::new("incomplete_evidence", "no loan evidence available"))?;

    let active = evaluated
        .iter()
        .filter_map(|item| match item {
            EvaluatedLoan::Closed { .. } => None,
            EvaluatedLoan::Active(value) => Some(value),
        })
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(GuardReport::no_debt(
            Some(oldest_age_seconds),
            Some(minimum_evidence_slot),
        ));
    }

    let worst = active
        .iter()
        .min_by(|left, right| {
            // Compare exact ratios without division:
            // left_liquidation / left_current versus
            // right_liquidation / right_current.
            // Liquidation LTV is at most 1e18 and current LTV at most 1e20,
            // so the 1e38 cross-product remains below u128::MAX.
            let left_ratio = left.liquidation_ltv_scaled * right.current_ltv_scaled;
            let right_ratio = right.liquidation_ltv_scaled * left.current_ltv_scaled;
            left_ratio
                .cmp(&right_ratio)
                .then_with(|| left.obligation.cmp(&right.obligation))
        })
        .ok_or_else(|| GuardError::new("incomplete_evidence", "no loan evidence available"))?;
    let (status, reason) = if worst.liquidatable {
        (
            GuardStatus::Liquidatable,
            "current LTV is at or above the liquidation threshold",
        )
    } else if worst.health_factor_bps < cfg.critical_health_bps {
        (
            GuardStatus::Critical,
            "health factor is below the operator critical threshold",
        )
    } else if worst.health_factor_bps < cfg.watch_health_bps {
        (
            GuardStatus::Watch,
            "health factor is below the operator watch threshold",
        )
    } else {
        (
            GuardStatus::Safe,
            "all observed obligations are above the operator watch threshold",
        )
    };

    Ok(GuardReport {
        status,
        reason,
        obligations: active.len(),
        health_factor_bps: Some(worst.health_factor_bps),
        liquidation_buffer_bps: Some(worst.liquidation_buffer_bps),
        worst_obligation: Some(worst.obligation.clone()),
        data_age_seconds: Some(oldest_age_seconds),
        solana_slot: Some(minimum_evidence_slot),
    })
}

fn parse_config_u32(
    section: &HashMap<String, String>,
    key: &str,
    default: u32,
    min: u32,
    max: u32,
) -> Result<u32, GuardError> {
    match section.get(key) {
        None => Ok(default),
        Some(value) => {
            let parsed = value.parse::<u32>().map_err(|_| {
                GuardError::new("invalid_config", "config value is not an unsigned integer")
            })?;
            if !(min..=max).contains(&parsed) {
                return Err(GuardError::new(
                    "invalid_config",
                    "config value is outside its accepted range",
                ));
            }
            Ok(parsed)
        }
    }
}

fn parse_config_u64(
    section: &HashMap<String, String>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, GuardError> {
    match section.get(key) {
        None => Ok(default),
        Some(value) => {
            let parsed = value.parse::<u64>().map_err(|_| {
                GuardError::new("invalid_config", "config value is not an unsigned integer")
            })?;
            if !(min..=max).contains(&parsed) {
                return Err(GuardError::new(
                    "invalid_config",
                    "config value is outside its accepted range",
                ));
            }
            Ok(parsed)
        }
    }
}

fn validate_rpc_url(value: &str) -> Result<&str, GuardError> {
    if value.is_empty()
        || value.len() > 2_048
        || !value.is_ascii()
        || value.contains('#')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(GuardError::new(
            "invalid_config",
            "Solana RPC URL is empty, oversized, or contains invalid characters",
        ));
    }
    let uri = value.parse::<http::Uri>().map_err(|_| {
        GuardError::new(
            "invalid_config",
            "Solana RPC URL is not a valid absolute HTTPS URI",
        )
    })?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none()
        || uri.host().unwrap_or_default().is_empty()
        || value
            .split_once("://")
            .map(|(_, rest)| {
                rest.split(['/', '?'])
                    .next()
                    .unwrap_or_default()
                    .contains('@')
            })
            .unwrap_or(true)
    {
        return Err(GuardError::new(
            "invalid_config",
            "Solana RPC URL must use HTTPS and must not contain user info",
        ));
    }
    Ok(value)
}

fn is_positive_plain_decimal(input: &str) -> bool {
    let (whole, fraction) = input.split_once('.').unwrap_or((input, ""));
    !whole.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
        && (whole.bytes().any(|byte| byte != b'0') || fraction.bytes().any(|byte| byte != b'0'))
}

/// Parse a non-negative JSON decimal into 18 fixed fractional digits. Bounded
/// base-10 exponent notation is handled exactly; excess non-zero precision is
/// rejected instead of rounded.
fn parse_decimal_scaled(input: &str) -> Result<u128, GuardError> {
    let mut exponent_parts = input.split(['e', 'E']);
    let mantissa = exponent_parts.next().unwrap_or_default();
    let exponent = match exponent_parts.next() {
        None => 0_i32,
        Some(value) if !value.is_empty() => value
            .parse::<i32>()
            .map_err(|_| GuardError::new("invalid_ltv", "LTV exponent is invalid"))?,
        Some(_) => {
            return Err(GuardError::new("invalid_ltv", "LTV exponent is invalid"));
        }
    };
    if exponent_parts.next().is_some() {
        return Err(GuardError::new(
            "invalid_ltv",
            "LTV value contains multiple exponents",
        ));
    }

    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.contains('.')
    {
        return Err(GuardError::new(
            "invalid_ltv",
            "LTV value is not a non-negative decimal",
        ));
    }

    let mut coefficient_text = String::with_capacity(whole.len().saturating_add(fraction.len()));
    coefficient_text.push_str(whole);
    coefficient_text.push_str(fraction);
    let coefficient = coefficient_text
        .parse::<u128>()
        .map_err(|_| GuardError::new("invalid_ltv", "LTV coefficient overflows"))?;
    if coefficient == 0 {
        return Ok(0);
    }

    let fractional_digits = i64::try_from(fraction.len())
        .map_err(|_| GuardError::new("invalid_ltv", "LTV precision is outside range"))?;
    let shift = i64::from(DECIMAL_DIGITS as i32)
        .checked_add(i64::from(exponent))
        .and_then(|value| value.checked_sub(fractional_digits))
        .ok_or_else(|| GuardError::new("invalid_ltv", "LTV scale is outside range"))?;
    if shift >= 0 {
        let power = u32::try_from(shift)
            .ok()
            .and_then(|value| 10_u128.checked_pow(value))
            .ok_or_else(|| GuardError::new("invalid_ltv", "LTV value overflows"))?;
        return coefficient
            .checked_mul(power)
            .ok_or_else(|| GuardError::new("invalid_ltv", "LTV value overflows"));
    }

    let divisor_power = u32::try_from(shift.unsigned_abs())
        .ok()
        .and_then(|value| 10_u128.checked_pow(value))
        .ok_or_else(|| {
            GuardError::new(
                "invalid_ltv",
                "LTV precision exceeds the deterministic fixed-point scale",
            )
        })?;
    if coefficient % divisor_power != 0 {
        return Err(GuardError::new(
            "invalid_ltv",
            "LTV precision exceeds the deterministic fixed-point scale",
        ));
    }
    Ok(coefficient / divisor_power)
}

fn mul_div_u32(left: u128, multiplier: u128, divisor: u128) -> Result<u32, GuardError> {
    let value = left
        .checked_mul(multiplier)
        .ok_or_else(|| GuardError::new("invalid_ltv", "health calculation overflows"))?
        / divisor;
    Ok(u32::try_from(value).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn decimal_parser_is_fixed_point_and_supports_exact_exponents() {
        assert_eq!(
            parse_decimal_scaled("0.75").unwrap(),
            750_000_000_000_000_000
        );
        assert_eq!(
            parse_decimal_scaled("0.7542029331106038").unwrap(),
            754_202_933_110_603_800
        );
        assert_eq!(parse_decimal_scaled("1").unwrap(), DECIMAL_SCALE);
        assert_eq!(
            parse_decimal_scaled("7.5e-1").unwrap(),
            750_000_000_000_000_000
        );
        assert_eq!(parse_decimal_scaled("5e-7").unwrap(), 500_000_000_000);
        assert_eq!(parse_decimal_scaled("1e2").unwrap(), 100 * DECIMAL_SCALE);
        assert!(parse_decimal_scaled("1e-19").is_err());
        assert!(parse_decimal_scaled("0.7500000000000000001").is_err());
    }
}
