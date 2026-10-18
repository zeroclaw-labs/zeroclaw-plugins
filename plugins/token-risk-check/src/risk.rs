//! Pure token-risk core. No wasm, no HTTP.
//!
//! The component shim (lib.rs) fetches Solana RPC / DAS JSON, then every
//! scoring decision runs through this module so host `cargo test` covers the
//! same logic the wasm path executes.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Custody tier for this plugin. Non-negotiable: T0 Read only.
pub const CUSTODY_TIER: &str = "T0";

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const DEFAULT_COMMITMENT: &str = "confirmed";

/// Flat config section the host injects via `__config`.
#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub rpc_url: String,
    pub das_url: Option<String>,
    pub commitment: String,
}

impl PluginConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let rpc_url = section
            .get("rpc_url")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        let das_url = section
            .get("das_url")
            .filter(|v| !v.is_empty())
            .cloned();
        let commitment = section
            .get("commitment")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_COMMITMENT.to_string());
        Self {
            rpc_url,
            das_url,
            commitment,
        }
    }
}

/// Traffic-light risk level returned to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Green,
    Amber,
    Red,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Green => "green",
            RiskLevel::Amber => "amber",
            RiskLevel::Red => "red",
        }
    }

    /// Worst-of merge (red > amber > green).
    pub fn max(self, other: Self) -> Self {
        use RiskLevel::*;
        match (self, other) {
            (Red, _) | (_, Red) => Red,
            (Amber, _) | (_, Amber) => Amber,
            _ => Green,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub severity: RiskLevel,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReport {
    pub custody_tier: String,
    pub mint: String,
    pub risk: RiskLevel,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub authorities: Authorities,
    pub token2022: Token2022Info,
    pub supply: Option<SupplyInfo>,
    pub concentration: Option<ConcentrationInfo>,
    /// Compact notes for the LLM — keep this short on purpose.
    pub agent_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Authorities {
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub mint_authority_set: bool,
    pub freeze_authority_set: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Token2022Info {
    pub is_token_2022: bool,
    pub extensions: Vec<String>,
    pub transfer_fee_bps: Option<u16>,
    pub transfer_fee_max: Option<u64>,
    pub permanent_delegate: Option<String>,
    pub transfer_hook_program: Option<String>,
    pub default_account_state_frozen: bool,
    pub non_transferable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyInfo {
    pub amount: String,
    pub decimals: u8,
    pub ui_amount: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcentrationInfo {
    pub top_holder_pct: Option<f64>,
    pub top5_holder_pct: Option<f64>,
    pub holder_count_hint: Option<u64>,
    pub source: String,
}

/// Validate a base58 Solana pubkey (32 bytes). Rejects anything else fail-closed.
pub fn parse_pubkey(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("mint is required".into());
    }
    // Hard reject private-key shaped inputs so prompt injection cannot smuggle secrets.
    if s.split_whitespace().count() > 1 {
        return Err("mint must be a single base58 pubkey, not a phrase".into());
    }
    if s.contains("private") || s.contains("secret") || s.starts_with('[') {
        return Err("refusing to parse secret-like mint input".into());
    }
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("invalid base58 mint: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "mint must decode to 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build a JSON-RPC body for `getAccountInfo` (base64 encoding).
pub fn rpc_get_account_info(mint: &str, commitment: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            mint,
            {
                "encoding": "base64",
                "commitment": commitment
            }
        ]
    })
}

/// Build JSON-RPC `getTokenSupply`.
pub fn rpc_get_token_supply(mint: &str, commitment: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "getTokenSupply",
        "params": [
            mint,
            { "commitment": commitment }
        ]
    })
}

/// Build JSON-RPC `getTokenLargestAccounts` (concentration signal).
pub fn rpc_get_token_largest_accounts(mint: &str, commitment: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "getTokenLargestAccounts",
        "params": [
            mint,
            { "commitment": commitment }
        ]
    })
}

/// Optional DAS `getAsset` body (Helius-compatible).
pub fn das_get_asset(mint: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": "token-risk-check",
        "method": "getAsset",
        "params": { "id": mint }
    })
}

// SPL Token mint layout offsets (same for classic SPL Token and Token-2022 base).
// https://github.com/solana-labs/solana-program-library/blob/master/token/program/src/state.rs
const MINT_SIZE_CLASSIC: usize = 82;
const OFF_MINT_AUTH_OPT: usize = 0; // COption<Pubkey> = 4 + 32
const OFF_SUPPLY: usize = 36; // u64
const OFF_DECIMALS: usize = 44; // u8
const OFF_IS_INITIALIZED: usize = 45; // bool
const OFF_FREEZE_AUTH_OPT: usize = 46; // COption<Pubkey>

/// SPL Token program id (classic).
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Token-2022 program id.
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

#[derive(Debug, Clone)]
pub struct ParsedMintAccount {
    pub owner_program: String,
    pub data: Vec<u8>,
    pub lamports: u64,
}

/// Parse a Solana `getAccountInfo` JSON result into raw mint bytes + owner.
pub fn parse_account_info_result(result: &Value) -> Result<ParsedMintAccount, String> {
    let value = result
        .get("value")
        .ok_or_else(|| "getAccountInfo: missing value".to_string())?;
    if value.is_null() {
        return Err("mint account not found on this cluster".into());
    }
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "getAccountInfo: missing owner".to_string())?
        .to_string();
    let lamports = value
        .get("lamports")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let data_arr = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| "getAccountInfo: data not base64 array".to_string())?;
    let b64 = data_arr
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| "getAccountInfo: empty data".to_string())?;
    // Standard base64 (Solana RPC).
    let data = decode_base64(b64).map_err(|e| format!("base64 decode: {e}"))?;
    Ok(ParsedMintAccount {
        owner_program: owner,
        data,
        lamports,
    })
}

fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    // Minimal base64 decoder to avoid extra deps on host/wasm.
    const T: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &c) in T.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let s = s.trim().as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s {
        if c == b'=' {
            break;
        }
        if c == b'\n' || c == b'\r' || c == b' ' {
            continue;
        }
        let v = table[c as usize];
        if v == 255 {
            return Err(format!("invalid base64 byte {c}"));
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn read_coption_pubkey(data: &[u8], off: usize) -> Result<Option<String>, String> {
    if data.len() < off + 36 {
        return Err("mint account data too short for COption pubkey".into());
    }
    let tag = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
    match tag {
        0 => Ok(None),
        1 => {
            let pk = &data[off + 4..off + 36];
            Ok(Some(bs58::encode(pk).into_string()))
        }
        _ => Err(format!("invalid COption tag {tag}")),
    }
}

fn read_u64_le(data: &[u8], off: usize) -> Result<u64, String> {
    if data.len() < off + 8 {
        return Err("mint data too short for u64".into());
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}

/// Parse classic SPL mint fields (first 82 bytes).
pub fn parse_mint_base(data: &[u8]) -> Result<(Authorities, u64, u8, bool), String> {
    if data.len() < MINT_SIZE_CLASSIC {
        return Err(format!(
            "mint data length {} < {MINT_SIZE_CLASSIC}",
            data.len()
        ));
    }
    let mint_authority = read_coption_pubkey(data, OFF_MINT_AUTH_OPT)?;
    let supply = read_u64_le(data, OFF_SUPPLY)?;
    let decimals = data[OFF_DECIMALS];
    let is_initialized = data[OFF_IS_INITIALIZED] != 0;
    let freeze_authority = read_coption_pubkey(data, OFF_FREEZE_AUTH_OPT)?;
    let authorities = Authorities {
        mint_authority_set: mint_authority.is_some(),
        freeze_authority_set: freeze_authority.is_some(),
        mint_authority,
        freeze_authority,
    };
    Ok((authorities, supply, decimals, is_initialized))
}

// Token-2022 TLV account type + extension parsing (best-effort, fail-closed on unknowns of interest).
// After the 82-byte base mint: optional padding to 165 for multisig-compat is NOT used on mints;
// Token-2022 mints append account type byte + TLV.
// See: https://github.com/solana-program/token-2022
const ACCOUNT_TYPE_MINT: u8 = 1;

/// Known Token-2022 extension type codes we care about for risk.
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum ExtType {
    TransferFeeConfig = 1,
    // 2 TransferFeeAmount (account)
    MintCloseAuthority = 3,
    // 4 ConfidentialTransferMint …
    DefaultAccountState = 6,
    ImmutableOwner = 7,
    MemoTransfer = 8,
    NonTransferable = 9,
    InterestBearingConfig = 10,
    // 11 CpiGuard
    PermanentDelegate = 12,
    NonTransferableAccount = 13,
    TransferHook = 14,
    // 15 TransferHookAccount
    MetadataPointer = 18,
    // 19 TokenMetadata
    GroupPointer = 20,
    // …
    Pausable = 26,
}

fn ext_name(t: u16) -> String {
    match t {
        1 => "transfer_fee_config".into(),
        3 => "mint_close_authority".into(),
        6 => "default_account_state".into(),
        7 => "immutable_owner".into(),
        8 => "memo_transfer".into(),
        9 => "non_transferable".into(),
        10 => "interest_bearing_config".into(),
        12 => "permanent_delegate".into(),
        14 => "transfer_hook".into(),
        18 => "metadata_pointer".into(),
        19 => "token_metadata".into(),
        20 => "group_pointer".into(),
        26 => "pausable".into(),
        other => format!("extension_{other}"),
    }
}

/// Parse Token-2022 extensions after the classic mint header.
pub fn parse_token2022_extensions(data: &[u8]) -> Token2022Info {
    let mut info = Token2022Info {
        is_token_2022: data.len() > MINT_SIZE_CLASSIC,
        ..Default::default()
    };
    if data.len() <= MINT_SIZE_CLASSIC {
        return info;
    }

    // Token-2022 mint: bytes[82] may be account type (1 = mint), then TLV pairs.
    let mut i = MINT_SIZE_CLASSIC;
    if data[i] == ACCOUNT_TYPE_MINT {
        i += 1;
    }

    while i + 4 <= data.len() {
        let ext_type = u16::from_le_bytes([data[i], data[i + 1]]);
        let ext_len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;
        if i + ext_len > data.len() {
            break;
        }
        let payload = &data[i..i + ext_len];
        let name = ext_name(ext_type);
        if !info.extensions.contains(&name) {
            info.extensions.push(name.clone());
        }

        match ext_type {
            x if x == ExtType::TransferFeeConfig as u16 => {
                // TransferFeeConfig layout (approx):
                // transfer_fee_config_authority: COption(36) + withdraw_withheld_authority: COption(36)
                // + withheld_amount: u64 + older_transfer_fee: TransferFee(10?) + newer_transfer_fee
                // We only need newer basis points if present — best effort.
                if payload.len() >= 36 + 36 + 8 + 8 + 2 {
                    // Skip two COptions (72) + withheld u64 (8) + older epoch/u64/u16...
                    // Practical approach: scan for basis points field near the end of the first fee struct.
                    // TransferFee = epoch(u64) + maximum_fee(u64) + transfer_fee_basis_points(u16)
                    // older at offset 72+8=80, newer follows 18 bytes later.
                    let older_off = 72 + 8;
                    if payload.len() >= older_off + 18 + 18 {
                        let newer_off = older_off + 18;
                        let bps = u16::from_le_bytes([
                            payload[newer_off + 16],
                            payload[newer_off + 17],
                        ]);
                        let max_fee = u64::from_le_bytes(
                            payload[newer_off + 8..newer_off + 16]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        info.transfer_fee_bps = Some(bps);
                        info.transfer_fee_max = Some(max_fee);
                    }
                }
            }
            x if x == ExtType::PermanentDelegate as u16 => {
                // PermanentDelegate: Pubkey (32)
                if payload.len() >= 32 {
                    info.permanent_delegate =
                        Some(bs58::encode(&payload[0..32]).into_string());
                }
            }
            x if x == ExtType::TransferHook as u16 => {
                // TransferHook: authority COption + program_id Pubkey — layout varies;
                // take last 32 bytes as program id when long enough.
                if payload.len() >= 32 {
                    let start = payload.len() - 32;
                    info.transfer_hook_program =
                        Some(bs58::encode(&payload[start..]).into_string());
                }
            }
            x if x == ExtType::DefaultAccountState as u16 => {
                // 0 = Uninitialized, 1 = Initialized, 2 = Frozen
                if !payload.is_empty() && payload[0] == 2 {
                    info.default_account_state_frozen = true;
                }
            }
            x if x == ExtType::NonTransferable as u16 => {
                info.non_transferable = true;
            }
            _ => {}
        }

        i += ext_len;
        // TLV entries are often padded to 4 or 8 — align up to 4.
        let mis = i % 4;
        if mis != 0 {
            i += 4 - mis;
        }
    }

    info
}

/// Parse `getTokenSupply` result.
pub fn parse_token_supply_result(result: &Value) -> Option<SupplyInfo> {
    let value = result.get("value")?;
    let amount = value.get("amount")?.as_str()?.to_string();
    let decimals = value.get("decimals")?.as_u64()? as u8;
    let ui_amount = value.get("uiAmount").and_then(Value::as_f64);
    Some(SupplyInfo {
        amount,
        decimals,
        ui_amount,
    })
}

/// Concentration from `getTokenLargestAccounts` + total supply amount string.
pub fn concentration_from_largest(
    largest: &Value,
    supply_amount: &str,
) -> Option<ConcentrationInfo> {
    let accounts = largest.get("value")?.as_array()?;
    let supply: u128 = supply_amount.parse().ok()?;
    if supply == 0 {
        return Some(ConcentrationInfo {
            top_holder_pct: None,
            top5_holder_pct: None,
            holder_count_hint: None,
            source: "getTokenLargestAccounts".into(),
        });
    }
    let mut amounts: Vec<u128> = accounts
        .iter()
        .filter_map(|a| a.get("amount")?.as_str()?.parse().ok())
        .collect();
    amounts.sort_by(|a, b| b.cmp(a));
    let top = amounts.first().copied().unwrap_or(0);
    let top5: u128 = amounts.iter().take(5).sum();
    Some(ConcentrationInfo {
        top_holder_pct: Some((top as f64) * 100.0 / supply as f64),
        top5_holder_pct: Some((top5 as f64) * 100.0 / supply as f64),
        holder_count_hint: None,
        source: "getTokenLargestAccounts".into(),
    })
}

/// Score findings from parsed mint data.
pub fn score_risk(
    mint: &str,
    owner_program: &str,
    authorities: &Authorities,
    t22: &Token2022Info,
    supply: &Option<SupplyInfo>,
    concentration: &Option<ConcentrationInfo>,
) -> RiskReport {
    let mut findings: Vec<Finding> = Vec::new();

    let is_token = owner_program == TOKEN_PROGRAM_ID || owner_program == TOKEN_2022_PROGRAM_ID;
    if !is_token {
        findings.push(Finding {
            code: "unknown_owner".into(),
            severity: RiskLevel::Red,
            detail: format!(
                "account owner is not SPL Token or Token-2022 (owner={owner_program})"
            ),
        });
    }

    if authorities.mint_authority_set {
        findings.push(Finding {
            code: "mint_authority_active".into(),
            severity: RiskLevel::Amber,
            detail: format!(
                "mint authority still set ({}) — supply can be inflated",
                authorities
                    .mint_authority
                    .as_deref()
                    .unwrap_or("?")
            ),
        });
    } else {
        findings.push(Finding {
            code: "mint_authority_revoked".into(),
            severity: RiskLevel::Green,
            detail: "mint authority is None (fixed supply)".into(),
        });
    }

    if authorities.freeze_authority_set {
        findings.push(Finding {
            code: "freeze_authority_active".into(),
            severity: RiskLevel::Amber,
            detail: format!(
                "freeze authority still set ({}) — accounts can be frozen",
                authorities
                    .freeze_authority
                    .as_deref()
                    .unwrap_or("?")
            ),
        });
    }

    if t22.permanent_delegate.is_some() {
        findings.push(Finding {
            code: "permanent_delegate".into(),
            severity: RiskLevel::Red,
            detail: format!(
                "Token-2022 permanent delegate present ({}) — can move tokens without owner signature",
                t22.permanent_delegate.as_deref().unwrap_or("?")
            ),
        });
    }

    if t22.transfer_hook_program.is_some() {
        findings.push(Finding {
            code: "transfer_hook".into(),
            severity: RiskLevel::Amber,
            detail: format!(
                "transfer hook program {} — transfers invoke extra program logic",
                t22.transfer_hook_program.as_deref().unwrap_or("?")
            ),
        });
    }

    if let Some(bps) = t22.transfer_fee_bps {
        let sev = if bps >= 500 {
            RiskLevel::Red
        } else if bps > 0 {
            RiskLevel::Amber
        } else {
            RiskLevel::Green
        };
        findings.push(Finding {
            code: "transfer_fee".into(),
            severity: sev,
            detail: format!(
                "transfer fee {bps} bps (max_fee={})",
                t22.transfer_fee_max.unwrap_or(0)
            ),
        });
    }

    if t22.default_account_state_frozen {
        findings.push(Finding {
            code: "default_frozen".into(),
            severity: RiskLevel::Red,
            detail: "default account state is Frozen — new ATAs start frozen".into(),
        });
    }

    if t22.non_transferable {
        findings.push(Finding {
            code: "non_transferable".into(),
            severity: RiskLevel::Amber,
            detail: "non-transferable token extension enabled".into(),
        });
    }

    if t22.extensions.iter().any(|e| e == "pausable") {
        findings.push(Finding {
            code: "pausable".into(),
            severity: RiskLevel::Amber,
            detail: "pausable extension present".into(),
        });
    }

    if let Some(c) = concentration {
        if let Some(top) = c.top_holder_pct {
            if top >= 50.0 {
                findings.push(Finding {
                    code: "holder_concentration_high".into(),
                    severity: RiskLevel::Red,
                    detail: format!("top holder controls ~{top:.1}% of supply"),
                });
            } else if top >= 20.0 {
                findings.push(Finding {
                    code: "holder_concentration_elevated".into(),
                    severity: RiskLevel::Amber,
                    detail: format!("top holder controls ~{top:.1}% of supply"),
                });
            }
        }
        if let Some(top5) = c.top5_holder_pct {
            if top5 >= 80.0 {
                findings.push(Finding {
                    code: "top5_concentration".into(),
                    severity: RiskLevel::Amber,
                    detail: format!("top 5 holders control ~{top5:.1}% of supply"),
                });
            }
        }
    }

    let risk = findings
        .iter()
        .map(|f| f.severity)
        .fold(RiskLevel::Green, RiskLevel::max);

    // If only green informational findings, stay green.
    let risk = if findings.iter().all(|f| f.severity == RiskLevel::Green) {
        RiskLevel::Green
    } else {
        risk
    };

    let summary = match risk {
        RiskLevel::Green => format!(
            "{mint}: GREEN — no high-risk authorities/extensions detected"
        ),
        RiskLevel::Amber => format!(
            "{mint}: AMBER — review authorities/extensions before treating as safe"
        ),
        RiskLevel::Red => format!(
            "{mint}: RED — dangerous mint controls present; do not treat as safe collateral"
        ),
    };

    let mut agent_notes = vec![
        format!("custody_tier={CUSTODY_TIER} (read-only; never signs or holds keys)"),
        format!("risk={}", risk.as_str()),
    ];
    for f in findings
        .iter()
        .filter(|f| f.severity != RiskLevel::Green)
        .take(5)
    {
        agent_notes.push(format!("{}: {}", f.code, f.detail));
    }
    if let Some(s) = supply {
        agent_notes.push(format!(
            "supply={} decimals={}",
            s.ui_amount
                .map(|u| u.to_string())
                .unwrap_or_else(|| s.amount.clone()),
            s.decimals
        ));
    }

    // Hard cap agent-facing notes so we don't flood the context window.
    const MAX_NOTE_CHARS: usize = 900;
    let mut used = 0usize;
    agent_notes.retain(|n| {
        if used + n.len() > MAX_NOTE_CHARS {
            return false;
        }
        used += n.len();
        true
    });

    RiskReport {
        custody_tier: CUSTODY_TIER.into(),
        mint: mint.to_string(),
        risk,
        summary,
        findings,
        authorities: authorities.clone(),
        token2022: t22.clone(),
        supply: supply.clone(),
        concentration: concentration.clone(),
        agent_notes,
    }
}

/// Compact JSON string for the agent (shaped, not raw RPC dump).
pub fn report_to_agent_output(report: &RiskReport) -> String {
    // Prefer a tight object the model can quote in chat.
    let compact = serde_json::json!({
        "risk": report.risk.as_str(),
        "mint": report.mint,
        "summary": report.summary,
        "custody_tier": report.custody_tier,
        "mint_authority": report.authorities.mint_authority,
        "freeze_authority": report.authorities.freeze_authority,
        "token2022": {
            "yes": report.token2022.is_token_2022,
            "extensions": report.token2022.extensions,
            "permanent_delegate": report.token2022.permanent_delegate,
            "transfer_hook": report.token2022.transfer_hook_program,
            "transfer_fee_bps": report.token2022.transfer_fee_bps,
        },
        "concentration": report.concentration,
        "findings": report.findings.iter().filter(|f| f.severity != RiskLevel::Green).map(|f| {
            serde_json::json!({
                "code": f.code,
                "severity": f.severity.as_str(),
                "detail": f.detail,
            })
        }).collect::<Vec<_>>(),
        "notes": report.agent_notes,
    });
    serde_json::to_string(&compact).unwrap_or_else(|_| report.summary.clone())
}

/// Full analysis entry used by tests and the wasm shim after HTTP is done.
pub fn analyze_from_rpc_payloads(
    mint: &str,
    account_info_result: &Value,
    supply_result: Option<&Value>,
    largest_result: Option<&Value>,
) -> Result<RiskReport, String> {
    let _ = parse_pubkey(mint)?;
    let account = parse_account_info_result(account_info_result)?;
    let (authorities, _raw_supply, _decimals, initialized) = parse_mint_base(&account.data)?;
    if !initialized {
        return Err("mint account is not initialized".into());
    }
    let mut t22 = if account.owner_program == TOKEN_2022_PROGRAM_ID {
        parse_token2022_extensions(&account.data)
    } else {
        Token2022Info {
            is_token_2022: false,
            ..Default::default()
        }
    };
    if account.owner_program == TOKEN_2022_PROGRAM_ID {
        t22.is_token_2022 = true;
    }

    let supply = supply_result.and_then(parse_token_supply_result);
    let concentration = match (largest_result, supply.as_ref()) {
        (Some(l), Some(s)) => concentration_from_largest(l, &s.amount),
        _ => None,
    };

    Ok(score_risk(
        mint,
        &account.owner_program,
        &authorities,
        &t22,
        &supply,
        &concentration,
    ))
}

/// Reject fund-moving / signing intents that an LLM might try to bolt onto this tool.
pub fn reject_unsafe_intent(args_json: &str) -> Option<String> {
    let lower = args_json.to_ascii_lowercase();
    const BANNED: &[&str] = &[
        "private_key",
        "secret_key",
        "secretkey",
        "privkey",
        "seed_phrase",
        "mnemonic",
        "sign_transaction",
        "send_transaction",
        "transfer_to",
        "withdraw",
        "drain",
    ];
    for b in BANNED {
        if lower.contains(b) {
            return Some(format!(
                "refused: token-risk-check is T0 read-only and rejects `{b}` fields (fail closed)"
            ));
        }
    }
    None
}
