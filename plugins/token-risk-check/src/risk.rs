//! Pure risk-assessment core: SPL mint layout parsing, Token-2022 extension
//! TLV parsing, holder concentration, and red/amber/green scoring.
//!
//! No wasm, no HTTP, no solana-sdk: raw byte-offset parsing of account data so
//! the whole module compiles and tests on the host with a plain `cargo test`.

use std::collections::HashMap;

use crate::rpc::{self, RpcTransport};

/// SPL Token program id (legacy).
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// SPL Token-2022 program id.
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
/// Default public mainnet RPC, used when the operator has not configured one.
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

const MINT_BASE_LEN: usize = 82;
/// Token-2022 mints with extensions pad the base to token-account size (165)
/// and put a 1-byte account-type discriminator before the TLV data.
const EXTENSION_TLV_START: usize = 166;

/// Operator-tunable thresholds, resolved from the plugin's config section.
/// Defaults are safe: an empty map (no `config_read`) produces this exact
/// behavior against the public mainnet RPC.
pub struct RiskConfig {
    pub rpc_url: String,
    /// Top-10 holder share (in percent) above which concentration is amber.
    pub concentration_amber_pct: f64,
    /// Top-10 holder share (in percent) above which concentration is red.
    pub concentration_red_pct: f64,
    /// Transfer fee (basis points) above which the fee is red instead of amber.
    pub transfer_fee_red_bps: u16,
}

impl RiskConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let get_f64 = |key: &str, default: f64| {
            section
                .get(key)
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(default)
        };
        let get_u16 = |key: &str, default: u16| {
            section
                .get(key)
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(default)
        };
        Self {
            rpc_url: section
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string()),
            concentration_amber_pct: get_f64("concentration_amber_pct", 50.0),
            concentration_red_pct: get_f64("concentration_red_pct", 80.0),
            transfer_fee_red_bps: get_u16("transfer_fee_red_bps", 500),
        }
    }
}

/// Base SPL mint fields, identical layout in legacy Token and Token-2022.
#[derive(Debug, PartialEq)]
pub struct BaseMint {
    pub mint_authority: Option<[u8; 32]>,
    pub supply: u64,
    pub decimals: u8,
    pub freeze_authority: Option<[u8; 32]>,
}

/// Token-2022 extensions relevant to holder risk, parsed from the TLV region.
#[derive(Debug, Default, PartialEq)]
pub struct Extensions {
    /// Transfer fee in basis points (newer config), if the extension is present.
    pub transfer_fee_bps: Option<u16>,
    pub permanent_delegate: bool,
    pub transfer_hook: bool,
    pub non_transferable: bool,
    /// DefaultAccountState set to Frozen: new holders start frozen.
    pub default_frozen: bool,
    /// Extension type ids we saw but do not specifically assess.
    pub other: Vec<u16>,
}

/// Parse the 82-byte base mint layout.
pub fn parse_base_mint(data: &[u8]) -> Result<BaseMint, String> {
    if data.len() < MINT_BASE_LEN {
        return Err(format!(
            "account data too short for a mint: {} bytes",
            data.len()
        ));
    }
    let coption_pubkey = |off: usize| -> Result<Option<[u8; 32]>, String> {
        let tag = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        match tag {
            0 => Ok(None),
            1 => Ok(Some(data[off + 4..off + 36].try_into().unwrap())),
            t => Err(format!("invalid COption tag {t} at offset {off}")),
        }
    };
    let mint_authority = coption_pubkey(0)?;
    let supply = u64::from_le_bytes(data[36..44].try_into().unwrap());
    let decimals = data[44];
    if data[45] != 1 {
        return Err("mint account is not initialized".to_string());
    }
    let freeze_authority = coption_pubkey(46)?;
    Ok(BaseMint {
        mint_authority,
        supply,
        decimals,
        freeze_authority,
    })
}

/// Parse the Token-2022 TLV extension region, if any.
pub fn parse_extensions(data: &[u8]) -> Extensions {
    let mut ext = Extensions::default();
    if data.len() <= EXTENSION_TLV_START {
        return ext;
    }
    let mut off = EXTENSION_TLV_START;
    while off + 4 <= data.len() {
        let ext_type = u16::from_le_bytes(data[off..off + 2].try_into().unwrap());
        let len = u16::from_le_bytes(data[off + 2..off + 4].try_into().unwrap()) as usize;
        let body = off + 4;
        if ext_type == 0 {
            break; // Uninitialized: end of TLV entries
        }
        if body + len > data.len() {
            break; // truncated entry; stop rather than misparse
        }
        match ext_type {
            // TransferFeeConfig: two authorities (32+32), withheld u64,
            // older TransferFee (18), newer TransferFee (epoch u64 +
            // maximum_fee u64 + basis_points u16).
            1 => {
                let bps_off = body + 32 + 32 + 8 + 18 + 8 + 8;
                if bps_off + 2 <= body + len {
                    ext.transfer_fee_bps = Some(u16::from_le_bytes(
                        data[bps_off..bps_off + 2].try_into().unwrap(),
                    ));
                }
            }
            // DefaultAccountState: single byte, 2 = Frozen.
            6 => {
                if len >= 1 && data[body] == 2 {
                    ext.default_frozen = true;
                }
            }
            9 => ext.non_transferable = true,
            12 => ext.permanent_delegate = true,
            14 => ext.transfer_hook = true,
            other => ext.other.push(other),
        }
        off = body + len;
    }
    ext
}

/// Severity of a single finding; overall = worst finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Green,
    Amber,
    Red,
}

/// One scored finding with a human-readable reason.
#[derive(Debug)]
pub struct Finding {
    pub severity: Severity,
    pub reason: String,
}

/// The full assessment for a mint.
#[derive(Debug)]
pub struct RiskReport {
    pub mint: String,
    pub token_program: &'static str,
    pub overall: Severity,
    pub findings: Vec<Finding>,
    pub top10_pct: Option<f64>,
}

/// Score a parsed mint + holder distribution against the config thresholds.
pub fn assess(
    mint: &str,
    owner_program: &str,
    base: &BaseMint,
    ext: &Extensions,
    largest_amounts: &[u64],
    cfg: &RiskConfig,
) -> Result<RiskReport, String> {
    let token_program = match owner_program {
        TOKEN_PROGRAM => "spl-token",
        TOKEN_2022_PROGRAM => "token-2022",
        other => return Err(format!("not a token mint (owner program {other})")),
    };

    let mut findings = Vec::new();
    let mut push = |severity: Severity, reason: String| findings.push(Finding { severity, reason });

    if base.mint_authority.is_some() {
        push(
            Severity::Amber,
            "mint authority ACTIVE — supply can be inflated".into(),
        );
    }
    if base.freeze_authority.is_some() {
        push(
            Severity::Amber,
            "freeze authority ACTIVE — holder accounts can be frozen".into(),
        );
    }
    if ext.permanent_delegate {
        push(
            Severity::Red,
            "permanent delegate SET — tokens can be seized from any holder".into(),
        );
    }
    if ext.non_transferable {
        push(
            Severity::Red,
            "non-transferable — tokens cannot be sold".into(),
        );
    }
    if ext.default_frozen {
        push(
            Severity::Red,
            "default account state FROZEN — new holders start frozen".into(),
        );
    }
    if let Some(bps) = ext.transfer_fee_bps {
        if bps > 0 {
            let pct = bps as f64 / 100.0;
            let sev = if bps > cfg.transfer_fee_red_bps {
                Severity::Red
            } else {
                Severity::Amber
            };
            push(sev, format!("transfer fee {pct}% on every transfer"));
        }
    }
    if ext.transfer_hook {
        push(
            Severity::Amber,
            "transfer hook SET — external program runs on every transfer".into(),
        );
    }

    let top10_pct = concentration_top10_pct(base.supply, largest_amounts);
    if let Some(pct) = top10_pct {
        if pct > cfg.concentration_red_pct {
            push(
                Severity::Red,
                format!("top 10 holders own {pct:.0}% of supply"),
            );
        } else if pct > cfg.concentration_amber_pct {
            push(
                Severity::Amber,
                format!("top 10 holders own {pct:.0}% of supply"),
            );
        }
    }

    let overall = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Green);

    Ok(RiskReport {
        mint: mint.to_string(),
        token_program,
        overall,
        findings,
        top10_pct,
    })
}

/// Share of total supply held by the 10 largest token accounts, in percent.
/// None when supply is zero (nothing meaningful to report).
pub fn concentration_top10_pct(supply: u64, largest_amounts: &[u64]) -> Option<f64> {
    if supply == 0 {
        return None;
    }
    let top10: u128 = largest_amounts.iter().take(10).map(|&a| a as u128).sum();
    Some(top10 as f64 / supply as f64 * 100.0)
}

/// Shape the report into the compact text the model receives. Deliberately
/// small: the model needs the verdict and reasons, not the raw RPC payloads.
pub fn format_report(report: &RiskReport) -> String {
    let (emoji, word) = match report.overall {
        Severity::Green => ("🟢", "GREEN"),
        Severity::Amber => ("🟡", "AMBER"),
        Severity::Red => ("🔴", "RED"),
    };
    let mut out = format!(
        "{emoji} {word} — {} ({})\n",
        report.mint, report.token_program
    );
    if report.findings.is_empty() {
        out.push_str("• no authorities, no risky extensions, no concentration flags\n");
    }
    for f in &report.findings {
        out.push_str("• ");
        out.push_str(&f.reason);
        out.push('\n');
    }
    if let (Some(pct), true) = (
        report.top10_pct,
        report.findings.iter().all(|f| !f.reason.contains("top 10")),
    ) {
        out.push_str(&format!("• top 10 holders: {pct:.0}% of supply\n"));
    }
    out
}

/// End-to-end check over a transport: fetch mint account + largest holders,
/// parse, score, and shape. This is the single function the wasm shim calls.
pub fn run_check(rpc: &dyn RpcTransport, mint: &str, cfg: &RiskConfig) -> Result<String, String> {
    validate_mint_address(mint)?;
    let account = rpc::get_account_info(rpc, mint)?;
    let base = parse_base_mint(&account.data)?;
    let ext = parse_extensions(&account.data);
    // Holder concentration is best-effort: some RPC providers disable this
    // endpoint, and the authority/extension findings stand on their own.
    let largest = rpc::get_token_largest_accounts(rpc, mint).unwrap_or_default();
    let report = assess(mint, &account.owner, &base, &ext, &largest, cfg)?;
    Ok(format_report(&report))
}

/// Reject anything that is not a plausible base58-encoded 32-byte pubkey
/// before it reaches the RPC. This is the injection surface: the mint string
/// is the only model-controlled input.
pub fn validate_mint_address(mint: &str) -> Result<(), String> {
    let decoded = bs58::decode(mint)
        .into_vec()
        .map_err(|_| format!("not a valid base58 address: {mint}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "not a valid Solana address (decodes to {} bytes, expected 32): {mint}",
            decoded.len()
        ));
    }
    Ok(())
}
