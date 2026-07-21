use std::collections::HashMap;

pub struct Config {
    pub rpc_url: String,
}

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

impl Config {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let rpc_url = section
            .get("rpc_url")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        Self { rpc_url }
    }
}

#[derive(Debug, PartialEq)]
pub struct MintAccountInfo {
    pub mint_authority_present: bool,
    pub freeze_authority_present: bool,
    pub supply: u64,
    pub decimals: u8,
}

const MINT_ACCOUNT_MIN_LEN: usize = 82;

pub fn decode_mint_account(data: &[u8]) -> Result<MintAccountInfo, String> {
    if data.len() < MINT_ACCOUNT_MIN_LEN {
        return Err(format!(
            "account data too short for a mint: got {} bytes, need at least {}",
            data.len(),
            MINT_ACCOUNT_MIN_LEN
        ));
    }

    let mint_authority_present = u32::from_le_bytes(data[0..4].try_into().unwrap()) == 1;
    let supply = u64::from_le_bytes(data[36..44].try_into().unwrap());
    let decimals = data[44];
    let freeze_authority_present = u32::from_le_bytes(data[46..50].try_into().unwrap()) == 1;

    Ok(MintAccountInfo {
        mint_authority_present,
        freeze_authority_present,
        supply,
        decimals,
    })
}

pub struct HolderBalance {
    pub amount: u64,
}

#[derive(Debug, PartialEq, Default)]
pub struct ConcentrationStats {
    pub top1_pct: f64,
    pub top10_pct: f64,
}

pub fn compute_concentration(holders: &[HolderBalance], total_supply: u64) -> ConcentrationStats {
    if total_supply == 0 || holders.is_empty() {
        return ConcentrationStats::default();
    }
    let top1 = holders[0].amount as f64;
    let top10: u64 = holders.iter().take(10).map(|h| h.amount).sum();
    ConcentrationStats {
        top1_pct: (top1 / total_supply as f64) * 100.0,
        top10_pct: (top10 as f64 / total_supply as f64) * 100.0,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RiskLevel {
    Green,
    Amber,
    Red,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Green => "green",
            RiskLevel::Amber => "amber",
            RiskLevel::Red => "red",
        }
    }
}

pub struct Verdict {
    pub level: RiskLevel,
    pub reasons: Vec<String>,
}

const TOP1_RED_THRESHOLD_PCT: f64 = 50.0;
const TOP10_AMBER_THRESHOLD_PCT: f64 = 80.0;

pub fn assess_risk(mint: &MintAccountInfo, concentration: &ConcentrationStats) -> Verdict {
    let mut reasons = Vec::new();
    let mut level = RiskLevel::Green;

    if mint.freeze_authority_present {
        reasons.push("freeze authority is still active: holder accounts can be frozen".to_string());
        level = RiskLevel::Red;
    }
    if concentration.top1_pct > TOP1_RED_THRESHOLD_PCT {
        reasons.push(format!(
            "top holder controls {:.1}% of supply",
            concentration.top1_pct
        ));
        level = RiskLevel::Red;
    }
    if mint.mint_authority_present && level != RiskLevel::Red {
        reasons.push("mint authority is still active: supply can be inflated".to_string());
        level = RiskLevel::Amber;
    } else if mint.mint_authority_present {
        reasons.push("mint authority is still active: supply can be inflated".to_string());
    }
    if concentration.top10_pct > TOP10_AMBER_THRESHOLD_PCT && level == RiskLevel::Green {
        reasons.push(format!(
            "top 10 holders control {:.1}% of supply",
            concentration.top10_pct
        ));
        level = RiskLevel::Amber;
    } else if concentration.top10_pct > TOP10_AMBER_THRESHOLD_PCT {
        reasons.push(format!(
            "top 10 holders control {:.1}% of supply",
            concentration.top10_pct
        ));
    }

    if reasons.is_empty() {
        reasons.push("no freeze authority, no mint authority, holders reasonably distributed".to_string());
    }

    Verdict { level, reasons }
}

pub fn format_summary(mint: &str, mint_info: &MintAccountInfo, verdict: &Verdict) -> String {
    let mut out = format!(
        "Verdict: {} | mint {} | decimals {} | supply {}\n",
        verdict.level.as_str().to_uppercase(),
        mint,
        mint_info.decimals,
        mint_info.supply
    );
    for reason in &verdict.reasons {
        out.push_str("- ");
        out.push_str(reason);
        out.push('\n');
    }
    out
}

pub fn validate_mint_address(mint: &str) -> Result<(), String> {
    let decoded = bs58::decode(mint)
        .into_vec()
        .map_err(|e| format!("not valid base58: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "decoded address is {} bytes, expected 32",
            decoded.len()
        ));
    }
    Ok(())
}
