
pub mod checks;
pub mod rpc;
pub mod shape;

use std::collections::HashMap;
use checks::{analyze_account_info, analyze_concentration, analyze_metadata, RiskReport};

pub struct Config {
    pub rpc_url: String,
    pub das_url: String,
}

impl Config {
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        Config {
            rpc_url: map.get("rpc_url").cloned()
                .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string()),
            das_url: map.get("das_url").cloned()
                .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string()),
        }
    }
}

pub fn check_token(
    rpc_url: &str,
    das_url: &str,
    mint: &str,
    rpc_account: impl Fn(&str, &str) -> Result<String, String>,
    rpc_largest: impl Fn(&str, &str) -> Result<String, String>,
    das_asset: impl Fn(&str, &str) -> Result<String, String>,
) -> RiskReport {
    let account_raw = rpc_account(rpc_url, mint).unwrap_or_default();
    let mut report = analyze_account_info(&account_raw);

    let largest_raw = rpc_largest(rpc_url, mint).unwrap_or_default();
    analyze_concentration(&largest_raw, &mut report);

    let das_raw = das_asset(das_url, mint).unwrap_or_default();
    analyze_metadata(&das_raw, &mut report);

    if report.reasons.is_empty() {
        report.reasons.push("No issues detected".to_string());
    }

    report
}
