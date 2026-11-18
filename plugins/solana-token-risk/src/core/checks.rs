
use serde_json::Value;

#[derive(Debug, PartialEq, Clone)]
pub enum RiskLevel {
    Red,
    Amber,
    Green,
}

impl RiskLevel {
    pub fn label(&self) -> &str {
        match self {
            RiskLevel::Red => "RED",
            RiskLevel::Amber => "AMBER",
            RiskLevel::Green => "GREEN",
        }
    }
}

#[derive(Debug)]
pub struct RiskReport {
    pub level: RiskLevel,
    pub reasons: Vec<String>,
}

pub fn analyze_account_info(raw: &str) -> RiskReport {
    let mut reasons: Vec<String> = Vec::new();
    let mut red: u32 = 0;
    let mut amber: u32 = 0;

    let v: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => {
            return RiskReport {
                level: RiskLevel::Red,
                reasons: vec!["Failed to parse RPC response".to_string()],
            }
        }
    };

    let info = &v["result"]["value"]["data"]["parsed"]["info"];

    let mint_auth = info["mintAuthority"].as_str().unwrap_or("");
    if mint_auth.is_empty() {
        reasons.push("Mint authority revoked".to_string());
    } else {
        reasons.push("Mint authority open - new tokens can be minted anytime".to_string());
        red += 1;
    }

    match info.get("freezeAuthority") {
        Some(Value::Null) | None => {}
        Some(v) if v.as_str().map(|s| s.is_empty()).unwrap_or(false) => {}
        _ => {
            reasons.push("Freeze authority present - accounts can be frozen".to_string());
            amber += 1;
        }
    }

    if let Some(Value::Array(exts)) = info.get("extensions") {
        for ext in exts {
            match ext["extension"].as_str() {
                Some("transferHook") => {
                    reasons.push("Transfer hook - arbitrary code runs on every transfer".to_string());
                    red += 1;
                }
                Some("permanentDelegate") => {
                    reasons.push("Permanent delegate - third party can move your tokens".to_string());
                    red += 1;
                }
                Some("transferFeeConfig") => {
                    let bps = ext["state"]["newerTransferFee"]["transferFeeBasisPoints"]
                        .as_u64()
                        .unwrap_or(0);
                    if bps > 500 {
                        reasons.push(format!("High transfer fee: {}bps ({:.1}%)", bps, bps as f64 / 100.0));
                        amber += 1;
                    }
                }
                _ => {}
            }
        }
    }

    let level = if red > 0 {
        RiskLevel::Red
    } else if amber > 0 {
        RiskLevel::Amber
    } else {
        RiskLevel::Green
    };

    RiskReport { level, reasons }
}

pub fn analyze_concentration(raw: &str, report: &mut RiskReport) {
    let v: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return,
    };

    let accounts = match v["result"]["value"].as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return,
    };

    let total: f64 = accounts.iter().filter_map(|a| a["uiAmount"].as_f64()).sum();
    let top3: f64 = accounts.iter().take(3).filter_map(|a| a["uiAmount"].as_f64()).sum();

    if total > 0.0 {
        let pct = (top3 / total * 100.0).round() as u64;
        if pct > 70 {
            report.reasons.push(format!("Top 3 holders own {}% of supply", pct));
            if pct > 85 {
                report.level = RiskLevel::Red;
            } else if report.level == RiskLevel::Green {
                report.level = RiskLevel::Amber;
            }
        }
    }
}

pub fn analyze_metadata(raw: &str, report: &mut RiskReport) {
    let v: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return,
    };
    match v["result"]["content"]["json_uri"].as_str() {
        None | Some("") => {
            report.reasons.push("No metadata URI - anonymous token".to_string());
            if report.level == RiskLevel::Green {
                report.level = RiskLevel::Amber;
            }
        }
        _ => {}
    }
}
