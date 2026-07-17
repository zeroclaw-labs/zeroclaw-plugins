//! Pure risk-analysis core. It consumes provider JSON supplied by the wasm shim;
//! there are no HTTP or WASM dependencies, so tests run on the host.

use serde_json::Value;

pub const MAX_OUTPUT_CHARS: usize = 1_150;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Green,
    Amber,
    Red,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Self::Green => "GREEN",
            Self::Amber => "AMBER",
            Self::Red => "RED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub verdict: Verdict,
    pub reasons: Vec<String>,
}

fn present(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(s)) => !s.is_empty() && s != "11111111111111111111111111111111",
        Some(Value::Null) | None => false,
        // RugCheck may return an authority-account object. Fail closed rather
        // than treating an unrecognised non-null shape as authority disabled.
        Some(_) => true,
    }
}

fn number(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .or_else(|| value.and_then(Value::as_str).and_then(|s| s.parse().ok()))
}

fn extension_names(helius: Option<&Value>, rugcheck: &Value) -> Vec<String> {
    let mut names: Vec<String> = helius
        .and_then(|v| v.pointer("/result/token_info/mint_extensions"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|x| {
                    x.get("extension")
                        .or_else(|| x.get("type"))
                        .and_then(Value::as_str)
                })
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default();
    if let Some(object) = rugcheck.get("token_extensions").and_then(Value::as_object) {
        names.extend(
            object
                .iter()
                .filter(|(_, value)| !value.is_null() && value.as_bool() != Some(false))
                .map(|(key, _)| key.to_ascii_lowercase()),
        );
    }
    names
}

pub fn assess(rugcheck: &Value, helius: Option<&Value>) -> Assessment {
    let mut red = Vec::new();
    let mut amber = Vec::new();
    let mint = rugcheck
        .get("mintAuthority")
        .or_else(|| rugcheck.pointer("/token/mintAuthority"));
    let freeze = rugcheck
        .get("freezeAuthority")
        .or_else(|| rugcheck.pointer("/token/freezeAuthority"));
    if present(mint) {
        red.push("mint authority remains active (supply can change)".to_string());
    }
    if present(freeze) {
        red.push("freeze authority remains active (accounts can be frozen)".to_string());
    }

    let holders = rugcheck.get("topHolders").and_then(Value::as_array);
    if let Some(holders) = holders {
        let top1 = number(holders.first().and_then(|h| h.get("pct"))).unwrap_or(0.0);
        let top5: f64 = holders
            .iter()
            .take(5)
            .filter_map(|h| number(h.get("pct")))
            .sum();
        if top1 >= 50.0 {
            red.push(format!("top holder controls {top1:.1}% of supply"));
        } else if top1 >= 20.0 {
            amber.push(format!("top holder controls {top1:.1}% of supply"));
        }
        if top5 >= 80.0 {
            red.push(format!("top 5 holders control {top5:.1}%"));
        } else if top5 >= 50.0 {
            amber.push(format!("top 5 holders control {top5:.1}%"));
        }
    } else {
        amber.push("holder concentration unavailable".to_string());
    }

    let locked = rugcheck
        .get("lockers")
        .and_then(Value::as_array)
        .map(|x| !x.is_empty())
        .unwrap_or(false);
    let liquidity = number(rugcheck.get("totalMarketLiquidity")).unwrap_or(0.0);
    if liquidity <= 0.0 {
        amber.push("no verified market liquidity".to_string());
    } else if locked { /* a reported locker satisfies the baseline LP-status check */
    } else {
        amber.push("liquidity is not reported as locked".to_string());
    }

    let exts = extension_names(helius, rugcheck);
    let token_2022 = rugcheck.get("tokenProgram").and_then(Value::as_str)
        == Some("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
    if token_2022 && exts.is_empty() {
        amber.push("Token-2022 extensions unverified (no Helius key)".to_string());
    }
    for (needle, text) in [
        ("transferhook", "Token-2022 transfer hook enabled"),
        ("transferfee", "Token-2022 transfer fees enabled"),
        ("permanentdelegate", "Token-2022 permanent delegate enabled"),
    ] {
        if exts
            .iter()
            .any(|e| e.replace(['-', '_', ' '], "").contains(needle))
        {
            red.push(text.to_string());
        }
    }

    let (verdict, reasons) = if !red.is_empty() {
        (Verdict::Red, red)
    } else if !amber.is_empty() {
        (Verdict::Amber, amber)
    } else {
        (
            Verdict::Green,
            vec![
                "mint and freeze authorities disabled".to_string(),
                "holder concentration and liquidity checks show no configured red flags"
                    .to_string(),
                "no flagged Token-2022 extension returned".to_string(),
            ],
        )
    };
    Assessment { verdict, reasons }
}

pub fn format(assessment: &Assessment, mint: &str) -> String {
    let mut out = format!(
        "{} — Solana token risk: {}\nMint: {}\n",
        assessment.verdict.label(),
        assessment.verdict.label(),
        mint
    );
    for reason in assessment.reasons.iter().take(6) {
        out.push_str("• ");
        out.push_str(reason);
        out.push('\n');
    }
    out.push_str("Read-only assessment; not financial advice.");
    out.chars().take(MAX_OUTPUT_CHARS).collect()
}

pub fn valid_mint(mint: &str) -> bool {
    (32..=44).contains(&mint.len()) && mint.bytes().all(|b| b.is_ascii_alphanumeric())
}
