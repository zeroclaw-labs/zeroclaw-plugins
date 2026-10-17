//! Pure risk-scoring core. No wit-bindgen or wasm/http dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through `lib.rs`, feeding it real
//! `getAccountInfo` / `getTokenLargestAccounts` JSON pulled over `wasi:http`.
//!
//! Everything here is read-only analysis of data already fetched by the
//! shim. This module never makes a network call and never holds a key.

use serde_json::Value;

/// A single Token-2022 extension present on the mint, as reported by the
/// RPC's `jsonParsed` encoding: `{"extension": "...", "state": {...}}`.
#[derive(Debug, Clone)]
pub struct Extension {
    pub name: String,
    pub state: Value,
}

/// Parsed mint account info, shared by classic SPL Token and Token-2022
/// mints (the latter additionally carries `extensions`).
#[derive(Debug, Clone)]
pub struct MintInfo {
    pub decimals: u8,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub supply: u128,
    pub extensions: Vec<Extension>,
}

impl MintInfo {
    pub fn extension(&self, name: &str) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.name == name)
    }
}

/// Parse a `getAccountInfo` (`encoding: "jsonParsed"`) RPC response body into
/// a [`MintInfo`]. Returns an error string (never panics) on anything
/// malformed or on an account that isn't a parsed mint — including the
/// common "mint doesn't exist" case, which surfaces as `result.value: null`.
pub fn parse_mint_info(rpc_response: &Value) -> Result<MintInfo, String> {
    let value = rpc_response
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or("malformed RPC response: missing result.value")?;

    if value.is_null() {
        return Err("account not found — is this a valid mint address?".to_string());
    }

    let parsed = value
        .get("data")
        .and_then(|d| d.get("parsed"))
        .ok_or("account data is not jsonParsed (wrong program owner, or not a mint)")?;

    if parsed.get("type").and_then(Value::as_str) != Some("mint") {
        return Err("account exists but is not a mint".to_string());
    }

    let info = parsed
        .get("info")
        .ok_or("malformed RPC response: missing parsed.info")?;

    let decimals = info
        .get("decimals")
        .and_then(Value::as_u64)
        .ok_or("malformed RPC response: missing decimals")? as u8;

    let supply = info
        .get("supply")
        .and_then(Value::as_str)
        .ok_or("malformed RPC response: missing supply")?
        .parse::<u128>()
        .map_err(|e| format!("malformed supply value: {e}"))?;

    let mint_authority = info
        .get("mintAuthority")
        .and_then(Value::as_str)
        .map(str::to_string);
    let freeze_authority = info
        .get("freezeAuthority")
        .and_then(Value::as_str)
        .map(str::to_string);

    let extensions = info
        .get("extensions")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let name = e.get("extension")?.as_str()?.to_string();
                    let state = e.get("state").cloned().unwrap_or(Value::Null);
                    Some(Extension { name, state })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(MintInfo {
        decimals,
        mint_authority,
        freeze_authority,
        supply,
        extensions,
    })
}

/// Concentration of supply held by the largest accounts, from
/// `getTokenLargestAccounts` (which returns at most the top 20).
#[derive(Debug, Clone, Copy)]
pub struct HolderConcentration {
    pub top1_pct: f64,
    pub top10_pct: f64,
}

/// Compute holder concentration from a `getTokenLargestAccounts` response and
/// the mint's total supply (raw base units, matching the `amount` field).
pub fn compute_holder_concentration(
    rpc_response: &Value,
    supply: u128,
) -> Result<HolderConcentration, String> {
    if supply == 0 {
        return Err("supply is zero — cannot compute concentration".to_string());
    }

    let accounts = rpc_response
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(Value::as_array)
        .ok_or("malformed RPC response: missing result.value array")?;

    let amounts: Vec<u128> = accounts
        .iter()
        .filter_map(|a| a.get("amount")?.as_str()?.parse::<u128>().ok())
        .collect();

    let top1: u128 = amounts.first().copied().unwrap_or(0);
    let top10: u128 = amounts.iter().take(10).sum();

    Ok(HolderConcentration {
        top1_pct: (top1 as f64 / supply as f64) * 100.0,
        top10_pct: (top10 as f64 / supply as f64) * 100.0,
    })
}

/// Overall verdict. Ordered by severity: a single Red reason makes the whole
/// report Red regardless of how many Green checks passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Green,
    Amber,
    Red,
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Green => "GREEN",
            Verdict::Amber => "AMBER",
            Verdict::Red => "RED",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Verdict::Green => "🟢",
            Verdict::Amber => "🟡",
            Verdict::Red => "🔴",
        }
    }
}

/// One risk finding: its own severity plus a human-readable reason.
#[derive(Debug, Clone)]
pub struct Finding {
    pub verdict: Verdict,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RiskReport {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

const CONCENTRATION_RED_PCT: f64 = 50.0;
const CONCENTRATION_AMBER_PCT: f64 = 20.0;

/// Run every check against a parsed mint (plus optional holder-concentration
/// and LP-liquidity data, both best-effort and independently omittable) and
/// return the worst verdict found, with every reason that contributed.
pub fn assess(
    mint: &MintInfo,
    holders: Option<HolderConcentration>,
    lp_active: Option<bool>,
) -> RiskReport {
    let mut findings = Vec::new();

    if let Some(delegate_ext) = mint.extension("permanentDelegate") {
        let delegate = delegate_ext
            .state
            .get("delegate")
            .and_then(Value::as_str)
            .unwrap_or("unknown address");
        findings.push(Finding {
            verdict: Verdict::Red,
            reason: format!(
                "permanent delegate ({delegate}) can transfer or burn any holder's tokens without consent"
            ),
        });
    }

    if mint.extension("nonTransferable").is_some() {
        findings.push(Finding {
            verdict: Verdict::Red,
            reason: "token is non-transferable (soulbound) — cannot be sold or moved".to_string(),
        });
    }

    if let Some(state_ext) = mint.extension("defaultAccountState") {
        let frozen = state_ext
            .state
            .get("state")
            .and_then(Value::as_str)
            .map(|s| s.eq_ignore_ascii_case("frozen"))
            .unwrap_or(false);
        if frozen {
            findings.push(Finding {
                verdict: Verdict::Red,
                reason: "new token accounts are frozen by default — transfers require the freeze authority to thaw first".to_string(),
            });
        }
    }

    if let Some(hook_ext) = mint.extension("transferHook") {
        let program = hook_ext
            .state
            .get("programId")
            .and_then(Value::as_str)
            .unwrap_or("unknown program");
        findings.push(Finding {
            verdict: Verdict::Amber,
            reason: format!(
                "transfer hook ({program}) runs custom logic on every transfer — inspect the hook program before trusting transfers"
            ),
        });
    }

    if let Some(fee_ext) = mint.extension("transferFeeConfig") {
        let bps = fee_ext
            .state
            .get("newerTransferFee")
            .and_then(|f| f.get("transferFeeBasisPoints"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if bps > 0 {
            findings.push(Finding {
                verdict: Verdict::Amber,
                reason: format!("transfer fee extension charges {:.2}% on every transfer", bps as f64 / 100.0),
            });
        }
    }

    if mint.mint_authority.is_some() {
        findings.push(Finding {
            verdict: Verdict::Amber,
            reason: "mint authority is still active — supply can be inflated at any time".to_string(),
        });
    }

    if mint.freeze_authority.is_some() {
        findings.push(Finding {
            verdict: Verdict::Amber,
            reason: "freeze authority is still active — individual holder accounts can be frozen".to_string(),
        });
    }

    if let Some(h) = holders {
        if h.top1_pct >= CONCENTRATION_RED_PCT {
            findings.push(Finding {
                verdict: Verdict::Red,
                reason: format!("top holder controls {:.1}% of supply", h.top1_pct),
            });
        } else if h.top1_pct >= CONCENTRATION_AMBER_PCT || h.top10_pct >= 70.0 {
            findings.push(Finding {
                verdict: Verdict::Amber,
                reason: format!(
                    "concentrated holdings: top holder {:.1}%, top 10 {:.1}% of supply",
                    h.top1_pct, h.top10_pct
                ),
            });
        }
    }

    if lp_active == Some(false) {
        findings.push(Finding {
            verdict: Verdict::Amber,
            reason: "no active liquidity route found — token may be illiquid or unswappable".to_string(),
        });
    }

    let verdict = findings
        .iter()
        .map(|f| f.verdict)
        .max()
        .unwrap_or(Verdict::Green);

    if findings.is_empty() {
        findings.push(Finding {
            verdict: Verdict::Green,
            reason: "no elevated risk factors found: no mint/freeze authority, no dangerous extensions, distributed holders".to_string(),
        });
    }

    RiskReport { verdict, findings }
}

/// Shape the report into short text for the LLM/chat surface — a verdict
/// line plus a bulleted reason list, not a JSON dump of everything fetched.
pub fn format_report(mint_address: &str, report: &RiskReport) -> String {
    let mut out = format!(
        "{} {} — {}\n",
        report.verdict.emoji(),
        report.verdict.label(),
        mint_address
    );
    for f in &report.findings {
        out.push_str(&format!("- {}\n", f.reason));
    }
    out.trim_end().to_string()
}

