//! Pure risk-analysis core for SPL / Token-2022 mints.
//!
//! No wasm, no network, no clocks: the caller supplies JSON blobs that were
//! fetched elsewhere (e.g. by the host's HTTP tool from a Solana RPC node) and
//! this module turns them into a structured risk report. Everything here is
//! host-testable with a plain `cargo test`.

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 5,
            Severity::Medium => 12,
            Severity::High => 25,
            Severity::Critical => 40,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct RiskReport {
    /// 0 (clean) .. 100 (do not touch).
    pub score: u32,
    pub level: &'static str,
    pub token_program: String,
    pub findings: Vec<Finding>,
    /// Data sections that were absent, so the model knows the report is partial.
    pub missing_inputs: Vec<&'static str>,
    pub summary: String,
    /// Same report rendered as markdown for direct inclusion in agent replies.
    pub summary_markdown: String,
}

/// Analyze a mint. `mint_account` is the jsonParsed account (tolerates the
/// whole RPC response, `result.value`, or the bare `value`). Optional:
/// `largest_accounts` (RPC getTokenLargestAccounts value array) and `supply`
/// (RPC getTokenSupply value object or raw amount string/number).
pub fn analyze(
    mint_account: &Value,
    largest_accounts: Option<&Value>,
    supply: Option<&Value>,
    metadata: Option<&Value>,
) -> Result<RiskReport, String> {
    let (program, parsed) = extract_parsed(mint_account)
        .ok_or_else(|| "mint_account is not a jsonParsed SPL mint account".to_string())?;

    if parsed.get("type").and_then(Value::as_str) != Some("mint") {
        return Err("account is not a mint (expected parsed.type == \"mint\")".to_string());
    }
    let info = parsed
        .get("info")
        .ok_or_else(|| "malformed jsonParsed mint: missing info".to_string())?;

    let mut findings: Vec<Finding> = Vec::new();
    let mut missing: Vec<&'static str> = Vec::new();

    // ── Authorities ─────────────────────────────────────────────────────────
    if let Some(auth) = non_null_str(info, "mintAuthority") {
        findings.push(Finding {
            id: "mint_authority_active",
            severity: Severity::High,
            title: "Mint authority is still active".into(),
            detail: format!(
                "{} can mint unlimited new tokens and dilute every holder.",
                display_pubkey(&auth)
            ),
        });
    }
    if let Some(auth) = non_null_str(info, "freezeAuthority") {
        findings.push(Finding {
            id: "freeze_authority_active",
            severity: Severity::High,
            title: "Freeze authority is still active".into(),
            detail: format!(
                "{} can freeze any holder's token account, blocking transfers and sales.",
                display_pubkey(&auth)
            ),
        });
    }

    // ── Token-2022 extensions ───────────────────────────────────────────────
    if program == "spl-token-2022" {
        findings.push(Finding {
            id: "token_2022",
            severity: Severity::Info,
            title: "Token-2022 mint".into(),
            detail: "Extensions below can change transfer behavior; review each one.".into(),
        });
    }
    for ext in info
        .get("extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        analyze_extension(ext, &mut findings);
    }

    // ── Holder concentration ────────────────────────────────────────────────
    let supply_raw = supply.and_then(extract_amount);
    match (largest_accounts, supply_raw) {
        (Some(largest), Some(total)) if total > 0.0 => {
            let list = largest
                .pointer("/value")
                .and_then(Value::as_array)
                .or_else(|| largest.as_array());
            if let Some(accounts) = list {
                let mut amounts: Vec<f64> = accounts.iter().filter_map(extract_amount).collect();
                amounts.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
                if let Some(top1) = amounts.first() {
                    let p1 = top1 / total * 100.0;
                    if p1 >= 30.0 {
                        findings.push(concentration(
                            "top1_concentration",
                            Severity::High,
                            format!("Largest holder controls {p1:.1}% of supply"),
                        ));
                    } else if p1 >= 15.0 {
                        findings.push(concentration(
                            "top1_concentration",
                            Severity::Medium,
                            format!("Largest holder controls {p1:.1}% of supply"),
                        ));
                    }
                }
                let top10: f64 = amounts.iter().take(10).sum();
                let p10 = top10 / total * 100.0;
                if p10 >= 60.0 {
                    findings.push(concentration(
                        "top10_concentration",
                        Severity::High,
                        format!("Top 10 holders control {p10:.1}% of supply"),
                    ));
                } else if p10 >= 40.0 {
                    findings.push(concentration(
                        "top10_concentration",
                        Severity::Medium,
                        format!("Top 10 holders control {p10:.1}% of supply"),
                    ));
                }
            }
        }
        _ => missing.push("largest_accounts+supply (holder concentration not checked)"),
    }

    // ── Metadata ────────────────────────────────────────────────────────────
    match metadata {
        Some(md) => {
            let mutable = md.get("isMutable").and_then(Value::as_bool).unwrap_or(true);
            if mutable {
                if let Some(ua) = non_null_str(md, "updateAuthority") {
                    findings.push(Finding {
                        id: "mutable_metadata",
                        severity: Severity::Low,
                        title: "Metadata is mutable".into(),
                        detail: format!(
                            "{} can rename the token or swap its image/URI at any time.",
                            display_pubkey(&ua)
                        ),
                    });
                }
            }
        }
        None => missing.push("metadata (name/image rug checks not run)"),
    }

    // ── Score ───────────────────────────────────────────────────────────────
    let score: u32 = findings
        .iter()
        .map(|f| f.severity.weight())
        .sum::<u32>()
        .min(100);
    let level = match score {
        0 => "clean",
        1..=14 => "low",
        15..=39 => "medium",
        40..=69 => "high",
        _ => "critical",
    };
    let worst = findings.iter().map(|f| f.severity).max();
    let summary = match worst {
        None => "No risk flags found in the provided data.".to_string(),
        Some(w) => format!(
            "{} finding(s), worst severity {:?}; risk score {}/100 ({}).",
            findings.len(),
            w,
            score,
            level
        ),
    };
    let summary_markdown = render_markdown(score, level, &findings, &missing);

    Ok(RiskReport {
        score,
        level,
        token_program: program,
        findings,
        missing_inputs: missing,
        summary,
        summary_markdown,
    })
}

fn render_markdown(score: u32, level: &str, findings: &[Finding], missing: &[&str]) -> String {
    let mut md = format!("### Token risk: {score}/100 ({level})\n");
    if findings.is_empty() {
        md.push_str("\nNo risk flags found in the provided data.\n");
    } else {
        for f in findings {
            md.push_str(&format!(
                "- **[{}] {}** — {}\n",
                f.severity.label(),
                f.title,
                f.detail
            ));
        }
    }
    if !missing.is_empty() {
        md.push_str(&format!("\n_Not checked: {}._\n", missing.join("; ")));
    }
    md
}

fn analyze_extension(ext: &Value, findings: &mut Vec<Finding>) {
    let name = ext.get("extension").and_then(Value::as_str).unwrap_or("");
    let state = ext.get("state").unwrap_or(&Value::Null);
    match name {
        "permanentDelegate" => {
            let who = non_null_str(state, "delegate")
                .map(|d| display_pubkey(&d))
                .unwrap_or_else(|| "an authority".into());
            findings.push(Finding {
                id: "permanent_delegate",
                severity: Severity::Critical,
                title: "Permanent delegate can seize tokens".into(),
                detail: format!(
                    "{who} can transfer or burn tokens FROM ANY WALLET without consent."
                ),
            });
        }
        "transferHook" => {
            if let Some(pid) = non_null_str(state, "programId") {
                findings.push(Finding {
                    id: "transfer_hook",
                    severity: Severity::High,
                    title: "Transfer hook program attached".into(),
                    detail: format!(
                        "Program {} runs on every transfer and can block sells (honeypot pattern).",
                        display_pubkey(&pid)
                    ),
                });
            }
        }
        "pausableConfig" => {
            if state
                .get("paused")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                findings.push(Finding {
                    id: "transfers_paused",
                    severity: Severity::Critical,
                    title: "Transfers are currently paused".into(),
                    detail: "The pause authority has halted all transfers; nobody can move \
                             or sell this token until it is unpaused."
                        .into(),
                });
            } else {
                findings.push(Finding {
                    id: "pausable",
                    severity: Severity::High,
                    title: "Issuer can pause all transfers".into(),
                    detail: "A pause authority can halt every transfer at any moment, \
                             trapping holders (exit-blocking pattern)."
                        .into(),
                });
            }
        }
        "confidentialTransferMint" => {
            findings.push(Finding {
                id: "confidential_transfers",
                severity: Severity::Medium,
                title: "Confidential transfers enabled".into(),
                detail: "Balances and flows can be hidden, so holder-concentration and \
                         volume analysis may be blind to the real distribution."
                    .into(),
            });
        }
        "interestBearingConfig" => {
            let rate = state
                .get("currentRate")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if rate != 0 {
                findings.push(Finding {
                    id: "interest_bearing_display",
                    severity: Severity::Low,
                    title: format!("Interest-bearing display rate of {rate} bps"),
                    detail: "The displayed balance grows without any tokens being minted; \
                             UI amounts overstate what is actually redeemable."
                        .into(),
                });
            }
        }
        "scaledUiAmountConfig" => {
            findings.push(Finding {
                id: "scaled_ui_amount",
                severity: Severity::Medium,
                title: "Scaled UI amount multiplier".into(),
                detail: "Displayed balances are multiplied by an issuer-controlled factor, \
                         so wallets can show amounts that do not match on-chain reality."
                    .into(),
            });
        }
        "defaultAccountState" => {
            if state.get("accountState").and_then(Value::as_str) == Some("frozen") {
                findings.push(Finding {
                    id: "default_frozen",
                    severity: Severity::Critical,
                    title: "New token accounts start frozen".into(),
                    detail: "Buyers cannot move tokens until the issuer thaws them.".into(),
                });
            }
        }
        "transferFeeConfig" => {
            let bps = state
                .pointer("/newerTransferFee/transferFeeBasisPoints")
                .or_else(|| state.pointer("/olderTransferFee/transferFeeBasisPoints"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if bps > 0 {
                let sev = if bps >= 500 {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(Finding {
                    id: "transfer_fee",
                    severity: sev,
                    title: format!("Transfer fee of {bps} bps on every transfer"),
                    detail: format!("Each transfer is taxed {:.2}%.", bps as f64 / 100.0),
                });
            }
        }
        "mintCloseAuthority" => {
            if non_null_str(state, "closeAuthority").is_some() {
                findings.push(Finding {
                    id: "mint_close_authority",
                    severity: Severity::Medium,
                    title: "Mint can be closed by its authority".into(),
                    detail: "A closed mint address can later be re-created, enabling spoofing."
                        .into(),
                });
            }
        }
        "nonTransferable" => {
            findings.push(Finding {
                id: "non_transferable",
                severity: Severity::Medium,
                title: "Token is non-transferable (soulbound)".into(),
                detail: "It can never be sold or moved to another wallet.".into(),
            });
        }
        _ => {}
    }
}

fn concentration(id: &'static str, severity: Severity, title: String) -> Finding {
    Finding {
        id,
        severity,
        title,
        detail: "Concentrated supply lets a few wallets dump on the market at will. \
                 Note: large holders can be exchanges, LPs, or escrows — verify before concluding."
            .into(),
    }
}

/// Accept the whole RPC envelope, `result.value`, or the bare account value.
fn extract_parsed(v: &Value) -> Option<(String, &Value)> {
    for candidate in [
        v.pointer("/result/value/data"),
        v.pointer("/value/data"),
        v.pointer("/data"),
        v.pointer("/account/data"),
    ]
    .into_iter()
    .flatten()
    {
        if let (Some(program), Some(parsed)) = (
            candidate.get("program").and_then(Value::as_str),
            candidate.get("parsed"),
        ) {
            if program.starts_with("spl-token") {
                return Some((program.to_string(), parsed));
            }
        }
    }
    None
}

/// Echo an authority-shaped field only if it actually looks like a pubkey.
///
/// Chain data is attacker-controlled: a hostile mint can put arbitrary prose in
/// any string field. Base58 (Bitcoin alphabet) pubkeys are 32–44 chars with no
/// spaces, so anything else is withheld rather than quoted back to the model.
fn display_pubkey(s: &str) -> String {
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if (32..=44).contains(&s.len()) && s.chars().all(|c| BASE58.contains(c)) {
        format!("`{s}`")
    } else {
        "an address withheld from this report (field is not a valid base58 pubkey)".to_string()
    }
}

fn non_null_str(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Pull a token amount out of getTokenSupply/getTokenLargestAccounts entries.
fn extract_amount(v: &Value) -> Option<f64> {
    for candidate in [v.pointer("/value/amount"), v.pointer("/amount"), Some(v)]
        .into_iter()
        .flatten()
    {
        match candidate {
            Value::String(s) => {
                if let Ok(n) = s.parse::<f64>() {
                    return Some(n);
                }
            }
            Value::Number(n) => return n.as_f64(),
            _ => {}
        }
    }
    v.pointer("/uiAmount").and_then(Value::as_f64)
}
