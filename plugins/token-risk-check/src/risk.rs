//! Pure mint risk assessment. No wasm, no sockets: chain access goes through
//! [`HttpTransport`], mocked in host tests.
//!
//! Given a mint, produce a red/amber/green verdict **with reasons**, from:
//! - authorities: an active mint authority can inflate supply, an active
//!   freeze authority can freeze any holder's account;
//! - Token-2022 extensions: permanent delegates can seize tokens, transfer
//!   hooks can block or tax transfers, default-frozen state strands buyers,
//!   transfer fees skim every hop;
//! - holder concentration from `getTokenLargestAccounts`.
//!
//! The report is deliberately shaped to a few hundred characters: this tool
//! exists to be called before every other Solana tool, so it must never cost
//! an operator a context window. Raw RPC responses die here.

use std::collections::HashMap;

use zeroclaw_solana_core::amount::format_base_units;
use zeroclaw_solana_core::pubkey::{token_2022_program, token_program, Pubkey};
use zeroclaw_solana_core::rpc::{get_account, get_token_largest_accounts, HttpTransport};
use zeroclaw_solana_core::token::{parse_mint, Extension};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

pub struct RiskConfig {
    pub rpc_url: String,
}

impl RiskConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        Self {
            rpc_url: section
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Verdict {
    Green,
    Amber,
    Red,
}

impl Verdict {
    fn as_str(&self) -> &'static str {
        match self {
            Verdict::Green => "GREEN",
            Verdict::Amber => "AMBER",
            Verdict::Red => "RED",
        }
    }
}

#[derive(Debug)]
pub struct RiskReport {
    pub verdict: Verdict,
    pub text: String,
}

/// Basis-point share of `part` in `total`, saturating, integer-only.
fn share_bps(part: u128, total: u128) -> u64 {
    if total == 0 {
        return 0;
    }
    ((part * 10_000) / total).min(10_000) as u64
}

/// Render basis points as a percentage with both decimal places, so 9999bps
/// reads "99.99%" rather than being truncated to "99.9%".
fn fmt_pct(bps: u64) -> String {
    format!("{}.{:02}%", bps / 100, bps % 100)
}

/// Assess `mint` and shape the result for an LLM context window.
pub fn assess_mint<T: HttpTransport>(
    transport: &T,
    mint_addr: &str,
    cfg: &RiskConfig,
) -> Result<RiskReport, String> {
    let mint = Pubkey::parse(mint_addr)?;
    let account = get_account(transport, &cfg.rpc_url, &mint)?
        .ok_or_else(|| format!("{mint} does not exist on this cluster"))?;

    let (program_label, is_2022) = if account.owner == token_program() {
        ("SPL Token", false)
    } else if account.owner == token_2022_program() {
        ("Token-2022", true)
    } else {
        return Err(format!(
            "{mint} is not a token mint (owned by {})",
            account.owner
        ));
    };
    let info = parse_mint(&account.data)?;

    let mut red: Vec<String> = Vec::new();
    let mut amber: Vec<String> = Vec::new();

    if info.extensions_truncated {
        red.push(
            "malformed mint: extension list is oversized or padded with duplicates \
             (possible hostile RPC); results below may be incomplete"
                .to_string(),
        );
    }
    if info.mint_authority.is_some() {
        amber.push("mint authority active: supply can be inflated at will".to_string());
    }
    if info.freeze_authority.is_some() {
        amber.push("freeze authority active: any holder's account can be frozen".to_string());
    }

    for ext in &info.extensions {
        match ext {
            Extension::PermanentDelegate { delegate } => red.push(format!(
                "permanent delegate {}: can transfer or burn ANY holder's tokens",
                abbreviate(&delegate.to_base58())
            )),
            Extension::TransferHook { program_id } => red.push(match program_id {
                Some(hook) => format!(
                    "transfer hook {}: every transfer runs third-party code that can block or tax it",
                    abbreviate(&hook.to_base58())
                ),
                None => "transfer hook extension present".to_string(),
            }),
            Extension::NonTransferable => {
                red.push("non-transferable: tokens cannot be moved or sold".to_string())
            }
            Extension::DefaultAccountState { frozen: true } => red.push(
                "new accounts start FROZEN: buyers cannot use tokens until unfrozen".to_string(),
            ),
            Extension::TransferFee { basis_points, .. } if *basis_points > 0 => {
                let msg = format!("transfer fee of {}bps on every transfer", basis_points);
                if *basis_points >= 500 {
                    red.push(msg);
                } else {
                    amber.push(msg);
                }
            }
            Extension::MintCloseAuthority => {
                amber.push("mint close authority: the mint account can be closed".to_string())
            }
            Extension::Pausable => {
                amber.push("pausable: all transfers can be suspended".to_string())
            }
            Extension::InterestBearing => {
                amber.push("interest-bearing: displayed balances rebase over time".to_string())
            }
            _ => {}
        }
    }

    // Holder concentration. Largest-accounts lookup is best-effort: a node
    // that refuses it (some throttle heavily) degrades the report, never
    // fails it.
    let concentration = match get_token_largest_accounts(transport, &cfg.rpc_url, &mint) {
        Ok(holders) if !holders.is_empty() && info.supply > 0 => {
            let supply = info.supply as u128;
            let top1 = share_bps(holders[0].base_units as u128, supply);
            let top5: u128 = holders.iter().take(5).map(|h| h.base_units as u128).sum();
            let top5 = share_bps(top5, supply);
            if top1 >= 5_000 {
                red.push(format!("one account holds {} of supply", fmt_pct(top1)));
            } else if top5 >= 7_000 {
                amber.push(format!("top 5 accounts hold {} of supply", fmt_pct(top5)));
            }
            format!(
                "Top holders: #1 holds {}, top 5 hold {} of supply.",
                fmt_pct(top1),
                fmt_pct(top5)
            )
        }
        Ok(_) => "Top holders: unavailable (empty result or zero supply).".to_string(),
        Err(_) => "Top holders: unavailable from this RPC.".to_string(),
    };

    if info.supply == 0 {
        amber.push("supply is zero".to_string());
    }

    let verdict = if !red.is_empty() {
        Verdict::Red
    } else if !amber.is_empty() {
        Verdict::Amber
    } else {
        Verdict::Green
    };

    fn plural(n: usize, word: &str) -> String {
        format!("{n} {word}{}", if n == 1 { "" } else { "s" })
    }
    let glyph = match &verdict {
        Verdict::Red => "🔴",
        Verdict::Amber => "🟡",
        Verdict::Green => "🟢",
    };
    let mut text = format!(
        "{glyph} RISK: {} — {}, {}\nMint {} ({program_label}, {} decimals, supply {}{})\n",
        verdict.as_str(),
        plural(red.len(), "red flag"),
        plural(amber.len(), "warning"),
        abbreviate(&mint.to_base58()),
        info.decimals,
        format_base_units(info.supply, info.decimals),
        if is_2022 && info.extensions.is_empty() { ", no extensions" } else { "" },
    );
    for flag in &red {
        text.push_str(&format!("RED: {flag}\n"));
    }
    for warn in &amber {
        text.push_str(&format!("WARN: {warn}\n"));
    }
    if verdict == Verdict::Green {
        text.push_str(
            "No mint/freeze authority, no risky extensions detected. \
             (Not a guarantee: LP status and off-chain factors are not checked.)\n",
        );
    }
    text.push_str(&concentration);
    text.push_str(&format!(
        "\nExplorer: {}",
        zeroclaw_solana_core::links::explorer_token_url(&mint.to_base58())
    ));

    // Belt-and-suspenders: the extension cap already bounds this, but never
    // hand the agent an oversized report even if a future field regresses.
    const MAX_REPORT_CHARS: usize = 2000;
    if text.chars().count() > MAX_REPORT_CHARS {
        text = text.chars().take(MAX_REPORT_CHARS).collect::<String>() + "\n…(report truncated)";
    }

    Ok(RiskReport { verdict, text })
}

fn abbreviate(addr: &str) -> String {
    if addr.len() <= 12 {
        return addr.to_string();
    }
    format!("{}…{}", &addr[..4], &addr[addr.len() - 4..])
}
