//! Pure Solana account/wallet overview. No wasm, no sockets: all chain access
//! goes through [`HttpTransport`], mocked in host tests. T0, read-only, zero
//! custody — the tool holds no keys and moves nothing.
//!
//! Given an address, it shapes a few on-chain reads (SOL balance + account
//! type, SPL token holdings, recent activity) into a ~200-token summary the
//! agent can read out, rather than dumping raw RPC JSON into its context.

use std::collections::HashMap;

use zeroclaw_solana_core::amount::format_base_units;
use zeroclaw_solana_core::links::explorer_account_url;
use zeroclaw_solana_core::pubkey::Pubkey;
use zeroclaw_solana_core::rpc::{
    get_account, get_signatures_for_address, get_token_accounts_by_owner, HttpTransport,
    TokenHolding,
};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
/// The System Program owns ordinary wallet accounts.
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const SOL_DECIMALS: u8 = 9;
const DEFAULT_MAX_TOKENS: usize = 6;
/// How many recent signatures to sample for the activity line.
const ACTIVITY_SAMPLE: u64 = 10;

/// Policy resolved from the plugin's own config section.
pub struct AccountConfig {
    pub rpc_url: String,
    /// How many token holdings to list before summarizing the rest.
    pub max_tokens: usize,
    /// mint base58 → SYMBOL, so well-known mints read nicely instead of as raw
    /// addresses. Seeded with a few mainnet stablecoins; operator-extensible.
    pub known_mints: Vec<(String, String)>,
}

impl AccountConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let mut known_mints = vec![
            (
                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
                "USDC".to_string(),
            ),
            (
                "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string(),
                "USDT".to_string(),
            ),
            (
                "So11111111111111111111111111111111111111112".to_string(),
                "wSOL".to_string(),
            ),
        ];
        if let Some(spec) = section.get("known_mints").filter(|v| !v.is_empty()) {
            for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                if let Some((mint, sym)) = entry.split_once(':') {
                    let sym = sym.trim();
                    if !mint.trim().is_empty() && !sym.is_empty() {
                        known_mints.push((mint.trim().to_string(), sym.to_ascii_uppercase()));
                    }
                }
            }
        }
        Self {
            rpc_url: section
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string()),
            max_tokens: section
                .get("max_tokens")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|n| *n > 0 && *n <= 20)
                .unwrap_or(DEFAULT_MAX_TOKENS),
            known_mints,
        }
    }
}

pub struct AccountArgs {
    /// The address to read (base58). Names (`.sol`) are out of scope — resolve
    /// them with `sns-resolve` first, then pass the derived address here.
    pub address: String,
}

#[derive(Debug)]
pub struct Brief {
    pub text: String,
}

/// Read an address's on-chain state and shape it into a short human summary.
pub fn account_brief<T: HttpTransport>(
    transport: &T,
    args: &AccountArgs,
    cfg: &AccountConfig,
) -> Result<Brief, String> {
    let addr = args.address.trim();
    // Bound the input before it can be echoed into an error (a base58 pubkey is
    // at most 44 chars); this keeps output size independent of caller input.
    if addr.len() > 64 {
        return Err("refused: address is too long".to_string());
    }
    let address =
        Pubkey::parse(addr).map_err(|e| format!("refused: not a valid Solana address: {e}"))?;
    let b58 = address.to_base58();

    // 1) Existence + SOL balance + account type (one read).
    let account = get_account(transport, &cfg.rpc_url, &address)?;
    let (sol_line, kind) = match &account {
        None => (
            "◎ SOL balance: 0 (account not found — never funded)".to_string(),
            "unused".to_string(),
        ),
        Some(a) => {
            let kind = if a.owner.to_base58() == SYSTEM_PROGRAM {
                "wallet".to_string()
            } else {
                format!("program-owned ({})", abbreviate(&a.owner.to_base58()))
            };
            (
                format!("◎ SOL balance: {}", format_base_units(a.lamports, SOL_DECIMALS)),
                kind,
            )
        }
    };

    // 2) SPL token holdings — only meaningful for an existing account. A token
    //    read failure is tolerated (line omitted) rather than failing the brief.
    let tokens_line = if account.is_some() {
        match get_token_accounts_by_owner(transport, &cfg.rpc_url, &address) {
            Ok(h) if !h.is_empty() => Some(format_holdings(&h, cfg)),
            Ok(_) => Some("Tokens: none".to_string()),
            Err(_) => None,
        }
    } else {
        None
    };

    // 3) Recent activity — best-effort; omitted if the RPC declines.
    let activity_line =
        match get_signatures_for_address(transport, &cfg.rpc_url, &address, ACTIVITY_SAMPLE) {
            Ok(sigs) if !sigs.is_empty() => {
                let ok = sigs.iter().filter(|s| !s.failed).count();
                let latest = sigs
                    .first()
                    .map(|s| s.confirmation.as_str())
                    .filter(|c| !c.is_empty())
                    .unwrap_or("confirmed");
                Some(format!(
                    "Recent activity: {ok}/{} recent txns succeeded (latest: {latest})",
                    sigs.len()
                ))
            }
            Ok(_) => Some("Recent activity: none".to_string()),
            Err(_) => None,
        };

    let mut text = format!("📇 Account {} — {kind}\n{sol_line}\n", abbreviate(&b58));
    if let Some(t) = tokens_line {
        text.push_str(&t);
        text.push('\n');
    }
    if let Some(a) = activity_line {
        text.push_str(&a);
        text.push('\n');
    }
    text.push_str(&format!("Explorer: {}", explorer_account_url(&b58)));

    Ok(Brief { text })
}

fn format_holdings(holdings: &[TokenHolding], cfg: &AccountConfig) -> String {
    let shown: Vec<String> = holdings
        .iter()
        .take(cfg.max_tokens)
        .map(|h| {
            let label = cfg
                .known_mints
                .iter()
                .find(|(m, _)| *m == h.mint)
                .map(|(_, s)| s.clone())
                .unwrap_or_else(|| abbreviate(&h.mint));
            format!("{} {label}", format_base_units(h.amount, h.decimals))
        })
        .collect();
    let more = holdings.len().saturating_sub(cfg.max_tokens);
    let suffix = if more > 0 {
        format!(", +{more} more")
    } else {
        String::new()
    };
    format!("Tokens ({}): {}{suffix}", holdings.len(), shown.join(", "))
}

fn abbreviate(s: &str) -> String {
    if s.len() <= 12 {
        return s.to_string();
    }
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}
