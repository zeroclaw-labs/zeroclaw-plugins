//! Pure payment-settlement check. No wasm, no sockets: chain access goes
//! through [`HttpTransport`], mocked in host tests.
//!
//! Closes the loop opened by `solana-pay-request`. It watches the operator's
//! configured **recipient wallet** (always present in a payment, unlike the
//! Solana Pay `reference`, which some wallets omit) for a recent incoming
//! credit, optionally matching an expected amount. T0, read-only, zero
//! custody.

use std::collections::HashMap;

use zeroclaw_solana_core::amount::{format_base_units, parse_decimal_amount};
use zeroclaw_solana_core::pubkey::Pubkey;
use zeroclaw_solana_core::rpc::{
    get_account, get_signatures_for_address, get_transaction_credit, HttpTransport,
};
use zeroclaw_solana_core::token::parse_mint;

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const NATIVE_SOL: &str = "native";
const SOL_DECIMALS: u8 = 9;

#[derive(Debug)]
pub struct WatchConfig {
    pub rpc_url: String,
    /// The operator wallet whose incoming payments we watch.
    pub recipient: Pubkey,
    /// symbol (upper-case) → mint base58, or `native` for SOL.
    pub tokens: Vec<(String, String)>,
}

impl WatchConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let recipient = section
            .get("recipient")
            .filter(|v| !v.is_empty())
            .ok_or("config error: set `recipient` to the wallet whose payments to watch")?;
        let recipient =
            Pubkey::parse(recipient).map_err(|e| format!("config error: bad recipient: {e}"))?;
        let tokens = match section.get("tokens").filter(|v| !v.is_empty()) {
            Some(spec) => parse_token_list(spec)?,
            None => vec![
                ("USDC".to_string(), USDC_MINT.to_string()),
                ("SOL".to_string(), NATIVE_SOL.to_string()),
            ],
        };
        Ok(Self {
            rpc_url: section
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string()),
            recipient,
            tokens,
        })
    }
}

fn parse_token_list(spec: &str) -> Result<Vec<(String, String)>, String> {
    let mut tokens = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (symbol, mint) = entry
            .split_once(':')
            .ok_or_else(|| format!("config error: token entry {entry:?} is not SYMBOL:mint"))?;
        let mint = mint.trim();
        if mint != NATIVE_SOL {
            Pubkey::parse(mint).map_err(|e| format!("config error: token {symbol:?}: {e}"))?;
        }
        tokens.push((symbol.trim().to_ascii_uppercase(), mint.to_string()));
    }
    if tokens.is_empty() {
        return Err("config error: `tokens` is set but empty".to_string());
    }
    Ok(tokens)
}

pub struct WatchArgs {
    /// Expected amount to match (decimal string). When omitted, the most
    /// recent incoming payment of the token is reported.
    pub amount: Option<String>,
    /// Token symbol from the allowlist (default: first, usually USDC).
    pub token: Option<String>,
    /// Optional human note echoed back for context.
    pub label: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Paid,
    Pending,
}

#[derive(Debug)]
pub struct WatchResult {
    pub status: Status,
    pub text: String,
}

/// Watch the configured recipient wallet for a recent incoming payment.
pub fn check_payment<T: HttpTransport>(
    transport: &T,
    args: &WatchArgs,
    cfg: &WatchConfig,
) -> Result<WatchResult, String> {
    if args
        .label
        .as_deref()
        .is_some_and(|l| l.chars().count() > 128)
    {
        return Err("refused: label is too long".to_string());
    }
    if args.amount.as_deref().is_some_and(|a| a.len() > 40) {
        return Err("refused: amount is too long".to_string());
    }

    // Resolve the token → (mint pubkey or SOL) and its decimals.
    let symbol = args
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_ascii_uppercase)
        .unwrap_or_else(|| cfg.tokens[0].0.clone());
    let mint_spec = cfg
        .tokens
        .iter()
        .find(|(s, _)| *s == symbol)
        .map(|(_, m)| m.clone())
        .ok_or_else(|| format!("refused: token {symbol:?} is not in the operator allowlist"))?;

    let (mint, decimals) = if mint_spec == NATIVE_SOL {
        (None, SOL_DECIMALS)
    } else {
        let mint = Pubkey::parse(&mint_spec)?;
        let account = get_account(transport, &cfg.rpc_url, &mint)?
            .ok_or_else(|| format!("mint {mint} does not exist on this cluster"))?;
        let info = parse_mint(&account.data)?;
        (Some(mint), info.decimals)
    };

    let expected = match args
        .amount
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
    {
        Some(a) => Some(parse_decimal_amount(a, decimals)?),
        None => None,
    };

    let tag = args
        .label
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| format!(" ({l})"))
        .unwrap_or_default();

    // Scan recent transactions touching the recipient, newest first. Cap the
    // number of per-tx lookups: getTransaction is the heaviest, most
    // rate-limited RPC call, and the newest few transactions are what matter.
    let sigs = get_signatures_for_address(transport, &cfg.rpc_url, &cfg.recipient, 8)?;
    for sig in sigs.iter().filter(|s| !s.failed).take(5) {
        // A rate-limited or transient getTransaction skips this signature
        // rather than failing the whole check.
        let credit = match get_transaction_credit(
            transport,
            &cfg.rpc_url,
            &sig.signature,
            &cfg.recipient,
            mint.as_ref(),
        ) {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(_) => continue,
        };
        // If an amount was expected, require the payment to cover it.
        if let Some(exp) = expected {
            if credit.amount < exp {
                continue;
            }
        }
        let from = credit
            .payer
            .as_deref()
            .map(abbreviate)
            .map(|p| format!(" from {p}"))
            .unwrap_or_default();
        // One clickable artifact: the Solscan link already carries the full
        // signature, so we don't also print the bare signature on its own line.
        let text = format!(
            "✅ Payment received{tag}: {} {symbol}{from}.\nView on Solscan: {}",
            format_base_units(credit.amount, decimals),
            explorer_tx_url(&sig.signature),
        );
        return Ok(WatchResult {
            status: Status::Paid,
            text,
        });
    }

    let want = expected
        .map(|_| {
            format!(
                " of {} {symbol}",
                args.amount.as_deref().unwrap_or("").trim()
            )
        })
        .unwrap_or_default();
    Ok(WatchResult {
        status: Status::Pending,
        text: format!(
            "⏳ Not paid yet{tag}. No incoming payment{want} found at {}.",
            abbreviate(&cfg.recipient.to_base58())
        ),
    })
}

fn explorer_tx_url(signature: &str) -> String {
    format!("https://solscan.io/tx/{signature}")
}

fn abbreviate(s: &str) -> String {
    if s.len() <= 12 {
        return s.to_string();
    }
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}
