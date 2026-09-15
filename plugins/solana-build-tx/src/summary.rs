//! Human-readable transaction summary for the approval gate.
//!
//! Rendered from the simulation report after Layer A + Layer B validation
//! passes. The summary is what the human sees at the approval gate — it must
//! cite concrete net flows and simulation evidence, never raw bytes or JSON.
//! Cap: ~150 tokens / ~600 chars.

use std::collections::{HashMap, HashSet};

use crate::builder::{SimulationReport, TokenBalance};
use crate::policy::PolicyConfig;

/// One owner's net delta for one mint, in base units. Positive = inflow.
struct Flow {
    mint: String,
    owner: String,
    delta: i128,
}

/// Render a one-sentence summary the approval gate shows to the human.
///
/// Example: `"Transfer 5 USDC from 9WZD...BbGX to 7Np4...3jWi
/// (sim: 5000 CU, 1 mint touched)"`
///
/// For instructions with no balance changes (e.g. `create_subscription`):
/// `"Create subscription (sim: 12000 CU, 0 mints touched)"`
pub fn render_summary(
    report: &SimulationReport,
    cfg: &PolicyConfig,
    instruction_name: &str,
) -> String {
    let flows = compute_flows(&report.pre_token_balances, &report.post_token_balances);
    let mints_touched: HashSet<&str> = flows.iter().map(|f| f.mint.as_str()).collect();

    let signer_out: Vec<&Flow> = flows
        .iter()
        .filter(|f| f.owner == cfg.signer_pubkey && f.delta < 0)
        .collect();
    let recipient_in: Vec<&Flow> = flows
        .iter()
        .filter(|f| f.owner != cfg.signer_pubkey && f.delta > 0)
        .collect();

    let mut parts: Vec<String> = Vec::new();
    parts.push(pretty_instruction(instruction_name));

    if !signer_out.is_empty() {
        let amounts = signer_out
            .iter()
            .map(|f| format_amount(&f.mint, u64::try_from(-f.delta).unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(amounts);
        parts.push(format!("from {}", short(&cfg.signer_pubkey)));
    }

    if !recipient_in.is_empty() {
        let recipients: HashSet<&str> = recipient_in.iter().map(|f| f.owner.as_str()).collect();
        let rstr = recipients
            .iter()
            .map(|r| short(r))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("to {rstr}"));
    }

    let cu = report.units_consumed;
    let n = mints_touched.len();
    parts.push(format!(
        "(sim: {cu} CU, {n} mint{} touched)",
        if n == 1 { "" } else { "s" }
    ));

    let s = parts.join(" ");
    // Cap at ~600 chars; truncate with ellipsis if over.
    if s.chars().count() > 600 {
        let truncated: String = s.chars().take(597).collect();
        format!("{truncated}...")
    } else {
        s
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Diff pre/post token balances by account_index → per-owner net delta per mint.
fn compute_flows(pre: &[TokenBalance], post: &[TokenBalance]) -> Vec<Flow> {
    let pre_map: HashMap<u32, &TokenBalance> =
        pre.iter().map(|tb| (tb.account_index, tb)).collect();
    let post_map: HashMap<u32, &TokenBalance> =
        post.iter().map(|tb| (tb.account_index, tb)).collect();

    let mut all_indices: HashSet<u32> = pre_map.keys().copied().collect();
    all_indices.extend(post_map.keys().copied());

    let mut flows = Vec::new();
    for idx in all_indices {
        let pre_amt = pre_map
            .get(&idx)
            .and_then(|tb| tb.amount.parse::<i128>().ok())
            .unwrap_or(0);
        let post_amt = post_map
            .get(&idx)
            .and_then(|tb| tb.amount.parse::<i128>().ok())
            .unwrap_or(0);
        let delta = post_amt - pre_amt;
        if delta != 0 {
            let tb = post_map.get(&idx).or(pre_map.get(&idx)).unwrap();
            flows.push(Flow {
                mint: tb.mint.clone(),
                owner: tb.owner.clone(),
                delta,
            });
        }
    }
    flows
}

/// `"transfer"` → `"Transfer"`, `"create_subscription"` → `"Create subscription"`.
fn pretty_instruction(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut first = true;
    for ch in name.chars() {
        if first {
            out.extend(ch.to_uppercase());
            first = false;
        } else if ch == '_' {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

/// `5_000_000` base units at 6 decimals → `"5 USDC"`.
/// Unknown mints get `"units"` and the same 6-decimal split (stablecoin-biased;
/// v1 may add a mint-decimals lookup from the IDL or an on-chain query).
fn format_amount(mint: &str, base_units: u64) -> String {
    const DIVISOR: u64 = 1_000_000;
    let whole = base_units / DIVISOR;
    let frac = base_units % DIVISOR;
    let symbol = mint_symbol(mint);
    if frac == 0 {
        format!("{whole} {symbol}")
    } else {
        let frac_str = format!("{frac:06}");
        let trimmed = frac_str.trim_end_matches('0');
        format!("{whole}.{trimmed} {symbol}")
    }
}

/// Well-known mint symbols. Extensible without API changes.
fn mint_symbol(mint: &str) -> &'static str {
    match mint {
        "EPjFWcc5VB1U3BdVJU6dQqXxVV7iLPmsZ3jLGqxQzG2d" => "USDC",
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" => "USDT",
        _ => "units",
    }
}

/// `9WZDXwBb...BbGX` — first 4 + last 4, readable at a glance.
fn short(addr: &str) -> String {
    if addr.len() <= 8 {
        return addr.to_string();
    }
    format!("{}...{}", &addr[..4], &addr[addr.len() - 4..])
}

// ─── self-check ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{SimulatedAccount, TokenBalance};
    use crate::policy::PolicyConfig;

    const SIGNER: &str = "9WZDXwBbmkg8ZTbNMqUxvQRAyrZzDSjDxXfaoFYmBbGX";
    const USDC: &str = "EPjFWcc5VB1U3BdVJU6dQqXxVV7iLPmsZ3jLGqxQzG2d";
    const RECIPIENT: &str = "7Np41oeYqPefeJQ5WqVcZHykOxrxXtPHuSdYXdXw3jWi";

    fn tb(idx: u32, mint: &str, owner: &str, amount: &str) -> TokenBalance {
        TokenBalance {
            account_index: idx,
            mint: mint.to_string(),
            owner: owner.to_string(),
            program_id: crate::policy::SPL_TOKEN_PROGRAM.to_string(),
            amount: amount.to_string(),
        }
    }

    fn empty_sim() -> SimulationReport {
        SimulationReport {
            err: None,
            pre_token_balances: vec![],
            post_token_balances: vec![],
            accounts: vec![SimulatedAccount {
                pubkey: String::new(),
                owner: String::new(),
                lamports: 0,
                data_base64: None,
                writable: false,
                executable: false,
                rent_epoch: 0,
            }],
            units_consumed: 0,
            logs: vec![],
        }
    }

    #[test]
    fn transfer_summary_mentions_amount_and_recipient() {
        let mut sim = empty_sim();
        sim.pre_token_balances = vec![
            tb(0, USDC, SIGNER, "100000000"),
            tb(1, USDC, RECIPIENT, "0"),
        ];
        sim.post_token_balances = vec![
            tb(0, USDC, SIGNER, "95000000"),
            tb(1, USDC, RECIPIENT, "5000000"),
        ];
        sim.units_consumed = 5_000;

        let cfg = PolicyConfig {
            signer_pubkey: SIGNER.to_string(),
            ..Default::default()
        };

        let s = render_summary(&sim, &cfg, "transfer");
        let lower = s.to_ascii_lowercase();
        assert!(lower.contains("transfer"), "must mention action: {s}");
        assert!(s.contains("5"), "must mention amount: {s}");
        assert!(s.contains("USDC"), "must mention token: {s}");
        assert!(lower.contains("sim:"), "must cite sim evidence: {s}");
        assert!(lower.contains("5000 cu"), "must cite CU: {s}");
    }

    #[test]
    fn no_balance_change_shows_action_only() {
        let mut sim = empty_sim();
        sim.units_consumed = 12_000;
        let cfg = PolicyConfig {
            signer_pubkey: SIGNER.to_string(),
            ..Default::default()
        };
        let s = render_summary(&sim, &cfg, "create_subscription");
        let lower = s.to_ascii_lowercase();
        assert!(lower.contains("create subscription"), "{s}");
        assert!(lower.contains("12000 cu"), "{s}");
        assert!(lower.contains("0 mints touched"), "{s}");
    }

    #[test]
    fn summary_does_not_exceed_600_chars() {
        let mut sim = empty_sim();
        sim.pre_token_balances = vec![tb(0, USDC, SIGNER, "100000000")];
        sim.post_token_balances = vec![tb(0, USDC, SIGNER, "50000000")];
        let cfg = PolicyConfig {
            signer_pubkey: SIGNER.to_string(),
            ..Default::default()
        };
        let s = render_summary(&sim, &cfg, "transfer");
        assert!(
            s.chars().count() <= 600,
            "summary too long: {} chars",
            s.chars().count()
        );
    }

    #[test]
    fn address_shortening_works() {
        assert_eq!(short("12345678"), "12345678");
        assert_eq!(short("123456789"), "1234...6789");
        assert_eq!(short("AB"), "AB");
    }

    #[test]
    fn pretty_instruction_handles_snake_case() {
        assert_eq!(pretty_instruction("transfer"), "Transfer");
        assert_eq!(
            pretty_instruction("create_subscription"),
            "Create subscription"
        );
        assert_eq!(pretty_instruction("execute_payment"), "Execute payment");
    }
}
