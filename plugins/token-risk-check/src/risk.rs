//! Pure SPL-token risk assessment over Solana RPC JSON. No wasm, no network —
//! host-testable with golden vectors; the wasm component reuses it through the shim.
//!
//! It reads a mint's on-chain facts and reports whether an agent (or its human)
//! should be wary before touching the token: who can still mint or freeze it, and
//! how concentrated the holders are. It **fails closed** — anything it cannot
//! positively verify is reported as high risk, never a false all-clear.

use serde_json::Value;

/// Known token-program owners.
const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    /// Avoid — unverifiable, or a shape typical of a rug (extreme concentration).
    Red,
    /// Caution — centralized controls (mint/freeze authority) or concentration present.
    Amber,
    /// No mint/freeze authority, reasonable distribution, standard SPL token.
    Green,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Red => "red",
            Verdict::Amber => "amber",
            Verdict::Green => "green",
        }
    }
}

#[derive(Debug)]
pub struct RiskReport {
    pub mint: String,
    pub verdict: Verdict,
    pub signals: Vec<String>,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub token_program: String,
    pub decimals: Option<u64>,
    pub top_holder_pct: Option<f64>,
    pub top10_pct: Option<f64>,
}

impl RiskReport {
    fn failed_closed(mint: &str, reason: &str) -> Self {
        RiskReport {
            mint: mint.to_string(),
            verdict: Verdict::Red,
            signals: vec![format!("could not verify: {reason} — treated as high risk")],
            mint_authority: None,
            freeze_authority: None,
            token_program: "unknown".to_string(),
            decimals: None,
            top_holder_pct: None,
            top10_pct: None,
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "mint": self.mint,
            "verdict": self.verdict.as_str(),
            "signals": self.signals,
            "mint_authority": self.mint_authority,
            "freeze_authority": self.freeze_authority,
            "token_program": self.token_program,
            "decimals": self.decimals,
            "top_holder_pct": self.top_holder_pct,
            "top10_pct": self.top10_pct,
        })
    }
}

/// Read an optional base58 authority string that RPC encodes as `null` when absent.
fn opt_str(v: &Value, key: &str) -> Option<String> {
    match v.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Assess a mint from its `getAccountInfo` result and an optional
/// `getTokenLargestAccounts` result. `acct` is the `result` object of a
/// jsonParsed `getAccountInfo`; `largest` is the `result` of
/// `getTokenLargestAccounts` (best-effort — concentration is skipped if absent).
pub fn assess(mint: &str, acct: &Value, largest: Option<&Value>) -> RiskReport {
    // Fails closed at every missing step.
    let value = match acct.get("value") {
        Some(Value::Null) | None => {
            return RiskReport::failed_closed(mint, "mint account not found");
        }
        Some(v) => v,
    };
    let parsed = value.pointer("/data/parsed");
    let is_mint = parsed.and_then(|p| p.get("type")).and_then(Value::as_str) == Some("mint");
    if !is_mint {
        return RiskReport::failed_closed(mint, "account is not an SPL mint");
    }
    let info = match parsed.and_then(|p| p.get("info")) {
        Some(i) => i,
        None => return RiskReport::failed_closed(mint, "mint has no parsed info"),
    };

    let owner = value.get("owner").and_then(Value::as_str).unwrap_or("");
    let token_program = match owner {
        SPL_TOKEN => "spl-token".to_string(),
        TOKEN_2022 => "token-2022".to_string(),
        _ => return RiskReport::failed_closed(mint, "unknown token program owner"),
    };

    let mint_authority = opt_str(info, "mintAuthority");
    let freeze_authority = opt_str(info, "freezeAuthority");
    let decimals = info.get("decimals").and_then(Value::as_u64);
    let supply: Option<u128> = info
        .get("supply")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok());

    // Holder concentration (best-effort).
    let (top_holder_pct, top10_pct) = concentration(largest, supply);

    // ---- score ----
    let mut signals: Vec<String> = Vec::new();
    let mut verdict = Verdict::Green;
    let bump = |v: &mut Verdict, to: Verdict| {
        if (to == Verdict::Red) || (to == Verdict::Amber && *v == Verdict::Green) {
            *v = to;
        }
    };

    if mint_authority.is_some() {
        signals.push("mint authority is active: total supply can still be inflated".into());
        bump(&mut verdict, Verdict::Amber);
    }
    if freeze_authority.is_some() {
        signals.push("freeze authority is active: your token account can be frozen".into());
        bump(&mut verdict, Verdict::Amber);
    }
    if token_program == "token-2022" {
        signals.push(
            "Token-2022 mint: check extensions (transfer fees/hooks, permanent delegate)".into(),
        );
        bump(&mut verdict, Verdict::Amber);
    }
    if let Some(top1) = top_holder_pct {
        if top1 >= 50.0 {
            signals.push(format!(
                "single wallet holds {top1:.1}% of supply (severe concentration)"
            ));
            bump(&mut verdict, Verdict::Red);
        } else if top1 >= 25.0 {
            signals.push(format!("top wallet holds {top1:.1}% of supply"));
            bump(&mut verdict, Verdict::Amber);
        }
    }
    if let Some(top10) = top10_pct {
        if top10 >= 90.0 {
            signals.push(format!("top 10 wallets hold {top10:.1}% of supply"));
            bump(&mut verdict, Verdict::Amber);
        }
    }
    if signals.is_empty() {
        signals
            .push("no mint/freeze authority, standard SPL token, no extreme concentration".into());
    }

    RiskReport {
        mint: mint.to_string(),
        verdict,
        signals,
        mint_authority,
        freeze_authority,
        token_program,
        decimals,
        top_holder_pct,
        top10_pct,
    }
}

/// Compute top-1 and top-10 holder percentages from a `getTokenLargestAccounts`
/// result and the mint supply. Excludes nothing — a burn address counts as held.
fn concentration(largest: Option<&Value>, supply: Option<u128>) -> (Option<f64>, Option<f64>) {
    let (Some(largest), Some(supply)) = (largest, supply) else {
        return (None, None);
    };
    if supply == 0 {
        return (None, None);
    }
    let Some(arr) = largest.get("value").and_then(Value::as_array) else {
        return (None, None);
    };
    let amounts: Vec<u128> = arr
        .iter()
        .filter_map(|a| a.get("amount").and_then(Value::as_str))
        .filter_map(|s| s.parse::<u128>().ok())
        .collect();
    if amounts.is_empty() {
        return (None, None);
    }
    let pct = |n: u128| (n as f64) / (supply as f64) * 100.0;
    let top1 = amounts.first().copied().map(pct);
    let top10: u128 = amounts.iter().take(10).sum();
    (top1, Some(pct(top10)))
}
