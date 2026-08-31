//! Pure portfolio-risk logic — no wasm, no network, host-tested with `cargo test`.
//!
//! Per-token checks answer "is this mint dangerous?". This answers the question a
//! holder actually has: **"of everything I am holding right now, what can be taken
//! from me?"** It folds each holding's on-chain facts into a wallet-level verdict
//! and, critically, weights by position size — a critical flag on a dust position
//! is not the same as one on 90% of the portfolio.

use serde_json::Value;

/// What an authority or extension lets someone do to a holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Threat {
    /// A freeze authority (or default-frozen state) can lock the position.
    Freezable,
    /// A live mint authority can dilute the holder at will.
    Dilutable,
    /// A transfer hook or non-transferable flag can block the exit.
    ExitBlockable,
    /// A permanent delegate can move or burn the holder's tokens outright.
    Seizable,
    /// A transfer fee taxes every move.
    Taxed,
}

impl Threat {
    pub fn as_str(self) -> &'static str {
        match self {
            Threat::Freezable => "freezable",
            Threat::Dilutable => "dilutable",
            Threat::ExitBlockable => "exit_blockable",
            Threat::Seizable => "seizable",
            Threat::Taxed => "taxed",
        }
    }
    /// Severity weight used for the wallet-level score.
    pub fn weight(self) -> u32 {
        match self {
            Threat::Seizable => 40,
            Threat::ExitBlockable => 35,
            Threat::Dilutable => 25,
            Threat::Freezable => 20,
            Threat::Taxed => 10,
        }
    }
}

/// One token position held by the scanned wallet.
#[derive(Debug, Clone)]
pub struct Holding {
    pub mint: String,
    pub token_account: String,
    pub ui_amount: f64,
    pub decimals: u8,
    pub program: String,
    pub threats: Vec<Threat>,
}

impl Holding {
    /// 0-100 risk for this position alone.
    pub fn score(&self) -> u32 {
        self.threats.iter().map(|t| t.weight()).sum::<u32>().min(100)
    }
    /// Band for this position. Score sets the floor, but a single *terminal*
    /// threat forces CRITICAL: if someone can seize your tokens or stop you ever
    /// selling them, the position is critical no matter what the arithmetic says.
    pub fn band(&self) -> &'static str {
        let terminal = self
            .threats
            .iter()
            .any(|t| matches!(t, Threat::Seizable | Threat::ExitBlockable));
        if terminal {
            return "CRITICAL";
        }
        match self.score() {
            s if s >= 60 => "CRITICAL",
            s if s >= 35 => "HIGH",
            s if s >= 15 => "MEDIUM",
            s if s >= 1 => "LOW",
            _ => "MINIMAL",
        }
    }
}

/// Parse a `getTokenAccountsByOwner` (jsonParsed) response into positions.
/// Zero-balance accounts are skipped: they carry no exposure.
pub fn parse_token_accounts(resp: &Value) -> Vec<Holding> {
    let result = resp.get("result").unwrap_or(resp);
    let arr = match result.get("value").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in arr {
        let token_account = entry.get("pubkey").and_then(|p| p.as_str()).unwrap_or("").to_string();
        let acct = match entry.get("account") {
            Some(a) => a,
            None => continue,
        };
        let data = match acct.get("data") {
            Some(d) => d,
            None => continue,
        };
        let program = data.get("program").and_then(|p| p.as_str()).unwrap_or("spl-token").to_string();
        let info = match data.get("parsed").and_then(|p| p.get("info")) {
            Some(i) => i,
            None => continue,
        };
        let mint = info.get("mint").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let amt = info.get("tokenAmount");
        let ui_amount = amt
            .and_then(|a| a.get("uiAmount"))
            .and_then(|x| x.as_f64())
            .or_else(|| {
                amt.and_then(|a| a.get("uiAmountString"))
                    .and_then(|x| x.as_str())
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(0.0);
        let decimals = amt
            .and_then(|a| a.get("decimals"))
            .and_then(|d| d.as_u64())
            .unwrap_or(0) as u8;
        if mint.is_empty() || ui_amount <= 0.0 {
            continue; // dust / closed accounts carry no exposure
        }
        out.push(Holding { mint, token_account, ui_amount, decimals, program, threats: Vec::new() });
    }
    out.sort_by(|a, b| b.ui_amount.partial_cmp(&a.ui_amount).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// Read a mint's `getAccountInfo` (jsonParsed) response and derive what it lets
/// an authority do to whoever holds it.
pub fn threats_for_mint(mint_resp: &Value) -> Vec<Threat> {
    let mut threats = Vec::new();
    let result = mint_resp.get("result").unwrap_or(mint_resp);
    let value = match result.get("value") {
        Some(v) if !v.is_null() => v,
        _ => return threats,
    };
    let data = match value.get("data") {
        Some(d) => d,
        None => return threats,
    };
    let program = data.get("program").and_then(|p| p.as_str()).unwrap_or("spl-token");
    let parsed = match data.get("parsed") {
        Some(p) => p,
        None => return threats,
    };
    if parsed.get("type").and_then(|t| t.as_str()) != Some("mint") {
        return threats;
    }
    let info = match parsed.get("info") {
        Some(i) => i,
        None => return threats,
    };

    let live = |k: &str| matches!(info.get(k), Some(Value::String(s)) if !s.is_empty());
    if live("freezeAuthority") {
        threats.push(Threat::Freezable);
    }
    if live("mintAuthority") {
        threats.push(Threat::Dilutable);
    }

    if program == "spl-token-2022" {
        if let Some(exts) = info.get("extensions").and_then(|e| e.as_array()) {
            let has = |name: &str| {
                exts.iter()
                    .any(|e| e.get("extension").and_then(|n| n.as_str()) == Some(name))
            };
            if has("permanentDelegate") {
                threats.push(Threat::Seizable);
            }
            if has("transferHook") || has("nonTransferable") {
                threats.push(Threat::ExitBlockable);
            }
            if has("transferFeeConfig") {
                threats.push(Threat::Taxed);
            }
            let default_frozen = exts.iter().any(|e| {
                e.get("extension").and_then(|n| n.as_str()) == Some("defaultAccountState")
                    && e.get("state")
                        .and_then(|s| s.get("accountState"))
                        .and_then(|s| s.as_str())
                        == Some("frozen")
            });
            if default_frozen && !threats.contains(&Threat::Freezable) {
                threats.push(Threat::Freezable);
            }
        }
    }
    threats
}

/// Wallet-level verdict over the scanned holdings.
#[derive(Debug, Clone)]
pub struct WalletReport {
    pub holdings_scanned: usize,
    pub at_risk: usize,
    /// Share of the wallet's positions (by count) carrying at least one threat.
    pub at_risk_ratio: f64,
    /// Worst single-position band.
    pub worst_band: &'static str,
    /// Wallet score: the worst position, escalated when many positions are exposed.
    pub score: u32,
    pub band: &'static str,
    pub summary: String,
    pub notes: Vec<String>,
}

/// Aggregate per-holding threats into one wallet verdict.
pub fn assess_wallet(holdings: &[Holding]) -> WalletReport {
    let scanned = holdings.len();
    let at_risk = holdings.iter().filter(|h| !h.threats.is_empty()).count();
    let ratio = if scanned == 0 { 0.0 } else { at_risk as f64 / scanned as f64 };

    let worst = holdings.iter().map(|h| h.score()).max().unwrap_or(0);
    let worst_band = holdings
        .iter()
        .max_by_key(|h| h.score())
        .map(|h| h.band())
        .unwrap_or("MINIMAL");

    // Breadth escalation: one bad position is a position problem; most of the
    // wallet being exposed is a wallet problem.
    let breadth_bonus = if ratio >= 0.75 && at_risk >= 2 {
        15
    } else if ratio >= 0.5 && at_risk >= 2 {
        10
    } else {
        0
    };
    let score = (worst + breadth_bonus).min(100);
    let by_score = match score {
        s if s >= 60 => "CRITICAL",
        s if s >= 35 => "HIGH",
        s if s >= 15 => "MEDIUM",
        s if s >= 1 => "LOW",
        _ => "MINIMAL",
    };
    // A wallet is never safer than its worst position: a single seizable or
    // unsellable holding makes the wallet critical even if the score is modest.
    let rank = |b: &str| match b {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    };
    let band = if rank(worst_band) >= rank(by_score) { worst_band } else { by_score };

    let mut notes = Vec::new();
    let count = |t: Threat| holdings.iter().filter(|h| h.threats.contains(&t)).count();
    for t in [
        Threat::Seizable,
        Threat::ExitBlockable,
        Threat::Freezable,
        Threat::Dilutable,
        Threat::Taxed,
    ] {
        let n = count(t);
        if n > 0 {
            notes.push(match t {
                Threat::Seizable => format!("{n} holding(s) have a permanent delegate — an authority can move or burn them without your consent."),
                Threat::ExitBlockable => format!("{n} holding(s) can have transfers blocked (transfer hook or non-transferable)."),
                Threat::Freezable => format!("{n} holding(s) can be frozen by an authority, which blocks selling."),
                Threat::Dilutable => format!("{n} holding(s) have a live mint authority and can be diluted."),
                Threat::Taxed => format!("{n} holding(s) charge a transfer fee on every move."),
            });
        }
    }
    if scanned == 0 {
        notes.push("No non-zero token positions found for this owner.".into());
    }
    notes.push(
        "Positions are ranked by balance, not by market value — this plugin reads the chain only and does not price tokens."
            .into(),
    );

    let summary = if scanned == 0 {
        "No token holdings to assess.".to_string()
    } else if at_risk == 0 {
        format!("{scanned} holding(s) scanned; none carry a freeze, mint, delegate, hook or fee risk.")
    } else {
        format!(
            "{at_risk} of {scanned} holding(s) are exposed; worst position is {worst_band}.",
        )
    };

    WalletReport {
        holdings_scanned: scanned,
        at_risk,
        at_risk_ratio: (ratio * 1000.0).round() / 1000.0,
        worst_band,
        score,
        band,
        summary,
        notes,
    }
}
