//! Pure risk-scoring core for a Solana mint. No wasm dependency, so it compiles
//! and tests on the host with `cargo test`; the wasm component reuses it.
//!
//! The component is responsible for fetching on-chain data (getAccountInfo on
//! the mint, getTokenLargestAccounts) over wasi:http and handing the parsed
//! JSON to [`score`]. This keeps the scoring logic plain Rust and unit-testable
//! without a network or a wasm target.

use serde_json::Value;

/// Abstraction over the two RPC reads we need. The wasm shim implements this
/// with waki; tests implement it with canned fixtures.
pub trait Rpc {
    /// `getAccountInfo` on the mint, parsed `result.value` (or None if missing).
    fn mint_account(&self, mint: &str) -> Option<Value>;
    /// `getTokenLargestAccounts` parsed `result.value` (top holders), or empty.
    fn largest_accounts(&self, mint: &str) -> Vec<Value>;
}

#[derive(Debug, serde::Serialize)]
pub struct RiskReport {
    pub level: String,        // "green" | "amber" | "red"
    pub score: u8,            // 0 (safe) .. 100 (dangerous)
    pub reasons: Vec<String>,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub token_2022: bool,
    pub extensions: Vec<String>,
    pub top_holder_pct: f64,
}

const SAFE_MINT_AUTH: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SAFE_TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Inspect a mint account's parsed data section for Token-2022 extensions.
pub fn detect_extensions(parsed: &Value) -> Vec<String> {
    let mut ext = Vec::new();
    if let Some(t22) = parsed.get("parsed").and_then(|p| p.get("info"))
        .and_then(|i| i.get("extensions")).and_then(|e| e.as_array()) {
        for e in t22 {
            if let Some(name) = e.get("extension").and_then(|n| n.as_str()) {
                ext.push(name.to_string());
            }
        }
    }
    ext
}

/// Main entry: score a mint given an Rpc source.
pub fn score<R: Rpc>(rpc: &R, mint: &str, supply: Option<f64>) -> RiskReport {
    let mut reasons = Vec::new();
    let mut score: u8 = 0;

    let account = rpc.mint_account(mint);
    let (mut mint_auth, mut freeze_auth, mut is_t22, mut exts) =
        (None, None, false, Vec::new());

    if let Some(acc) = &account {
        let owner = acc.get("owner").and_then(|o| o.as_str()).unwrap_or("");
        is_t22 = owner == SAFE_TOKEN_2022;
        if let Some(info) = acc.get("parsed").and_then(|p| p.get("info")) {
            mint_auth = info.get("mintAuthority").and_then(|v| v.as_str()).map(String::from);
            freeze_auth = info.get("freezeAuthority").and_then(|v| v.as_str()).map(String::from);
            exts = detect_extensions(acc);

            if mint_auth.is_none() || mint_auth.as_deref() == Some("") {
                reasons.push("mint authority burned (good)".into());
            } else {
                reasons.push("mint authority live — can inflate supply".into());
                score += 25;
            }
            if freeze_auth.is_some() && !freeze_auth.as_deref().unwrap().is_empty() {
                reasons.push("freeze authority live — can freeze holdings".into());
                score += 30;
            } else {
                reasons.push("freeze authority burned (good)".into());
            }
        }
    } else {
        reasons.push("mint account not found / RPC error".into());
        score += 40;
    }

    if is_t22 {
        reasons.push("Token-2022 mint — extensions present".into());
        // Flag the dangerous ones specifically.
        for e in &exts {
            match e.as_str() {
                "permanentDelegate" => { reasons.push("permanent delegate — issuer can move your tokens".into()); score += 25; }
                "transferFeeConfig" => { reasons.push("transfer fee — taxable on every move".into()); score += 5; }
                "transferHook" => { reasons.push("transfer hook — programmable restrictions".into()); score += 10; }
                "confidentialTransferMint" => { reasons.push("confidential transfers — opacity risk".into()); score += 5; }
                _ => {}
            }
        }
    }

    // Holder concentration from largest accounts.
    let holders = rpc.largest_accounts(mint);
    let mut top_pct = 0.0;
    if let Some(first) = holders.first() {
        if let (Some(amt), Some(total)) = (
            first.get("uiAmount").and_then(|a| a.as_f64()),
            supply,
        ) {
            if total > 0.0 {
                top_pct = (amt / total) * 100.0;
                if top_pct > 50.0 {
                    reasons.push(format!("top holder owns {top_pct:.1}% of supply"));
                    score += 20;
                } else if top_pct > 20.0 {
                    reasons.push(format!("top holder owns {top_pct:.1}% of supply"));
                    score += 8;
                }
            }
        }
    }

    let level = if score >= 50 { "red" } else if score >= 20 { "amber" } else { "green" };
    RiskReport {
        level: level.to_string(),
        score: score.min(100),
        reasons,
        mint_authority: mint_auth,
        freeze_authority: freeze_auth,
        token_2022: is_t22,
        extensions: exts,
        top_holder_pct: top_pct,
    }
}
