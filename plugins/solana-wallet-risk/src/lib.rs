//! A ZeroClaw WIT tool plugin: `solana-wallet-risk`.
//!
//! Scans a wallet's SPL **and** Token-2022 holdings live over `wasi:http` and
//! answers the question a holder actually has: *of everything I hold right now,
//! what can be frozen, diluted, seized, blocked or taxed?* Per-token scanners
//! answer "is this mint dangerous"; this aggregates that across a portfolio and
//! weights it by breadth of exposure.
//!
//! Read-only and key-free: it calls `getTokenAccountsByOwner` and `getAccountInfo`
//! and nothing else. The scoring core ([`portfolio`]) is pure Rust, host-tested
//! with a plain `cargo test`; only the RPC fetch is wasm-only (waki), and the
//! dispatch takes the fetcher as a parameter so tests drive the identical path.

pub mod portfolio;

pub mod handler {
    use crate::portfolio::*;
    use serde_json::{json, Value};

    pub const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";
    pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

    /// How many positions to resolve mint risk for. Holdings are sorted by balance,
    /// so this covers the exposure that matters while bounding RPC calls.
    pub const MAX_MINTS_RESOLVED: usize = 12;

    /// One JSON-RPC call: (rpc_url, method, params) -> result Value or error.
    pub type Fetcher<'a> = dyn Fn(&str, &str, Value) -> Result<Value, String> + 'a;

    fn err(msg: &str) -> String {
        json!({ "ok": false, "error": msg }).to_string()
    }

    fn plausible_pubkey(s: &str) -> bool {
        let n = s.len();
        (32..=44).contains(&n)
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l')
    }

    /// Run the `scan` op: enumerate holdings, resolve each mint's threats, aggregate.
    pub fn run(args: &str, fetch: &Fetcher) -> (String, bool) {
        let v: Value = match serde_json::from_str(args) {
            Ok(v) => v,
            Err(e) => return (err(&format!("invalid JSON args: {e}")), false),
        };
        let op = v.get("op").and_then(|o| o.as_str()).unwrap_or("scan");
        if op != "scan" {
            return (err(&format!("unknown op '{op}' (only 'scan')")), false);
        }
        let owner = match v.get("owner").and_then(|m| m.as_str()) {
            Some(o) if !o.is_empty() => o,
            _ => return (err("missing 'owner' (a base58 Solana wallet address)"), false),
        };
        if !plausible_pubkey(owner) {
            return (err("'owner' is not a plausible base58 Solana address (32–44 base58 chars)"), false);
        }
        let rpc = v.get("rpc_url").and_then(|r| r.as_str()).unwrap_or(DEFAULT_RPC);

        // 1) enumerate holdings from BOTH token programs
        let mut holdings: Vec<Holding> = Vec::new();
        let mut programs_read = 0usize;
        for program in [TOKEN_PROGRAM, TOKEN_2022_PROGRAM] {
            let params = json!([owner, {"programId": program}, {"encoding": "jsonParsed"}]);
            match fetch(rpc, "getTokenAccountsByOwner", params) {
                Ok(resp) => {
                    programs_read += 1;
                    holdings.extend(parse_token_accounts(&resp));
                }
                Err(e) => {
                    // A failure on one program shouldn't hide the other's holdings,
                    // but a total failure must be reported, not silently "clean".
                    if program == TOKEN_2022_PROGRAM && programs_read == 0 {
                        return (err(&format!("getTokenAccountsByOwner failed: {e}")), false);
                    }
                }
            }
        }
        if programs_read == 0 {
            return (err("getTokenAccountsByOwner failed for both token programs"), false);
        }
        holdings.sort_by(|a, b| b.ui_amount.partial_cmp(&a.ui_amount).unwrap_or(std::cmp::Ordering::Equal));

        // 2) resolve threats for the largest positions
        let mut unresolved = 0usize;
        for (i, h) in holdings.iter_mut().enumerate() {
            if i >= MAX_MINTS_RESOLVED {
                unresolved += 1;
                continue;
            }
            let params = json!([h.mint, {"encoding": "jsonParsed"}]);
            match fetch(rpc, "getAccountInfo", params) {
                Ok(resp) => h.threats = threats_for_mint(&resp),
                Err(_) => unresolved += 1,
            }
        }

        let mut report = assess_wallet(&holdings);
        if unresolved > 0 {
            report.notes.push(format!(
                "{unresolved} smaller position(s) were not risk-resolved (bounded to the {MAX_MINTS_RESOLVED} largest); they are excluded from the verdict rather than assumed safe."
            ));
        }
        (report_json(owner, rpc, &holdings, &report), true)
    }

    fn report_json(owner: &str, rpc: &str, holdings: &[Holding], r: &WalletReport) -> String {
        let items: Vec<Value> = holdings
            .iter()
            .take(MAX_MINTS_RESOLVED)
            .map(|h| {
                json!({
                    "mint": h.mint,
                    "token_account": h.token_account,
                    "ui_amount": h.ui_amount,
                    "decimals": h.decimals,
                    "program": h.program,
                    "threats": h.threats.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                    "risk_score": h.score(),
                    "risk_band": h.band(),
                })
            })
            .collect();
        json!({
            "ok": true,
            "op": "scan",
            "owner": owner,
            "rpc": rpc,
            "holdings_scanned": r.holdings_scanned,
            "at_risk": r.at_risk,
            "at_risk_ratio": r.at_risk_ratio,
            "worst_position_band": r.worst_band,
            "wallet_risk_score": r.score,
            "wallet_risk_band": r.band,
            "summary": r.summary,
            "holdings": items,
            "notes": r.notes,
            "disclaimer": "Deterministic on-chain evidence, not financial advice. Absence of flags is not a guarantee of safety.",
        })
        .to_string()
    }

    pub const SCHEMA: &str = r#"{
      "type": "object",
      "properties": {
        "op": {"type": "string", "enum": ["scan"], "default": "scan",
               "description": "Scan a wallet's token holdings and aggregate their risk."},
        "owner": {"type": "string", "description": "The base58 Solana wallet address to scan (required)."},
        "rpc_url": {"type": "string", "description": "Optional Solana JSON-RPC endpoint; defaults to mainnet-beta."}
      },
      "required": ["owner"]
    }"#;
}

// ── the wasm component: same handler, waki-backed Solana RPC ─────────────────
#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::handler;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde_json::{json, Value};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaWalletRisk;

    impl PluginInfo for SolanaWalletRisk {
        fn plugin_name() -> String { "solana-wallet-risk".to_string() }
        fn plugin_version() -> String { env!("CARGO_PKG_VERSION").to_string() }
    }

    /// One read-only Solana JSON-RPC POST over wasi:http (TLS host-side; only
    /// reachable after the host validates the `http_client` grant).
    fn rpc_fetch(url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        let resp = waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(bytes)
            .send()
            .map_err(|e| format!("wasi:http send failed: {e}"))?;
        let raw = resp.body().map_err(|e| format!("read response body: {e}"))?;
        let v: Value = serde_json::from_slice(&raw).map_err(|e| format!("RPC returned non-JSON: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("RPC error: {err}"));
        }
        Ok(v)
    }

    impl Tool for SolanaWalletRisk {
        fn name() -> String { "solana_wallet_risk".to_string() }

        fn description() -> String {
            "Scan a Solana wallet's SPL and Token-2022 holdings live and report which \
             positions can be frozen, diluted by a live mint authority, seized by a \
             permanent delegate, blocked by a transfer hook, or taxed by a transfer fee. \
             Returns per-holding evidence plus a wallet-level risk score and band. \
             Read-only, no keys. Pass {\"owner\":\"<wallet address>\"} (optionally \"rpc_url\")."
                .to_string()
        }

        fn parameters_schema() -> String { handler::SCHEMA.to_string() }

        fn execute(args: String) -> Result<ToolResult, String> {
            let (output, ok) = handler::run(&args, &rpc_fetch);
            log_record(
                LogLevel::Info,
                &PluginEvent {
                    function_name: "solana_wallet_risk::tool::execute".to_string(),
                    action: if ok { PluginAction::Complete } else { PluginAction::Fail },
                    outcome: Some(if ok { PluginOutcome::Success } else { PluginOutcome::Failure }),
                    duration_ms: None,
                    attrs: None,
                    message: "solana-wallet-risk".to_string(),
                },
            );
            Ok(ToolResult { success: ok, output, error: None })
        }
    }

    export!(SolanaWalletRisk);
}
