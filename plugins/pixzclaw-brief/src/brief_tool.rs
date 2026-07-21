//! Pure PixZClaw dashboard core — host-testable without wasm.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use solana_wasm_core::{
    default_usdc_mint, format_dashboard, DashboardSnapshot, HttpTransport, RpcClient,
    SignatureInfo,
};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const DEFAULT_LOOKBACK: u64 = 30;
pub const DEFAULT_RECENT: usize = 5;

#[derive(Debug, Clone)]
pub struct BriefConfig {
    pub rpc_url: String,
    pub merchant_solana: String,
    pub usdc_mint: String,
}

impl Default for BriefConfig {
    fn default() -> Self {
        Self {
            rpc_url: DEFAULT_RPC_URL.into(),
            merchant_solana: String::new(),
            usdc_mint: default_usdc_mint().into(),
        }
    }
}

impl BriefConfig {
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        let mut c = Self::default();
        if let Some(v) = map.get("rpc_url").filter(|s| !s.trim().is_empty()) {
            c.rpc_url = v.trim().into();
        }
        if let Some(v) = map.get("merchant_solana") {
            c.merchant_solana = v.trim().into();
        }
        if let Some(v) = map.get("usdc_mint").filter(|s| !s.trim().is_empty()) {
            c.usdc_mint = v.trim().into();
        }
        c
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExecuteArgs {
    #[serde(default)]
    pub lookback: Option<u64>,
    #[serde(default)]
    pub recent_limit: Option<usize>,
    /// Optional override; normally from config.
    #[serde(default)]
    pub merchant: Option<String>,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

/// Pure path: format a pre-built snapshot (unit tests).
pub fn evaluate_brief(snap: &DashboardSnapshot) -> String {
    format_dashboard(snap)
}

/// Fetch balances + signatures and format the card.
pub fn fetch_and_brief<T: HttpTransport>(
    cfg: &BriefConfig,
    http: T,
    lookback: u64,
    recent_limit: usize,
    now_unix: i64,
) -> Result<String, String> {
    let merchant = cfg.merchant_solana.trim();
    if merchant.is_empty() {
        return Err(
            "pixzclaw_brief: merchant_solana is required in config (receive wallet)"
                .into(),
        );
    }
    if cfg.rpc_url.trim().is_empty() {
        return Err("pixzclaw_brief: rpc_url is empty".into());
    }

    let client = RpcClient::new(cfg.rpc_url.trim(), http);

    let sol_lamports = client
        .get_balance(merchant)
        .map_err(|e| format!("pixzclaw_brief: getBalance failed: {}", e.message))?;

    let usdc_ui = client
        .get_token_ui_balance(merchant, cfg.usdc_mint.trim())
        .map_err(|e| format!("pixzclaw_brief: getTokenAccountsByOwner failed: {}", e.message))?;

    let limit = if lookback == 0 {
        DEFAULT_LOOKBACK
    } else {
        lookback
    };
    let signatures = client
        .get_signatures_for_address(merchant, limit)
        .map_err(|e| format!("pixzclaw_brief: getSignaturesForAddress failed: {}", e.message))?;

    let snap = DashboardSnapshot {
        merchant_solana: merchant.into(),
        sol_lamports,
        usdc_ui,
        signatures,
        now_unix,
        recent_limit: if recent_limit == 0 {
            DEFAULT_RECENT
        } else {
            recent_limit
        },
    };
    Ok(evaluate_brief(&snap))
}

pub fn execute_brief_json_with_http<T: HttpTransport>(
    args_json: &str,
    http: T,
    now_unix: i64,
) -> Result<String, String> {
    let args: ExecuteArgs =
        serde_json::from_str(args_json).map_err(|e| format!("invalid arguments: {e}"))?;
    execute_from_args_with_http(args, http, now_unix)
}

/// Host-test helper when transport is injected (not used by wasm — wasm has its own path).
pub fn execute_from_args_with_http<T: HttpTransport>(
    args: ExecuteArgs,
    http: T,
    now_unix: i64,
) -> Result<String, String> {
    let mut cfg = BriefConfig::from_map(&args.config);
    if let Some(m) = args.merchant.filter(|s| !s.trim().is_empty()) {
        // merchant override only if config empty (operator can lock by setting config)
        if cfg.merchant_solana.is_empty() {
            cfg.merchant_solana = m.trim().into();
        }
    }
    let lookback = args.lookback.unwrap_or(DEFAULT_LOOKBACK);
    let recent = args.recent_limit.unwrap_or(DEFAULT_RECENT);
    fetch_and_brief(&cfg, http, lookback, recent, now_unix)
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn fixture_sig(signature: &str, memo: Option<&str>, t: i64) -> SignatureInfo {
    SignatureInfo {
        signature: signature.into(),
        slot: 1,
        err: None,
        memo: memo.map(|m| m.into()),
        block_time: Some(t),
        confirmation_status: Some("finalized".into()),
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn evaluate_formats_card() {
        let now = 1_700_000_000i64;
        let snap = DashboardSnapshot {
            merchant_solana: "11111111111111111111111111111112".into(),
            sol_lamports: 500_000_000,
            usdc_ui: "10".into(),
            signatures: vec![fixture_sig(
                "SigLongEnoughXXXX",
                Some("PIX|BRL|inv-1|x"),
                now - 60,
            )],
            now_unix: now,
            recent_limit: 5,
        };
        let s = evaluate_brief(&snap);
        assert!(s.contains("PixZClaw"));
        assert!(s.contains("10"));
    }

    #[test]
    fn brief_has_daily_closeout_sections() {
        let now = 1_700_000_000i64;
        let snap = DashboardSnapshot {
            merchant_solana: "11111111111111111111111111111112".into(),
            sol_lamports: 500_000_000,
            usdc_ui: "10".into(),
            signatures: vec![
                fixture_sig("SigA", Some("PIX|BRL|inv-1|cafe"), now - 120),
                fixture_sig("SigB", Some("PIX|BRL|inv-2|x"), now - 3_600),
                // Fora da janela de 24h: não deve contar em "Hoje".
                fixture_sig("SigOld", Some("PIX|BRL|velha|x"), now - 3 * 86_400),
            ],
            now_unix: now,
            recent_limit: 5,
        };
        let s = evaluate_brief(&snap);
        // Fechamento de caixa diário.
        assert!(s.contains("Hoje (últimas 24h)"), "faltou seção Hoje:\n{s}");
        assert!(s.contains("faturas PIX:"));
        assert!(s.contains("pagas: inv-1"));
        // Legenda da sparkline 7d.
        assert!(s.contains("(velho→novo)"));
        // Hora relativa com prefixo "há".
        assert!(s.contains("há 1h"));
    }

    #[test]
    fn config_requires_merchant_on_fetch() {
        let cfg = BriefConfig::default();
        struct Boom;
        impl HttpTransport for Boom {
            fn post_json(
                &self,
                _: &str,
                _: &serde_json::Value,
            ) -> Result<serde_json::Value, solana_wasm_core::RpcError> {
                unreachable!()
            }
        }
        let err = fetch_and_brief(&cfg, Boom, 10, 5, 0).unwrap_err();
        assert!(err.contains("merchant_solana"));
    }
}
