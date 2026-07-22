//! Pure core for the `token-risk-check` tool plugin: no wasm dependency, so
//! this compiles and tests on the host with a plain `cargo test`. The wasm
//! component shim in `lib.rs` parses the WIT `execute(args)` JSON string and
//! calls straight into [`check`] with already-typed values.

use std::collections::HashMap;

use zeroclaw_solana_core::rpc::{
    self, HttpTransport, MintRiskView, EXTENSION_DEFAULT_ACCOUNT_STATE,
    EXTENSION_MINT_CLOSE_AUTHORITY, EXTENSION_NON_TRANSFERABLE, EXTENSION_PERMANENT_DELEGATE,
    EXTENSION_TRANSFER_FEE_CONFIG, EXTENSION_TRANSFER_HOOK,
};
use zeroclaw_solana_core::Pubkey;

pub fn name() -> &'static str {
    "token_risk_check"
}

pub fn description() -> &'static str {
    "Checks an SPL Token-2022 mint for rug-pull risk: mint/freeze authority, dangerous \
     extensions (permanent delegate, transfer hook, transfer fee, non-transferable), holder \
     concentration, and liquidity pool status. Returns a red/amber/green verdict with the \
     specific reasons."
}

pub fn parameters_schema() -> &'static str {
    r#"{"type":"object","properties":{"mint":{"type":"string","description":"Base58-encoded SPL Token-2022 mint address"}},"required":["mint"]}"#
}

/// Operator-configured thresholds, read from this plugin's own jailed config
/// section (`config_read` permission -- the host injects it into `execute`
/// args as `__config`, a flat `string -> string` map). `solana_rpc_url` is
/// the only required key; everything else defaults to a reasonable value
/// if omitted.
#[derive(Debug)]
pub struct RiskConfig {
    pub rpc_url: String,
    pub concentration_amber_pct: f64,
    pub concentration_red_pct: f64,
    /// A free key from <https://dev.jup.ag/docs/get-started>, used only for
    /// the liquidity-pool check. Entirely optional: without it, that one
    /// check is skipped (see [`check`]) and everything else still works.
    pub jupiter_api_key: Option<String>,
    pub min_liquidity_usd: f64,
}

impl RiskConfig {
    pub fn from_section(cfg: &HashMap<String, String>) -> Result<Self, String> {
        let rpc_url = cfg
            .get("solana_rpc_url")
            .cloned()
            .ok_or_else(|| "missing required config: solana_rpc_url".to_string())?;
        Ok(Self {
            rpc_url,
            concentration_amber_pct: parse_pct(cfg, "concentration_amber_pct", 30.0)?,
            concentration_red_pct: parse_pct(cfg, "concentration_red_pct", 60.0)?,
            jupiter_api_key: cfg.get("jupiter_api_key").cloned(),
            min_liquidity_usd: parse_pct(cfg, "min_liquidity_usd", 1000.0)?,
        })
    }
}

fn parse_pct(cfg: &HashMap<String, String>, key: &str, default: f64) -> Result<f64, String> {
    match cfg.get(key) {
        Some(raw) => raw
            .parse::<f64>()
            .map_err(|e| format!("invalid config {key}: {e}")),
        None => Ok(default),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Green,
    Amber,
    Red,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Green => "GREEN",
            Verdict::Amber => "AMBER",
            Verdict::Red => "RED",
        }
    }
}

/// Liquidity-pool signal from a third-party DEX aggregator (Jupiter's
/// Tokens API v2 -- see [`fetch_liquidity_info`]). The bounty spec allows
/// "any aggregator API" under the `http_client` permission; this is one.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LiquidityInfo {
    pub has_pool: bool,
    pub liquidity_usd: Option<f64>,
}

fn jupiter_token_search_url(mint_base58: &str) -> String {
    format!("https://api.jup.ag/tokens/v2/search?query={mint_base58}")
}

/// Queries Jupiter's Tokens API v2 (<https://dev.jup.ag/docs/tokens/token-information>)
/// for whether this mint has ever had a liquidity pool indexed, and if so,
/// its current aggregated USD liquidity. The response is a JSON array;
/// an empty array (or no entry matching `mint_base58`) means Jupiter has
/// never seen a pool for this mint at all -- not an error, a real "no
/// pool" answer -- so it's returned as `LiquidityInfo { has_pool: false,
/// liquidity_usd: None }`, not `Err`.
pub fn fetch_liquidity_info(
    transport: &dyn HttpTransport,
    api_key: &str,
    mint_base58: &str,
) -> Result<LiquidityInfo, String> {
    let url = jupiter_token_search_url(mint_base58);
    let raw = transport.get_with_headers(&url, &[("x-api-key", api_key)])?;
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("malformed jupiter response: {e}"))?;
    let entries = parsed
        .as_array()
        .ok_or_else(|| "expected a jupiter token array".to_string())?;

    let Some(entry) = entries
        .iter()
        .find(|e| e.get("id").and_then(|v| v.as_str()) == Some(mint_base58))
    else {
        return Ok(LiquidityInfo {
            has_pool: false,
            liquidity_usd: None,
        });
    };

    let has_pool = entry
        .get("firstPool")
        .map(|v| !v.is_null())
        .unwrap_or(false);
    let liquidity_usd = entry.get("liquidity").and_then(|v| v.as_f64());
    Ok(LiquidityInfo {
        has_pool,
        liquidity_usd,
    })
}

/// Computes a verdict + the specific reasons for it from a parsed mint,
/// (if available) the top holder's share of supply, and (if available) a
/// liquidity signal. Pure and independently testable: no RPC, no args
/// parsing, just risk logic over already-typed inputs. Severity only ever
/// escalates (green -> amber -> red); nothing here can downgrade a flagged
/// risk based on another field.
pub fn assess(
    view: &MintRiskView,
    top_holder_pct: Option<f64>,
    liquidity: Option<LiquidityInfo>,
    cfg: &RiskConfig,
) -> (Verdict, Vec<String>) {
    let mut reasons = Vec::new();
    let mut severity: u8 = 0; // 0 = green, 1 = amber, 2 = red

    if view.authorities.mint_authority.is_some() {
        severity = severity.max(1);
        reasons
            .push("mint authority is still active: supply can be inflated at any time".to_string());
    }
    if view.authorities.freeze_authority.is_some() {
        severity = severity.max(1);
        reasons.push(
            "freeze authority is still active: holder accounts can be frozen at any time"
                .to_string(),
        );
    }
    if view.extension_types.contains(&EXTENSION_PERMANENT_DELEGATE) {
        severity = severity.max(2);
        reasons.push(
            "permanent delegate extension: the delegate can move any holder's tokens without their signature"
                .to_string(),
        );
    }
    if view.extension_types.contains(&EXTENSION_NON_TRANSFERABLE) {
        severity = severity.max(2);
        reasons.push(
            "non-transferable extension: this mint cannot be sent between wallets at all"
                .to_string(),
        );
    }
    if view
        .extension_types
        .contains(&EXTENSION_TRANSFER_FEE_CONFIG)
    {
        severity = severity.max(1);
        reasons.push("transfer fee extension: a portion of every transfer is withheld".to_string());
    }
    if view.extension_types.contains(&EXTENSION_TRANSFER_HOOK) {
        severity = severity.max(1);
        reasons.push(
            "transfer hook extension: an external program runs on every transfer and can block or alter it"
                .to_string(),
        );
    }
    if view
        .extension_types
        .contains(&EXTENSION_MINT_CLOSE_AUTHORITY)
    {
        severity = severity.max(1);
        reasons.push(
            "mint close authority extension: the mint account itself can be closed by its authority"
                .to_string(),
        );
    }
    if view
        .extension_types
        .contains(&EXTENSION_DEFAULT_ACCOUNT_STATE)
    {
        severity = severity.max(1);
        reasons.push(
            "default account state extension present: new token accounts for this mint may be created frozen by default"
                .to_string(),
        );
    }

    if let Some(pct) = top_holder_pct {
        if pct >= cfg.concentration_red_pct {
            severity = severity.max(2);
            reasons.push(format!(
                "top holder controls {pct:.1}% of supply (>= {:.0}% red threshold)",
                cfg.concentration_red_pct
            ));
        } else if pct >= cfg.concentration_amber_pct {
            severity = severity.max(1);
            reasons.push(format!(
                "top holder controls {pct:.1}% of supply (>= {:.0}% amber threshold)",
                cfg.concentration_amber_pct
            ));
        }
    }

    // Liquidity is a softer signal than the on-chain authority/extension
    // checks above (a legitimately new, honest project can have no pool
    // yet), so it only ever escalates to AMBER, never RED -- unlike a
    // permanent delegate or non-transferable extension, "no pool" alone
    // isn't proof of malicious intent, just a reason to look closer.
    if let Some(info) = liquidity {
        if !info.has_pool {
            severity = severity.max(1);
            reasons.push(
                "no known liquidity pool found (Jupiter aggregator): may be illiquid, unlisted, or too new to have traded"
                    .to_string(),
            );
        } else if let Some(usd) = info.liquidity_usd {
            if usd < cfg.min_liquidity_usd {
                severity = severity.max(1);
                reasons.push(format!(
                    "liquidity pool exists but is thin (${usd:.0} < ${:.0} threshold): a large sell could move the price sharply",
                    cfg.min_liquidity_usd
                ));
            }
        }
    }

    if reasons.is_empty() {
        reasons.push(
            "no mint/freeze authority, no flagged Token-2022 extensions, holder concentration and liquidity within thresholds"
                .to_string(),
        );
    }

    let verdict = match severity {
        0 => Verdict::Green,
        1 => Verdict::Amber,
        _ => Verdict::Red,
    };
    (verdict, reasons)
}

/// Renders the verdict + reasons + raw facts as compact markdown,
/// deliberately terse (well under 150 tokens) so it's cheap to feed back
/// into an LLM context window.
pub fn format_report(
    mint: &str,
    view: &MintRiskView,
    top_holder_pct: Option<f64>,
    liquidity: Option<LiquidityInfo>,
    verdict: Verdict,
    reasons: &[String],
) -> String {
    let mint_auth = if view.authorities.mint_authority.is_some() {
        "active"
    } else {
        "renounced"
    };
    let freeze_auth = if view.authorities.freeze_authority.is_some() {
        "active"
    } else {
        "renounced"
    };
    let extensions = if view.extension_types.is_empty() {
        "none".to_string()
    } else {
        format!("{:?}", view.extension_types)
    };
    let holder_line = match top_holder_pct {
        Some(pct) => format!("{pct:.1}% (top holder)"),
        None => "unavailable".to_string(),
    };
    let liquidity_line = match liquidity {
        Some(LiquidityInfo {
            has_pool: false, ..
        }) => "no pool found".to_string(),
        Some(LiquidityInfo {
            liquidity_usd: Some(usd),
            ..
        }) => format!("${usd:.0}"),
        Some(LiquidityInfo {
            liquidity_usd: None,
            ..
        }) => "pool found, amount unknown".to_string(),
        None => "unavailable".to_string(),
    };
    // f64 division/powi never panics (produces inf/NaN at worst for a
    // pathological `decimals`), unlike integer arithmetic -- safe even for
    // adversarial mint data.
    let ui_supply = view.supply as f64 / 10f64.powi(view.decimals as i32);
    let reasons_md = reasons
        .iter()
        .map(|r| format!("- {r}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "**Token Risk: `{mint}` -- {}**\n\
         - Decimals: {} | Supply: {ui_supply}\n\
         - Mint authority: {mint_auth} | Freeze authority: {freeze_auth}\n\
         - Extensions: {extensions}\n\
         - Top holder: {holder_line} | Liquidity: {liquidity_line}\n\
         {reasons_md}\n",
        verdict.label(),
        view.decimals,
    )
}

/// Full orchestration: fetch the mint account, top holders, and (if
/// configured) liquidity info over the given transport, parse, assess, and
/// format. This is what the wasm shim's `execute` calls after parsing
/// `args` and `__config`.
pub fn check(
    mint_base58: &str,
    transport: &dyn HttpTransport,
    cfg: &RiskConfig,
) -> Result<String, String> {
    // Fails closed on any malformed or prompt-injected value before it ever
    // reaches an RPC call.
    Pubkey::from_base58(mint_base58)?;

    let data_b64 = rpc::fetch_account_data_base64(transport, &cfg.rpc_url, mint_base58)?;
    let data = rpc::decode_account_data(&data_b64)?;
    let view = rpc::parse_mint_risk_view(&data)?;

    // Holder concentration and liquidity are both best-effort: neither
    // failing (unsupported RPC method, missing/invalid Jupiter key, network
    // error) fails the whole check -- a partial risk read from the parts
    // that did succeed beats none.
    let top_holder_pct = rpc::fetch_largest_token_accounts(transport, &cfg.rpc_url, mint_base58)
        .ok()
        .and_then(|entries| entries.into_iter().map(|e| e.amount).max())
        .filter(|_| view.supply > 0)
        .map(|top_amount| (top_amount as f64 / view.supply as f64) * 100.0);

    let liquidity = match &cfg.jupiter_api_key {
        Some(key) => fetch_liquidity_info(transport, key, mint_base58).ok(),
        None => None,
    };

    let (verdict, reasons) = assess(&view, top_holder_pct, liquidity, cfg);
    Ok(format_report(
        mint_base58,
        &view,
        top_holder_pct,
        liquidity,
        verdict,
        &reasons,
    ))
}
