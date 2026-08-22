//! Frozen internal seam between the WIT shim (`lib.rs`) and the pure guard
//! logic ([`HttpRequest`], [`HttpResponse`], [`Transport`], [`ToolOutput`],
//! and the `run` signature — frozen since the scaffold slice, verbatim).
//! `run`'s body wires `args::parse_call` into the `check`/`portfolio`/
//! `rescue` pipelines against the frozen modules: `net` (all I/O shaping),
//! `kamino` (payload parsing + snapshot codec), `health` (tier/forecast
//! math), `remedy` (ranked repay/deposit remedies), `rescue` (unsigned
//! repay tx), `report` (text rendering). No I/O happens outside a
//! [`Transport::fetch`] call; `run` never panics — every error path
//! (parse failure, missing data, non-200) returns `ToolOutput { success:
//! false, .. }`.

/// HTTP method for a [`Transport::fetch`] call.
#[derive(Clone, Copy)]
pub enum Method {
    Get,
    Post,
}

/// A single outbound HTTP request issued by the guard logic.
pub struct HttpRequest {
    pub method: Method,
    /// Absolute https URL.
    pub url: String,
    /// JSON body for POST.
    pub body: Option<String>,
}

/// The response to an [`HttpRequest`].
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    /// HTTP `Date` response header, verbatim.
    pub date_header: Option<String>,
}

/// Abstraction over the HTTP transport so `run` is testable on the host
/// without a real wasi:http client.
pub trait Transport {
    fn fetch(&mut self, req: &HttpRequest) -> Result<HttpResponse, String>;
}

/// Result of a `run` call; mapped into the WIT `tool-result` by `lib.rs`.
pub struct ToolOutput {
    pub success: bool,
    pub text: String,
}

/// Entry point for the guard logic: parses `raw_args`, dispatches to the
/// requested action, and never panics — any failure anywhere in the
/// pipeline becomes `ToolOutput { success: false, text }` with a typed
/// message.
pub fn run(raw_args: &str, transport: &mut dyn Transport) -> ToolOutput {
    match run_inner(raw_args, transport) {
        Ok(text) => ToolOutput {
            success: true,
            text,
        },
        Err(text) => ToolOutput {
            success: false,
            text,
        },
    }
}

// ---------------------------------------------------------------------
// Pipeline implementation (private — the only frozen surface is `run`
// itself and the types above it).
// ---------------------------------------------------------------------

use std::collections::HashMap;

use crate::args::{self, Action, ParsedCall};
use crate::config::Config;
use crate::health::{self, PositionFacts, PriorSnapshotFacts, Thresholds};
use crate::kamino::{self, ObligationFacts, PositionRow, PriceRow, ReserveMetrics};
use crate::net::{self, ApiCall};
use crate::remedy::{self, RemedyInput, RemedyKind};
use crate::report::{self, DepositText, PositionMeta, RescueText};
use crate::rescue::{self, ReserveAccounts};

fn run_inner(raw_args: &str, transport: &mut dyn Transport) -> Result<String, String> {
    let call = args::parse_call(raw_args)?;
    match call.action {
        Action::Check => run_check(&call, transport),
        Action::Portfolio => run_portfolio(&call, transport),
        Action::Rescue => run_rescue(&call, transport),
        Action::Deposit => run_deposit(&call, transport),
    }
}

/// Issues one `ApiCall`, checking the response and naming the endpoint
/// class in any error (no retry).
fn fetch(
    transport: &mut dyn Transport,
    call: &ApiCall,
    label: &str,
) -> Result<HttpResponse, String> {
    let req = net::api_request(call);
    let resp = transport
        .fetch(&req)
        .map_err(|e| format!("{label} request failed: {e}"))?;
    net::check_response(&resp).map_err(|e| format!("{label} request failed: {e}"))?;
    Ok(resp)
}

/// Issues an already-built RPC `HttpRequest`, checking the response and
/// naming the endpoint class in any error (no retry).
fn fetch_req(
    transport: &mut dyn Transport,
    req: HttpRequest,
    label: &str,
) -> Result<HttpResponse, String> {
    let resp = transport
        .fetch(&req)
        .map_err(|e| format!("{label} request failed: {e}"))?;
    net::check_response(&resp).map_err(|e| format!("{label} request failed: {e}"))?;
    Ok(resp)
}

/// Resolves the message blockhash for a transaction build, and is the only
/// place either tx path gets one.
///
/// Proves the configured endpoint is mainnet-beta first: the check is a
/// hard gate, because a cluster mismatch silently invalidates every account
/// address already baked into the plan. An unreadable or erroring
/// `getGenesisHash` fails the build — it never degrades to "assume
/// mainnet".
///
/// Then durable nonce when configured (opt-in, and any nonce problem is a
/// hard error — never a silent fallback to a fetched blockhash, since the
/// user configured durability on purpose), else the default
/// `getLatestBlockhash` path.
fn resolve_blockhash(
    call: &ParsedCall,
    transport: &mut dyn Transport,
    wallet: &str,
) -> Result<(String, Option<rescue::NonceInfo>), String> {
    let genesis_resp = fetch_req(
        transport,
        net::rpc_get_genesis_hash(&call.config.rpc_url),
        "genesis hash",
    )?;
    let genesis = net::parse_genesis_hash_response(&genesis_resp.body)?;
    if genesis != MAINNET_GENESIS_HASH {
        return Err(format!(
            "configured rpc_url is not Solana mainnet-beta (genesis {genesis}, \
             expected {MAINNET_GENESIS_HASH}): refusing to build a transaction \
             against mainnet Kamino accounts"
        ));
    }

    match &call.config.nonce_account {
        Some(nonce_account) => {
            let acct_resp = fetch_req(
                transport,
                net::rpc_get_account_info(&call.config.rpc_url, nonce_account),
                "nonce account",
            )?;
            let (owner, data) = net::parse_account_info_response(&acct_resp.body)?;
            let stored_value = rescue::parse_nonce_account(&owner, &data, wallet)?;
            let info = rescue::NonceInfo {
                account: nonce_account.clone(),
                authority: wallet.to_string(),
                stored_value: stored_value.clone(),
            };
            Ok((stored_value, Some(info)))
        }
        None => {
            let blockhash_resp = fetch_req(
                transport,
                net::rpc_get_latest_blockhash(&call.config.rpc_url),
                "blockhash",
            )?;
            Ok((net::parse_blockhash_response(&blockhash_resp.body)?, None))
        }
    }
}

/// Scales a UI amount to native token units — the last arithmetic step
/// before an amount becomes transaction bytes, so it is gated explicitly.
///
/// `overflow-checks` does not help here: `f64 as u64` *saturates* rather
/// than wrapping, and saturation is not an overflow the profile can trap.
/// Left ungated, NaN and negatives land as `0` and anything at or past
/// 2^64 as `u64::MAX` — a silently zero-amount or max-amount transaction
/// presented to the user as a rescue. `remedy::safe_div` and the
/// healthy-position gate happen to keep those out of reach today; this
/// makes the invariant stated and tested rather than incidental.
///
/// `u64::MAX as f64` rounds *up* to exactly 2^64, so the bound is `>=`.
fn ui_to_native(amount_ui: f64, decimals: u8, label: &str) -> Result<u64, String> {
    let scaled = (amount_ui * 10f64.powi(decimals as i32)).round();
    if !scaled.is_finite() || scaled <= 0.0 || scaled >= u64::MAX as f64 {
        return Err(format!(
            "refusing to build a transaction: {label} amount {amount_ui} does not scale to a \
             usable native amount at {decimals} decimals"
        ));
    }
    Ok(scaled as u64)
}

fn resolve_wallet(call: &ParsedCall) -> Result<String, String> {
    call.wallet
        .clone()
        .or_else(|| call.config.wallet.clone())
        .ok_or_else(|| "wallet required: pass 'wallet' or set it in plugin config".to_string())
}

/// The market a `check`/`rescue` call scopes to: the arg when given, else
/// the first configured market (`config.markets` is never empty).
fn resolve_market(call: &ParsedCall) -> String {
    call.market
        .clone()
        .unwrap_or_else(|| call.config.markets[0].clone())
}

/// Drops any obligation the configured wallet does not own.
///
/// The `/obligations` query is already wallet-scoped, so in honest operation
/// this filter never removes anything — it fires only when the response
/// disagrees with the request. It matters because every transaction built
/// downstream spends *this* wallet's tokens into *this* obligation: without
/// the check, the wallet↔position binding rests entirely on the API being
/// truthful, and a response naming a foreign obligation would produce a
/// transaction that moves the user's funds into a position they do not
/// control. `ObligationFacts.owner` was parsed all along and read nowhere;
/// this is the check that makes the inbound-only custody property locally
/// verifiable instead of API-dependent.
fn owned_by(obligations: Vec<ObligationFacts>, wallet: &str) -> Vec<ObligationFacts> {
    obligations
        .into_iter()
        .filter(|f| f.owner == wallet)
        .collect()
}

/// Picks the single obligation a `check`/`rescue` call operates on: the
/// `obligation` arg when given (exact match), else the sole result. More
/// than one candidate with no `obligation` arg is a typed refusal rather
/// than a guess. Obligations not owned by `wallet` are never candidates.
fn select_obligation(
    obligations: Vec<ObligationFacts>,
    wanted: Option<&str>,
    wallet: &str,
) -> Result<ObligationFacts, String> {
    let obligations = owned_by(obligations, wallet);
    let mut matches: Vec<ObligationFacts> = match wanted {
        Some(o) => obligations
            .into_iter()
            .filter(|f| f.obligation == o)
            .collect(),
        None => obligations,
    };
    match matches.len() {
        0 => Err("no matching obligation found for that wallet/market".to_string()),
        1 => Ok(matches.remove(0)),
        _ => Err("multiple obligations found; specify 'obligation'".to_string()),
    }
}

/// The largest-by-`usd_value` row — the obligation's dominant deposit or
/// borrow, used as "the" collateral/debt asset for display and remedy math
/// (v1 does not attempt multi-asset remedy ranking).
fn dominant(rows: &[PositionRow]) -> Option<&PositionRow> {
    rows.iter().max_by(|a, b| {
        a.usd_value
            .partial_cmp(&b.usd_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}

fn metrics_for<'a>(
    metrics: &'a [ReserveMetrics],
    reserve: &str,
) -> Result<&'a ReserveMetrics, String> {
    metrics
        .iter()
        .find(|m| m.reserve == reserve)
        .ok_or_else(|| format!("no reserve metrics for reserve {reserve}"))
}

fn price_for<'a>(prices: &'a [PriceRow], mint: &str) -> Result<&'a PriceRow, String> {
    prices
        .iter()
        .find(|p| p.mint == mint)
        .ok_or_else(|| format!("no price for mint {mint}"))
}

/// The SOL mint every pinned LST's stake rate is quoted against.
const SOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// Solana mainnet-beta genesis hash. Every address this plugin encodes into
/// a transaction — Kamino program ids, reserves, obligations — comes from
/// `net::API_BASE`, which serves mainnet and only mainnet. A non-mainnet
/// `rpc_url` is therefore a misconfiguration rather than a use case: it
/// would pair mainnet account addresses with a foreign cluster's blockhash
/// (or nonce), so the operator's "which chain am I on" mistake would
/// surface as an opaque failure at signing time instead of here.
const MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/// Pinned major-LST mint table (safety invariant 6: a collateral mint's
/// presence here — never a payload `name`/symbol string — is the only thing
/// that turns on SOL-level quoting). Mints for JitoSOL, mSOL, bSOL, jupSOL,
/// and bnSOL are verified against `tests/fixtures/prices.json` by
/// `tests::pinned_lst_mints_match_fixture` below; the fixture carries no INF
/// row, so that entry is cross-checked instead against Sanctum's published
/// Infinity LST mint, published by Sanctum.
const PINNED_LST_MINTS: &[&str] = &[
    "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn", // JitoSOL
    "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So",  // mSOL
    "bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1",  // bSOL
    "jupSoLaHXQiZZTSfEWMTRRgpnyFm8f6sZdosWBjx93v",  // jupSOL
    "5oVNBeEEQvYi1cX3ir8Dx5n1P7pdxydbGF2X4TxVusJm", // INF
    "BNso1VUJnh4zcfpZa6986Ea66P6TCp59hvtNJ8b1X85",  // bnSOL
];

/// `Some(lst_price_usd / sol_price_usd)` — both from the same
/// `/oracles/prices` response — when `collateral_mint` is in the pinned LST
/// table and a nonzero SOL price is present; `None` otherwise (unpinned
/// mint, missing SOL row, or zero SOL price), which falls back to the
/// existing token-level quote rather than fabricating a rate.
fn lst_stake_rate_for(
    collateral_mint: &str,
    collateral_price: f64,
    prices: &[PriceRow],
) -> Option<f64> {
    if !PINNED_LST_MINTS.contains(&collateral_mint) {
        return None;
    }
    let sol_price = price_for(prices, SOL_MINT).ok()?.price;
    if sol_price == 0.0 {
        return None;
    }
    Some(collateral_price / sol_price)
}

/// Facts shared by the `check` and `rescue` pipelines: the dominant
/// deposit/borrow rows joined to their reserve metrics and prices.
struct JoinedFacts<'a> {
    collateral_symbol: String,
    collateral_price: f64,
    collateral_row: &'a PositionRow,
    debt_symbol: String,
    debt_price: f64,
    debt_row: &'a PositionRow,
}

fn join_facts<'a>(
    obligation: &'a ObligationFacts,
    prices: &[PriceRow],
    metrics: &[ReserveMetrics],
) -> Result<JoinedFacts<'a>, String> {
    let collateral_row =
        dominant(&obligation.deposits).ok_or_else(|| "obligation has no deposits".to_string())?;
    let debt_row =
        dominant(&obligation.borrows).ok_or_else(|| "obligation has no borrows".to_string())?;

    let collateral_metrics = metrics_for(metrics, &collateral_row.reserve)?;
    let debt_metrics = metrics_for(metrics, &debt_row.reserve)?;
    let collateral_price_row = price_for(prices, &collateral_metrics.mint)?;
    let debt_price_row = price_for(prices, &debt_metrics.mint)?;

    Ok(JoinedFacts {
        collateral_symbol: collateral_metrics.symbol.clone(),
        collateral_price: collateral_price_row.price,
        collateral_row,
        debt_symbol: debt_metrics.symbol.clone(),
        debt_price: debt_price_row.price,
        debt_row,
    })
}

fn stale_names(prices: &[PriceRow], mints: &[&str], now_unix: Option<i64>) -> Vec<String> {
    let Some(now) = now_unix else {
        return Vec::new();
    };
    prices
        .iter()
        .filter(|p| mints.contains(&p.mint.as_str()) && kamino::price_is_stale(now, p))
        .map(|p| p.name.clone())
        .collect()
}

/// Stale-price names for the two assets a transaction build depends on.
///
/// `check` gets this via [`assess_obligation`]; the two money paths need the
/// same clock. The prices that decide whether a price row is expired are the
/// very prices that size the repay/deposit amount, so a transaction built on
/// an expired oracle is exactly what the operator must be told before they
/// sign. Both paths previously hard-coded an empty list, leaving the
/// freshness channel dead on the only outputs that move funds.
fn stale_for_joined(
    prices: &[PriceRow],
    metrics: &[ReserveMetrics],
    joined: &JoinedFacts,
    now_unix: Option<i64>,
) -> Result<Vec<String>, String> {
    let collateral_mint = metrics_for(metrics, &joined.collateral_row.reserve)?
        .mint
        .clone();
    let debt_mint = metrics_for(metrics, &joined.debt_row.reserve)?.mint.clone();
    Ok(stale_names(
        prices,
        &[collateral_mint.as_str(), debt_mint.as_str()],
        now_unix,
    ))
}

/// Renders one obligation's `check` result: joins facts, decodes the prior
/// snapshot, assesses health, ranks remedies, and re-encodes a fresh
/// snapshot.
fn assess_obligation(
    obligation: &ObligationFacts,
    prices: &[PriceRow],
    metrics: &[ReserveMetrics],
    now_unix: Option<i64>,
    config: &Config,
    prev_snapshot: Option<&str>,
) -> Result<String, String> {
    let joined = join_facts(obligation, prices, metrics)?;
    let collateral_mint = metrics_for(metrics, &joined.collateral_row.reserve)?
        .mint
        .clone();
    let debt_mint = metrics_for(metrics, &joined.debt_row.reserve)?.mint.clone();
    let stale = stale_names(
        prices,
        &[collateral_mint.as_str(), debt_mint.as_str()],
        now_unix,
    );

    let debt_metrics = metrics_for(metrics, &joined.debt_row.reserve)?;

    // Pinned-mint-table lookup only (safety invariant 6) — never a payload
    // name/symbol match. `None` for an unpinned mint, a missing SOL price
    // row, or a zero SOL price; `health::assess` then falls back to the
    // token-level (spot/redemption) quote, never a fabricated rate.
    let lst_stake_rate = lst_stake_rate_for(&collateral_mint, joined.collateral_price, prices);

    let facts = PositionFacts {
        ltv: obligation.ltv,
        liq_ltv: obligation.liq_ltv,
        borrow_usd: obligation.borrow_usd,
        deposit_usd: obligation.deposit_usd,
        collateral_symbol: joined.collateral_symbol.clone(),
        debt_symbol: joined.debt_symbol.clone(),
        collateral_price: joined.collateral_price,
        debt_price: joined.debt_price,
        lst_stake_rate,
        multi_volatile_collateral: obligation.deposits.len() > 1,
        elevation_group: obligation.elevation_group,
        // Only a market-level `autodeleverageEnabled` flag is available
        // from the closed endpoint set (no per-reserve granularity) — when
        // set, both held assets are flagged via the existing symbol-match
        // warn-only mechanism below.
        adl_assets: if obligation.market_adl_enabled {
            vec![joined.collateral_symbol.clone(), joined.debt_symbol.clone()]
        } else {
            Vec::new()
        },
        position_value_usd: obligation.deposit_usd,
        min_full_liquidation_value_usd: obligation.min_full_liquidation_value_usd,
        borrow_apy: Some(debt_metrics.borrow_apy),
        utilization: debt_metrics.utilization,
    };

    let thresholds = Thresholds {
        watch: config.watch_pct / 100.0,
        warn: config.warn_pct / 100.0,
        critical: config.critical_pct / 100.0,
    };

    // F6: a decoded snapshot from a different obligation is never diffed
    // against this one — filtered out here degrades it to "no prior
    // snapshot", same as any other garbled/missing input, never an error
    // and never a cross-obligation PARAM ALERT/drift line.
    let prior = prev_snapshot
        .and_then(kamino::decode_snapshot)
        .filter(|s| s.obligation == obligation.obligation)
        .map(|s| PriorSnapshotFacts {
            ltv: s.ltv,
            liq_ltv: s.liq_ltv,
            collateral_price: s.collateral_price,
            elevation_group: s.elevation_group,
        });

    let health_report = health::assess(&facts, prior.as_ref(), &thresholds);

    let remedies = remedy::rank(&RemedyInput {
        borrow_usd: facts.borrow_usd,
        deposit_usd: facts.deposit_usd,
        liq_ltv: facts.liq_ltv,
        watch: thresholds.watch,
        debt_symbol: joined.debt_symbol.clone(),
        debt_price: joined.debt_price,
        collateral_symbol: joined.collateral_symbol.clone(),
        collateral_price: joined.collateral_price,
        max_repay_ui: config.max_repay_ui,
        // Documentation-only in `remedy::rank` today (never branched on);
        // v1 has no historical-price feed to compute a real trend from.
        collateral_is_falling: false,
    });

    let snapshot = kamino::Snapshot {
        v: 1,
        obligation: obligation.obligation.clone(),
        ltv: facts.ltv,
        liq_ltv: facts.liq_ltv,
        collateral_price: facts.collateral_price,
        elevation_group: facts.elevation_group,
        taken_unix: now_unix.unwrap_or(0),
    };
    let snapshot_str = kamino::encode_snapshot(&snapshot);

    let meta = PositionMeta {
        obligation: obligation.obligation.clone(),
        market: obligation.market.clone(),
        collateral_symbol: joined.collateral_symbol,
        debt_symbol: joined.debt_symbol,
        collateral_price: joined.collateral_price,
        debt_price: joined.debt_price,
        stale_price_names: stale,
    };

    Ok(report::render_check(
        &meta,
        &health_report,
        &remedies,
        &snapshot_str,
    ))
}

fn run_check(call: &ParsedCall, transport: &mut dyn Transport) -> Result<String, String> {
    let wallet = resolve_wallet(call)?;
    let market = resolve_market(call);

    let obligations_resp = fetch(
        transport,
        &ApiCall::Obligations {
            market: &market,
            wallet: &wallet,
        },
        "obligations",
    )?;
    let obligations = kamino::parse_obligations(&obligations_resp.body)?;
    let obligation = select_obligation(obligations, call.obligation.as_deref(), &wallet)?;

    let prices_resp = fetch(transport, &ApiCall::Prices, "prices")?;
    let prices = kamino::parse_prices(&prices_resp.body)?;
    let now_unix = prices_resp
        .date_header
        .as_deref()
        .map(kamino::http_date_to_unix)
        .transpose()?;

    let metrics_resp = fetch(
        transport,
        &ApiCall::ReservesMetrics { market: &market },
        "reserves metrics",
    )?;
    let metrics = kamino::parse_reserves_metrics(&metrics_resp.body)?;

    assess_obligation(
        &obligation,
        &prices,
        &metrics,
        now_unix,
        &call.config,
        call.prev_snapshot.as_deref(),
    )
}

fn run_portfolio(call: &ParsedCall, transport: &mut dyn Transport) -> Result<String, String> {
    let wallet = resolve_wallet(call)?;

    let prices_resp = fetch(transport, &ApiCall::Prices, "prices")?;
    let prices = kamino::parse_prices(&prices_resp.body)?;
    let now_unix = prices_resp
        .date_header
        .as_deref()
        .map(kamino::http_date_to_unix)
        .transpose()?;

    let mut sections = Vec::new();
    for market in &call.config.markets {
        let obligations_resp = fetch(
            transport,
            &ApiCall::Obligations {
                market,
                wallet: &wallet,
            },
            "obligations",
        )?;
        let obligations = owned_by(kamino::parse_obligations(&obligations_resp.body)?, &wallet);
        if obligations.is_empty() {
            continue;
        }
        let metrics_resp = fetch(
            transport,
            &ApiCall::ReservesMetrics { market },
            "reserves metrics",
        )?;
        let metrics = kamino::parse_reserves_metrics(&metrics_resp.body)?;
        for obligation in &obligations {
            sections.push(assess_obligation(
                obligation,
                &prices,
                &metrics,
                now_unix,
                &call.config,
                call.prev_snapshot.as_deref(),
            )?);
        }
    }

    if sections.is_empty() {
        return Err("no obligations found across configured markets".to_string());
    }
    Ok(report::render_portfolio(&sections))
}

/// Parses a `/kamino-market/reserves/account-data` response body — an
/// array of `{market, reserves: [{pubkey, data}]}` entries, one per
/// requested market — into a `reserve pubkey -> base64 data` map for the
/// entry matching `market`. No parser for this endpoint lives in
/// `kamino.rs` (its docs scope it to obligations/prices/reserve-metrics);
/// the shape is two string fields per row, narrow enough that a local pass
/// here doesn't earn a new module.
fn parse_reserve_account_data(body: &str, market: &str) -> Result<HashMap<String, String>, String> {
    #[derive(serde::Deserialize)]
    struct Entry {
        market: String,
        reserves: Vec<ReserveRow>,
    }
    #[derive(serde::Deserialize)]
    struct ReserveRow {
        pubkey: String,
        data: String,
    }
    let entries: Vec<Entry> = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let entry = entries
        .into_iter()
        .find(|e| e.market == market)
        .ok_or_else(|| format!("no reserve account data for market {market}"))?;
    Ok(entry
        .reserves
        .into_iter()
        .map(|r| (r.pubkey, r.data))
        .collect())
}

fn run_rescue(call: &ParsedCall, transport: &mut dyn Transport) -> Result<String, String> {
    // Fail-closed gate (safety invariant 4): no `max_repay_ui` means
    // rescue is disabled outright, before any network I/O.
    let max_repay_ui = call.config.max_repay_ui.ok_or_else(|| {
        "rescue disabled: set 'max_repay_ui' in plugin config to enable it".to_string()
    })?;

    let wallet = resolve_wallet(call)?;
    let market = resolve_market(call);

    let obligations_resp = fetch(
        transport,
        &ApiCall::Obligations {
            market: &market,
            wallet: &wallet,
        },
        "obligations",
    )?;
    let obligations = kamino::parse_obligations(&obligations_resp.body)?;
    let obligation = select_obligation(obligations, call.obligation.as_deref(), &wallet)?;

    rescue::refuse_referrer_obligation(obligation.referrer.as_deref())?;

    let prices_resp = fetch(transport, &ApiCall::Prices, "prices")?;
    let prices = kamino::parse_prices(&prices_resp.body)?;
    let now_unix = prices_resp
        .date_header
        .as_deref()
        .map(kamino::http_date_to_unix)
        .transpose()?;

    let metrics_resp = fetch(
        transport,
        &ApiCall::ReservesMetrics { market: &market },
        "reserves metrics",
    )?;
    let metrics = kamino::parse_reserves_metrics(&metrics_resp.body)?;

    let joined = join_facts(&obligation, &prices, &metrics)?;
    let stale = stale_for_joined(&prices, &metrics, &joined, now_unix)?;

    let thresholds_watch = call.config.watch_pct / 100.0;
    let remedies = remedy::rank(&RemedyInput {
        borrow_usd: obligation.borrow_usd,
        deposit_usd: obligation.deposit_usd,
        liq_ltv: obligation.liq_ltv,
        watch: thresholds_watch,
        debt_symbol: joined.debt_symbol.clone(),
        debt_price: joined.debt_price,
        collateral_symbol: joined.collateral_symbol.clone(),
        collateral_price: joined.collateral_price,
        // Deliberately `None`, unlike `assess_obligation`'s use of this
        // same ranker: rescue wants the raw, uncapped Δ here so the
        // explicit `min(computed, requested, max_repay_ui, balance)` below
        // is the single place capping happens — passing `max_repay_ui`
        // through here too would let `remedy::rank` cap it a second time,
        // which only produces a spurious tie against the `max_repay_ui`
        // candidate below (same amount, wrong `capped_by` label).
        max_repay_ui: None,
        collateral_is_falling: false,
    });
    let computed_delta_ui = remedies
        .iter()
        .find(|r| r.kind == RemedyKind::Repay)
        .map(|r| r.ui_amount)
        .ok_or_else(|| {
            "position is already healthy at/above the WATCH threshold; no rescue needed".to_string()
        })?;

    let account_data_resp = fetch(
        transport,
        &ApiCall::ReserveAccountData { market: &market },
        "reserve account data",
    )?;
    let reserve_blobs = parse_reserve_account_data(&account_data_resp.body, &obligation.market)?;

    let mut obligation_reserves: Vec<ReserveAccounts> = Vec::new();
    for row in obligation.deposits.iter().chain(obligation.borrows.iter()) {
        let data = reserve_blobs
            .get(row.reserve.as_str())
            .ok_or_else(|| format!("missing account data for reserve {}", row.reserve))?;
        obligation_reserves.push(rescue::extract_reserve_accounts(
            &row.reserve,
            data,
            &obligation.market,
        )?);
    }

    let repay_accounts = obligation_reserves
        .iter()
        .find(|r| r.reserve == joined.debt_row.reserve)
        .cloned()
        .ok_or_else(|| {
            format!(
                "missing extracted accounts for repay reserve {}",
                joined.debt_row.reserve
            )
        })?;

    // Optional wallet-balance cap: best-effort only. Any failure along this
    // path (derivation, transport error, non-200, malformed body) just
    // leaves `balance_ui` at `None` — never a fatal error for the rescue
    // action. F7: the balance reading is a first-class min-candidate below,
    // never pre-applied to `computed_delta_ui` — so when it's the binding
    // constraint, the label truthfully says `"balance"` instead of
    // `"computed"`.
    let mut balance_ui: Option<f64> = None;
    if let Ok(ata) = rescue::derive_ata(
        &wallet,
        &repay_accounts.liquidity_mint,
        &repay_accounts.token_program,
    ) {
        let balance_req = net::rpc_get_token_account_balance(&call.config.rpc_url, &ata);
        if let Ok(balance_resp) = transport.fetch(&balance_req) {
            if net::check_response(&balance_resp).is_ok() {
                if let Ok(ui) = net::parse_token_balance_response(&balance_resp.body) {
                    balance_ui = Some(ui);
                }
            }
        }
    }

    // amount_native = min(computed repay Δ, requested repay_ui_amount,
    // max_repay_ui, wallet balance) — spec safety invariant 4. `capped_by`
    // names whichever candidate is smallest, so a balance-bound repay is
    // always labeled `"balance"`, truthfully, never `"computed"`.
    let mut candidates: Vec<(&str, f64)> = vec![
        ("computed", computed_delta_ui),
        ("max_repay_ui", max_repay_ui),
    ];
    if let Some(requested) = call.repay_ui_amount {
        candidates.push(("requested", requested));
    }
    if let Some(b) = balance_ui {
        candidates.push(("balance", b));
    }
    let (capped_by, amount_ui) = candidates
        .into_iter()
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .expect("candidates is never empty");

    let (blockhash, nonce_info) = resolve_blockhash(call, transport, &wallet)?;

    let amount_native = ui_to_native(amount_ui, repay_accounts.mint_decimals, "repay")?;

    let tx_options = rescue::TxOptions {
        priority_fee_microlamports: call.config.priority_fee_microlamports,
        nonce: nonce_info,
    };
    let plan = rescue::build_repay_tx(
        &wallet,
        &obligation.obligation,
        &obligation.market,
        &obligation_reserves,
        &joined.debt_row.reserve,
        amount_native,
        &blockhash,
        &tx_options,
    )?;

    let rescue_text = RescueText {
        tx_base64: plan.tx_base64,
        repay_ui: plan.repay_ui,
        debt_symbol: joined.debt_symbol.clone(),
        amount_native: plan.amount_native,
        capped_by: capped_by.to_string(),
        priority_fee_microlamports: call.config.priority_fee_microlamports,
        nonce_account: call.config.nonce_account.clone(),
    };

    let meta = PositionMeta {
        obligation: obligation.obligation.clone(),
        market: obligation.market.clone(),
        collateral_symbol: joined.collateral_symbol,
        debt_symbol: joined.debt_symbol,
        collateral_price: joined.collateral_price,
        debt_price: joined.debt_price,
        stale_price_names: stale,
    };

    let snapshot = kamino::Snapshot {
        v: 1,
        obligation: obligation.obligation.clone(),
        ltv: obligation.ltv,
        liq_ltv: obligation.liq_ltv,
        collateral_price: joined.collateral_price,
        elevation_group: obligation.elevation_group,
        taken_unix: 0,
    };
    let snapshot_str = kamino::encode_snapshot(&snapshot);

    Ok(report::render_rescue(&meta, &rescue_text, &snapshot_str))
}

/// Mirrors [`run_rescue`] for the deposit remedy: same pipeline shape
/// (fail-closed config gate, referrer refusal, facts, cap candidates,
/// balance warning, blockhash/nonce source), but resolves the deposit
/// target as the obligation's dominant *collateral* reserve and calls
/// [`rescue::build_deposit_tx`].
fn run_deposit(call: &ParsedCall, transport: &mut dyn Transport) -> Result<String, String> {
    // Fail-closed gate (amended safety invariant 3/4): no `max_deposit_ui`
    // means the deposit action is disabled outright, before any network I/O.
    let max_deposit_ui = call.config.max_deposit_ui.ok_or_else(|| {
        "deposit disabled: set 'max_deposit_ui' in plugin config to enable it".to_string()
    })?;

    let wallet = resolve_wallet(call)?;
    let market = resolve_market(call);

    let obligations_resp = fetch(
        transport,
        &ApiCall::Obligations {
            market: &market,
            wallet: &wallet,
        },
        "obligations",
    )?;
    let obligations = kamino::parse_obligations(&obligations_resp.body)?;
    let obligation = select_obligation(obligations, call.obligation.as_deref(), &wallet)?;

    rescue::refuse_referrer_obligation(obligation.referrer.as_deref())?;

    let prices_resp = fetch(transport, &ApiCall::Prices, "prices")?;
    let prices = kamino::parse_prices(&prices_resp.body)?;
    let now_unix = prices_resp
        .date_header
        .as_deref()
        .map(kamino::http_date_to_unix)
        .transpose()?;

    let metrics_resp = fetch(
        transport,
        &ApiCall::ReservesMetrics { market: &market },
        "reserves metrics",
    )?;
    let metrics = kamino::parse_reserves_metrics(&metrics_resp.body)?;

    let joined = join_facts(&obligation, &prices, &metrics)?;
    let stale = stale_for_joined(&prices, &metrics, &joined, now_unix)?;

    let thresholds_watch = call.config.watch_pct / 100.0;
    let remedies = remedy::rank(&RemedyInput {
        borrow_usd: obligation.borrow_usd,
        deposit_usd: obligation.deposit_usd,
        liq_ltv: obligation.liq_ltv,
        watch: thresholds_watch,
        debt_symbol: joined.debt_symbol.clone(),
        debt_price: joined.debt_price,
        collateral_symbol: joined.collateral_symbol.clone(),
        collateral_price: joined.collateral_price,
        // Deliberately `None`, mirroring `run_rescue`: the explicit
        // `min(computed, requested, max_deposit_ui, balance)` below is the
        // single place capping happens.
        max_repay_ui: None,
        collateral_is_falling: false,
    });
    // The deposit remedy can be absent for two OPPOSITE reasons, and reporting
    // the healthy one for both was a lie: `remedy::rank` returns nothing at all
    // when the position is at or above the WATCH buffer, but it also omits just
    // the deposit when the target LTV is zero (`liq_ltv == 0` — no deposit of
    // this collateral counts toward the buffer at all). That second case is the
    // state `check` calls CRITICAL, so answering "already healthy" made the
    // three actions contradict each other on the same position.
    let computed_delta_ui = remedies
        .iter()
        .find(|r| r.kind == RemedyKind::Deposit)
        .map(|r| r.ui_amount)
        .ok_or_else(|| {
            if remedies.is_empty() {
                "position is already healthy at/above the WATCH threshold; no deposit needed"
                    .to_string()
            } else {
                "no deposit can restore this position: its liquidation threshold is zero, so \
                 no amount of this collateral counts toward the buffer. Repay is the only \
                 remedy that moves it."
                    .to_string()
            }
        })?;

    let account_data_resp = fetch(
        transport,
        &ApiCall::ReserveAccountData { market: &market },
        "reserve account data",
    )?;
    let reserve_blobs = parse_reserve_account_data(&account_data_resp.body, &obligation.market)?;

    let mut obligation_reserves: Vec<ReserveAccounts> = Vec::new();
    for row in obligation.deposits.iter().chain(obligation.borrows.iter()) {
        let data = reserve_blobs
            .get(row.reserve.as_str())
            .ok_or_else(|| format!("missing account data for reserve {}", row.reserve))?;
        obligation_reserves.push(rescue::extract_reserve_accounts(
            &row.reserve,
            data,
            &obligation.market,
        )?);
    }

    // Deposit reserve = the obligation's dominant collateral reserve
    // (`joined.collateral_row`), which is always one of `obligation.deposits`
    // and therefore always present in `obligation_reserves` above — unlike
    // `build_deposit_tx`'s own contract (which tolerates a reserve absent
    // from `obligation_reserves`), this pipeline's own
    // invariant makes a miss here a genuine bug, so it's a hard error.
    let deposit_accounts = obligation_reserves
        .iter()
        .find(|r| r.reserve == joined.collateral_row.reserve)
        .cloned()
        .ok_or_else(|| {
            format!(
                "missing extracted accounts for deposit reserve {}",
                joined.collateral_row.reserve
            )
        })?;

    // Optional wallet-balance cap: best-effort only, same mechanism as
    // `run_rescue`'s (F7-style truthful `capped_by` label).
    let mut balance_ui: Option<f64> = None;
    if let Ok(ata) = rescue::derive_ata(
        &wallet,
        &deposit_accounts.liquidity_mint,
        &deposit_accounts.token_program,
    ) {
        let balance_req = net::rpc_get_token_account_balance(&call.config.rpc_url, &ata);
        if let Ok(balance_resp) = transport.fetch(&balance_req) {
            if net::check_response(&balance_resp).is_ok() {
                if let Ok(ui) = net::parse_token_balance_response(&balance_resp.body) {
                    balance_ui = Some(ui);
                }
            }
        }
    }

    // amount_native = min(computed deposit Δ, requested deposit_ui_amount,
    // max_deposit_ui, wallet balance) — mirrors `run_rescue`'s safety
    // invariant 4 candidate set exactly.
    let mut candidates: Vec<(&str, f64)> = vec![
        ("computed", computed_delta_ui),
        ("max_deposit_ui", max_deposit_ui),
    ];
    if let Some(requested) = call.deposit_ui_amount {
        candidates.push(("requested", requested));
    }
    if let Some(b) = balance_ui {
        candidates.push(("balance", b));
    }
    let (capped_by, amount_ui) = candidates
        .into_iter()
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .expect("candidates is never empty");

    let (blockhash, nonce_info) = resolve_blockhash(call, transport, &wallet)?;

    let amount_native = ui_to_native(amount_ui, deposit_accounts.mint_decimals, "deposit")?;

    let tx_options = rescue::TxOptions {
        priority_fee_microlamports: call.config.priority_fee_microlamports,
        nonce: nonce_info,
    };
    let plan = rescue::build_deposit_tx(
        &wallet,
        &obligation.obligation,
        &obligation.market,
        &obligation_reserves,
        &deposit_accounts,
        amount_native,
        &blockhash,
        &tx_options,
    )?;

    let deposit_text = DepositText {
        tx_base64: plan.tx_base64,
        deposit_ui: plan.repay_ui,
        collateral_symbol: joined.collateral_symbol.clone(),
        amount_native: plan.amount_native,
        capped_by: capped_by.to_string(),
        priority_fee_microlamports: call.config.priority_fee_microlamports,
        nonce_account: call.config.nonce_account.clone(),
    };

    let meta = PositionMeta {
        obligation: obligation.obligation.clone(),
        market: obligation.market.clone(),
        collateral_symbol: joined.collateral_symbol,
        debt_symbol: joined.debt_symbol,
        collateral_price: joined.collateral_price,
        debt_price: joined.debt_price,
        stale_price_names: stale,
    };

    let snapshot = kamino::Snapshot {
        v: 1,
        obligation: obligation.obligation.clone(),
        ltv: obligation.ltv,
        liq_ltv: obligation.liq_ltv,
        collateral_price: joined.collateral_price,
        elevation_group: obligation.elevation_group,
        taken_unix: 0,
    };
    let snapshot_str = kamino::encode_snapshot(&snapshot);

    Ok(report::render_deposit(&meta, &deposit_text, &snapshot_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRICES_JSON: &str = include_str!("../tests/fixtures/prices.json");

    /// The `f64 as u64` in `ui_to_native` saturates instead of wrapping, so
    /// `overflow-checks` cannot catch a bad amount there. Each input below
    /// silently becomes a real transaction amount (`0` or `u64::MAX`) if the
    /// gate is deleted, so this fails loudly if anyone "simplifies" it back
    /// to a bare cast.
    #[test]
    fn ui_to_native_refuses_amounts_that_do_not_scale() {
        for (amount, why) in [
            (f64::NAN, "NaN casts to 0"),
            (-1.0, "negative casts to 0"),
            (0.0, "zero-amount transaction is not a rescue"),
            (1e30, "saturates to u64::MAX"),
            (f64::INFINITY, "saturates to u64::MAX"),
        ] {
            let out = ui_to_native(amount, 6, "repay");
            assert!(out.is_err(), "{amount} should be refused: {why}");
        }

        // The ordinary path still scales, and rounds rather than truncates.
        assert_eq!(ui_to_native(1.5, 6, "repay").unwrap(), 1_500_000);
        assert_eq!(ui_to_native(0.0000015, 6, "repay").unwrap(), 2);
    }

    /// Ruling A requires each pinned LST mint be verified against the
    /// committed prices fixture rather than invented — this looks each
    /// pinned mint up by its distinct fixture `name` (test-only; runtime
    /// code never branches on payload name strings, only on this const
    /// table — safety invariant 6) and asserts it matches
    /// `PINNED_LST_MINTS`, so a wrong/copied-wrong address fails a test
    /// instead of being caught only by eye.
    #[test]
    fn pinned_lst_mints_match_fixture() {
        let prices = kamino::parse_prices(PRICES_JSON).expect("prices parse");
        let mint_for = |name: &str| -> String {
            prices
                .iter()
                .find(|p| p.name == name)
                .unwrap_or_else(|| panic!("fixture has no price row named {name}"))
                .mint
                .clone()
        };

        // Every pinned mint that has a row in the fixture must match it.
        assert_eq!(
            mint_for("JITOSOL"),
            "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn"
        );
        assert_eq!(
            mint_for("MSOL"),
            "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"
        );
        assert_eq!(
            mint_for("bSOL"),
            "bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1"
        );
        assert_eq!(
            mint_for("JupSOL"),
            "jupSoLaHXQiZZTSfEWMTRRgpnyFm8f6sZdosWBjx93v"
        );
        assert_eq!(
            mint_for("bnSOL"),
            "BNso1VUJnh4zcfpZa6986Ea66P6TCp59hvtNJ8b1X85"
        );
        assert_eq!(mint_for("SOL"), SOL_MINT);

        // Round-trip the other direction: every fixture-verified mint is
        // actually present in the const table.
        for name in ["JITOSOL", "MSOL", "bSOL", "JupSOL", "bnSOL"] {
            let mint = mint_for(name);
            assert!(
                PINNED_LST_MINTS.contains(&mint.as_str()),
                "{name} ({mint}) missing from PINNED_LST_MINTS"
            );
        }

        // INF has no row in this fixture, so it is the one pinned mint this
        // test cannot verify against committed data; it was cross-checked
        // against Sanctum's published Infinity LST mint instead.
        assert!(
            !prices.iter().any(|p| p.name == "INF"),
            "fixture unexpectedly gained an INF row — verify it against \
             PINNED_LST_MINTS directly instead"
        );
    }

    /// `lst_stake_rate_for` only fires for a pinned mint; the rate is
    /// exactly `lst_price / sol_price` from the same prices slice, and a
    /// zero/missing SOL price degrades to `None`, never a fabricated rate.
    #[test]
    fn lst_stake_rate_for_pinned_mint_only() {
        let prices = kamino::parse_prices(PRICES_JSON).expect("prices parse");
        let jitosol_price = prices
            .iter()
            .find(|p| p.mint == "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn")
            .unwrap()
            .price;
        let sol_price = prices.iter().find(|p| p.mint == SOL_MINT).unwrap().price;

        assert_eq!(
            lst_stake_rate_for(
                "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn",
                jitosol_price,
                &prices,
            ),
            Some(jitosol_price / sol_price)
        );

        // Unpinned mint (USDC) never gets a rate.
        assert_eq!(
            lst_stake_rate_for("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 1.0, &prices),
            None
        );

        // Pinned mint but no SOL row in the prices slice -> None, not a
        // fabricated rate.
        let no_sol: Vec<PriceRow> = prices
            .iter()
            .filter(|p| p.mint != SOL_MINT)
            .cloned()
            .collect();
        assert_eq!(
            lst_stake_rate_for(
                "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn",
                jitosol_price,
                &no_sol,
            ),
            None
        );
    }
}
