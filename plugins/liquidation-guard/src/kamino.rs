//! Kamino Lend API payload parsing, obligation→facts mapping, and the
//! snapshot codec.
//!
//! Pure parsing + mapping only: no I/O lives here (the `net` module fetches;
//! this module turns response bodies into plain facts). Every JSON payload
//! shape below was verified against a live capture (see
//! `tests/fixtures/*.json`); every numeric field in the Kamino API arrives
//! as a JSON **string** and is parsed explicitly — never trust the wire
//! type.

use serde::{Deserialize, Serialize};

/// All-zero system-program pubkey used by Kamino as a "no reserve" /
/// "no referrer" placeholder sentinel.
const ZERO_PUBKEY: &str = "11111111111111111111111111111111";

// ---------------------------------------------------------------------
// Public facts types (interface contract — frozen; downstream slices
// compile against these).
// ---------------------------------------------------------------------

/// One obligation, mapped from the raw API payload to plain facts.
#[derive(Debug, Clone)]
pub struct ObligationFacts {
    pub obligation: String,
    pub market: String,
    pub owner: String,
    /// Fraction (not percent): `userTotalBorrowBorrowFactorAdjusted /
    /// userTotalLiquidatableDeposit`.
    pub ltv: f64,
    /// Fraction (not percent): `refreshedStats.liquidationLtv`.
    pub liq_ltv: f64,
    /// `userTotalBorrowBorrowFactorAdjusted`.
    pub borrow_usd: f64,
    /// `userTotalLiquidatableDeposit`.
    pub deposit_usd: f64,
    /// `None` when `state.referrer` is the all-zero sentinel.
    pub referrer: Option<String>,
    pub elevation_group: u8,
    /// `state.deposits`, fixed-size placeholder rows filtered out.
    pub deposits: Vec<PositionRow>,
    /// `state.borrows`, fixed-size placeholder rows filtered out.
    pub borrows: Vec<PositionRow>,
    /// `market.state.autodeleverageEnabled` (market-level, not per-reserve).
    pub market_adl_enabled: bool,
    /// `market.state.minFullLiquidationValueThreshold`; `None` when the
    /// payload doesn't carry it — the dust check is suppressed, never
    /// defaulted.
    pub min_full_liquidation_value_usd: Option<f64>,
}

/// One real (non-placeholder) deposit or borrow row.
#[derive(Debug, Clone)]
pub struct PositionRow {
    pub reserve: String,
    /// `marketValueSf / 2^60` — last-crank composition value; use only to
    /// compare rows within a position, never as a total (totals come from
    /// `refreshedStats`).
    pub usd_value: f64,
    /// Raw on-chain amount, passed through as a string (deposits:
    /// `depositedAmount`; borrows: `borrowedAmountSf`) — not interpreted
    /// here.
    pub raw_amount: String,
}

/// One row of `/oracles/prices`.
#[derive(Debug, Clone)]
pub struct PriceRow {
    pub mint: String,
    pub name: String,
    pub price: f64,
    pub timestamp: i64,
    pub max_age_s: i64,
}

/// One row of `/kamino-market/{m}/reserves/metrics` — the only
/// reserve→mint/symbol mapping source.
#[derive(Debug, Clone)]
pub struct ReserveMetrics {
    pub reserve: String,
    pub mint: String,
    pub symbol: String,
    pub borrow_apy: f64,
    /// `totalBorrow / totalSupply`, `None` when supply is zero.
    pub utilization: Option<f64>,
}

/// Opaque, versioned snapshot carried across calls by the caller
/// (`prev_snapshot`). All fields public but callers must treat the encoded
/// string as opaque.
///
/// `obligation` binds a snapshot to the specific obligation it was taken
/// from (F6): the caller filters a decoded snapshot against the obligation
/// under assessment and drops it (falls back to "no prior snapshot") on any
/// mismatch, so a snapshot from one obligation can never be diffed against
/// another. Old-format snapshots that predate this field simply fail to
/// deserialize (a required field is missing), which already degrades to
/// `None` via `decode_snapshot`'s any-failure-is-None contract — no version
/// bump needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub v: u8,
    pub obligation: String,
    pub ltv: f64,
    pub liq_ltv: f64,
    pub collateral_price: f64,
    pub elevation_group: u8,
    pub taken_unix: i64,
}

// ---------------------------------------------------------------------
// Raw wire shapes (private — tolerant to extra fields by construction:
// no `deny_unknown_fields`, and only the fields actually consumed are
// declared).
// ---------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawObligation {
    obligation_address: String,
    market: RawMarket,
    refreshed_stats: RawRefreshedStats,
    state: RawState,
    // NOTE: the top-level `deposits`/`borrows` keys on this payload are
    // always empty objects `{}` — intentionally not mapped to a field
    // here; the real rows live at `state.deposits` / `state.borrows`.
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMarket {
    address: String,
    state: RawMarketState,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMarketState {
    /// JSON number (`0`/`1`), not a JSON bool — Kamino's wire shape.
    autodeleverage_enabled: u8,
    /// JSON string, like every Kamino numeric; `None` when the payload
    /// omits the key (missing != zero — never defaulted).
    min_full_liquidation_value_threshold: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRefreshedStats {
    liquidation_ltv: String,
    user_total_borrow_borrow_factor_adjusted: String,
    user_total_liquidatable_deposit: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawState {
    owner: String,
    referrer: String,
    elevation_group: u8,
    deposits: Vec<RawDeposit>,
    borrows: Vec<RawBorrow>,
    // NOTE (safety invariant 8): `state.lastUpdate.stale` is the on-chain
    // inter-crank marker — a live capture observed it as `1` on a fully
    // healthy obligation, so it is never a liquidation-risk signal and is
    // intentionally not deserialized or branched on anywhere in this
    // module. The only staleness clock is the prices-response HTTP `Date`
    // header vs. each price row's own `timestamp`/`maxAgeInSeconds` (see
    // `http_date_to_unix` / `price_is_stale`).
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDeposit {
    deposit_reserve: String,
    deposited_amount: String,
    market_value_sf: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBorrow {
    borrow_reserve: String,
    borrowed_amount_sf: String,
    market_value_sf: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPrice {
    mint: String,
    name: String,
    max_age_in_seconds: String,
    price: String,
    timestamp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawReserveMetric {
    reserve: String,
    liquidity_token: String,
    liquidity_token_mint: String,
    borrow_apy: String,
    total_borrow: String,
    total_supply: String,
}

// ---------------------------------------------------------------------
// Parsing entry points.
// ---------------------------------------------------------------------

/// Parses an `/obligations` list response body into plain facts.
///
/// Tolerant to extra payload fields; a required field missing from any row
/// produces a typed `Err` naming that field (via serde's own message).
pub fn parse_obligations(body: &str) -> Result<Vec<ObligationFacts>, String> {
    let raw: Vec<RawObligation> = serde_json::from_str(body).map_err(|e| e.to_string())?;

    // STRICT: one unmappable row fails the whole list.
    //
    // A per-entry "drop the bad row and carry on" pass was tried here and was
    // wrong, because this endpoint is
    // `/kamino-market/{market}/users/{wallet}/obligations` — every row is one
    // of the USER'S OWN positions, not an unrelated sibling. Dropping one
    // removes a candidate, and removing a candidate is exactly what turns
    // `select_obligation`'s "multiple obligations found; specify 'obligation'"
    // refusal into a silent single pick: a wallet holding a safe position and
    // a leveraged one, where the leveraged row is the malformed one, would get
    // a confident healthy verdict about the *other* position. That is the
    // precise fail-open this parser exists to prevent.
    //
    // Failing closed costs availability against a hostile API, which can stop
    // the watcher by returning a single bad row. That trade is still right:
    // such an API can deny service by any means (garbage, 500s, silence), so
    // availability was never defensible here — a confident verdict about the
    // wrong position is what must be impossible.
    raw.into_iter().map(map_obligation).collect()
}

/// Parses an `/oracles/prices` list response body.
pub fn parse_prices(body: &str) -> Result<Vec<PriceRow>, String> {
    let raw: Vec<RawPrice> = serde_json::from_str(body).map_err(|e| e.to_string())?;
    raw.into_iter().map(map_price).collect()
}

/// Parses a `/reserves/metrics` list response body.
pub fn parse_reserves_metrics(body: &str) -> Result<Vec<ReserveMetrics>, String> {
    let raw: Vec<RawReserveMetric> = serde_json::from_str(body).map_err(|e| e.to_string())?;
    raw.into_iter().map(map_reserve_metric).collect()
}

fn map_obligation(raw: RawObligation) -> Result<ObligationFacts, String> {
    let borrow_usd = parse_num(
        &raw.refreshed_stats.user_total_borrow_borrow_factor_adjusted,
        "userTotalBorrowBorrowFactorAdjusted",
    )?;
    let deposit_usd = parse_num(
        &raw.refreshed_stats.user_total_liquidatable_deposit,
        "userTotalLiquidatableDeposit",
    )?;
    let liq_ltv = parse_num(&raw.refreshed_stats.liquidation_ltv, "liquidationLtv")?;
    // LTV for all health math is the BF-adjusted ratio, not the payload's
    // own `loanToValue` field (equal when every borrow has BF=1).
    //
    // Zero liquidatable deposit with debt still outstanding is the *most*
    // liquidatable state there is, not the safest: it is what an obligation
    // looks like after governance drops a collateral asset's liquidation
    // threshold to zero. Reporting `ltv = 0` there made `buffer` 100% and the
    // tier `OK` — a fabricated healthy verdict on a position that is past
    // every threshold. Infinity is the honest ratio and drives the tier to
    // CRITICAL. Zero deposit AND zero debt is a genuinely empty obligation,
    // where zero is correct.
    let ltv = if deposit_usd != 0.0 {
        borrow_usd / deposit_usd
    } else if borrow_usd > 0.0 {
        f64::INFINITY
    } else {
        0.0
    };

    let referrer = if raw.state.referrer == ZERO_PUBKEY {
        None
    } else {
        Some(parse_pubkey(raw.state.referrer, "state.referrer")?)
    };

    let market_adl_enabled = raw.market.state.autodeleverage_enabled != 0;
    let min_full_liquidation_value_usd = raw
        .market
        .state
        .min_full_liquidation_value_threshold
        .as_deref()
        .map(|s| parse_num(s, "minFullLiquidationValueThreshold"))
        .transpose()?;

    let deposits = raw
        .state
        .deposits
        .into_iter()
        .filter(|d| d.deposit_reserve != ZERO_PUBKEY)
        .map(|d| {
            Ok(PositionRow {
                usd_value: sf_to_usd(&d.market_value_sf)?,
                reserve: parse_pubkey(d.deposit_reserve, "depositReserve")?,
                raw_amount: d.deposited_amount,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let borrows = raw
        .state
        .borrows
        .into_iter()
        .filter(|b| b.borrow_reserve != ZERO_PUBKEY)
        .map(|b| {
            Ok(PositionRow {
                usd_value: sf_to_usd(&b.market_value_sf)?,
                reserve: parse_pubkey(b.borrow_reserve, "borrowReserve")?,
                raw_amount: b.borrowed_amount_sf,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(ObligationFacts {
        obligation: parse_pubkey(raw.obligation_address, "obligationAddress")?,
        market: parse_pubkey(raw.market.address, "market.address")?,
        owner: parse_pubkey(raw.state.owner, "state.owner")?,
        ltv,
        liq_ltv,
        borrow_usd,
        deposit_usd,
        referrer,
        elevation_group: raw.state.elevation_group,
        deposits,
        borrows,
        market_adl_enabled,
        min_full_liquidation_value_usd,
    })
}

fn map_price(raw: RawPrice) -> Result<PriceRow, String> {
    Ok(PriceRow {
        price: parse_num(&raw.price, "price")?,
        timestamp: parse_int(&raw.timestamp, "timestamp")?,
        max_age_s: parse_int(&raw.max_age_in_seconds, "maxAgeInSeconds")?,
        mint: parse_pubkey(raw.mint, "mint")?,
        // Rendered into model-visible output by the stale-data line.
        name: sanitize_display(&raw.name),
    })
}

fn map_reserve_metric(raw: RawReserveMetric) -> Result<ReserveMetrics, String> {
    let borrow_apy = parse_num(&raw.borrow_apy, "borrowApy")?;
    let total_borrow = parse_num(&raw.total_borrow, "totalBorrow")?;
    let total_supply = parse_num(&raw.total_supply, "totalSupply")?;
    let utilization = if total_supply != 0.0 {
        Some(total_borrow / total_supply)
    } else {
        None
    };
    Ok(ReserveMetrics {
        reserve: parse_pubkey(raw.reserve, "reserve")?,
        mint: parse_pubkey(raw.liquidity_token_mint, "liquidityTokenMint")?,
        // Rendered into model-visible output on every remedy/forecast line.
        symbol: sanitize_display(&raw.liquidity_token),
        borrow_apy,
        utilization,
    })
}

/// Longest payload string ever echoed back in an error or rendered into
/// model-visible output. Untrusted payload text is both an injection vector
/// and an exfiltration channel, so it is always truncated.
const MAX_ECHO_LEN: usize = 48;

/// Cap on a payload string RENDERED into model-visible output. Deliberately
/// separate from [`MAX_ECHO_LEN`]: the two answer different questions (how
/// much of a bad value to quote back in an error, versus how much of a symbol
/// to display), and the longest real symbol or price name observed live is 18
/// characters, so this is already generous.
const MAX_DISPLAY_LEN: usize = 32;

/// Renders an untrusted payload string safely inside an error message:
/// truncated and `Debug`-escaped, so control characters cannot forge output
/// lines and an oversized value cannot flood the model's context.
fn echo(s: &str) -> String {
    let clipped: String = s.chars().take(MAX_ECHO_LEN).collect();
    if s.chars().count() > MAX_ECHO_LEN {
        format!("{clipped:?}...")
    } else {
        format!("{clipped:?}")
    }
}

/// Sanitizes a payload-supplied *display* string (a token symbol or price
/// name) before it can reach model-visible output.
///
/// These are the only payload strings rendered verbatim by `report`, and a
/// raw one is a prompt-injection vector: real newlines let a hostile
/// `liquidityToken` forge additional report lines (including a fake
/// `snapshot:` line, which is this plugin's own last line), and ANSI escapes
/// let it rewrite a terminal. Control characters — newlines and `ESC`
/// included — collapse to a space, and the result is length-capped. Escaping
/// at the parse boundary means every downstream renderer inherits it.
fn sanitize_display(s: &str) -> String {
    // An ALLOWLIST, not a blocklist. Every real Kamino symbol and price name
    // is plain ASCII alphanumeric — verified across all 116 live rows of
    // /reserves/metrics and /oracles/prices — whereas blocklisting has to
    // chase an open-ended set: `char::is_control` catches newline and ESC but
    // NOT the zero-width, bidi-override and line/paragraph separators
    // (U+200B, U+202E, U+2028, U+FEFF …) that also forge lines or visually
    // reverse the text around them.
    //
    // Disallowed characters become '?' rather than being dropped, so a hostile
    // symbol is *visibly* mangled instead of silently vanishing.
    let cleaned: String = s
        .chars()
        .take(MAX_DISPLAY_LEN)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | '/' | ' ') {
                c
            } else {
                '?'
            }
        })
        .collect();
    // Never hand back something that renders as blank: an all-whitespace
    // symbol would leave "Repay 5.0   -> LTV ..." naming no asset at all.
    if cleaned.trim().is_empty() {
        return "?".to_string();
    }
    cleaned
}

/// Requires a payload field to be a base58 32-byte pubkey.
///
/// Every identifier this module hands downstream ends up in a transaction,
/// a URL, or an error message, so the shape is enforced at the trust
/// boundary rather than at each use. This is also what keeps an identifier
/// from carrying injection text: base58 has no newline, no quote, and no
/// `/?&#`.
fn parse_pubkey(s: String, field: &str) -> Result<String, String> {
    match crate::config::validate_base58_32(&s) {
        Ok(()) => Ok(s),
        Err(()) => Err(format!(
            "invalid `{field}` value: not a base58 32-byte pubkey: {}",
            echo(&s)
        )),
    }
}

/// Parses a Kamino API decimal string into `f64`, naming the field on
/// failure.
///
/// Rejects non-finite and negative values. Rust's `f64::from_str` accepts
/// `"NaN"`, `"inf"` and `"1e400"`, and none of the health math guards
/// against them: a negative or `-inf` borrow total drives `buffer` above
/// every threshold and reports a maximally unhealthy position as `OK`
/// (fail-OPEN). No money, ratio, price or APY field this parser feeds can
/// legitimately be negative or infinite.
fn parse_num(s: &str, field: &str) -> Result<f64, String> {
    let v: f64 = s
        .parse()
        .map_err(|_| format!("invalid `{field}` value: {}", echo(s)))?;
    if !v.is_finite() || v < 0.0 {
        return Err(format!(
            "invalid `{field}` value: must be finite and non-negative: {}",
            echo(s)
        ));
    }
    Ok(v)
}

/// Parses a Kamino API integer string into `i64`, naming the field on
/// failure. Bounded to a sane epoch-seconds range: these values feed
/// `i64` arithmetic in `price_is_stale`, and `overflow-checks` turns an
/// extreme value into a wasm trap rather than an error.
fn parse_int(s: &str, field: &str) -> Result<i64, String> {
    let v: i64 = s
        .parse()
        .map_err(|_| format!("invalid `{field}` value: {}", echo(s)))?;
    if !(0..=MAX_UNIX_SECONDS).contains(&v) {
        return Err(format!(
            "invalid `{field}` value: outside the supported range: {}",
            echo(s)
        ));
    }
    Ok(v)
}

/// Upper bound for any payload/header-derived epoch-seconds value (year
/// ~5138). Keeps every downstream `i64` time computation far from overflow.
const MAX_UNIX_SECONDS: i64 = 100_000_000_000;

/// `marketValueSf` (a decimal-string integer scaled by 2^60) to USD.
/// Precision loss from the f64 string-parse is fine for display math; per
/// spec these values are last-on-chain-crank and only ever used for
/// per-position composition, never totals.
fn sf_to_usd(sf: &str) -> Result<f64, String> {
    let raw = parse_num(sf, "marketValueSf")?;
    Ok(raw / (1u128 << 60) as f64)
}

// ---------------------------------------------------------------------
// Staleness clock: the wasm world has no clock, so the prices response's
// own HTTP `Date` header is the only time source (safety invariant 8).
// ---------------------------------------------------------------------

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Parses an RFC-1123 HTTP `Date` header (e.g. `Sat, 18 Jul 2026 15:31:07
/// GMT`) into a unix timestamp. Hand-rolled over the fixed format the
/// Kamino API always sends — no chrono dependency.
pub fn http_date_to_unix(date_header: &str) -> Result<i64, String> {
    let parts: Vec<&str> = date_header.split_whitespace().collect();
    let [_dow, day, mon, year, time, tz] = parts[..] else {
        return Err(format!("malformed HTTP date: {date_header:?}"));
    };
    if tz != "GMT" {
        return Err(format!("expected GMT timezone: {date_header:?}"));
    }
    // EVERY numeric field is range-checked before any arithmetic. The `Date`
    // header is set by whatever serves the response, and each of these feeds
    // an unchecked multiply — `days_from_civil`'s `era * 146_097` and
    // `doy + d`, then `days * 86_400 + hour * 3600 + min * 60`. With
    // `overflow-checks` on in release an overflow is a wasm TRAP, not an
    // error, which would break `guard::run`'s never-panics contract from a
    // single hostile header. Bounding only the year left four open: an
    // absurd day, hour, minute or second still trapped.
    //
    // The bounds are just the real RFC-1123 ranges, so this is ordinary
    // format validation that happens to close the trap. `sec` allows 60 for
    // a leap second.
    let day = bounded_date_field(day, 1, 31, "day", date_header)?;
    let month = MONTHS
        .iter()
        .position(|m| *m == mon)
        .ok_or_else(|| format!("bad month in HTTP date: {date_header:?}"))? as i64
        + 1;
    let year = bounded_date_field(year, 1970, 5000, "year", date_header)?;

    let mut hms = time.split(':');
    let (h, m, s) = (hms.next(), hms.next(), hms.next());
    let (Some(h), Some(m), Some(s)) = (h, m, s) else {
        return Err(format!("bad time in HTTP date: {date_header:?}"));
    };
    let hour = bounded_date_field(h, 0, 23, "hour", date_header)?;
    let min = bounded_date_field(m, 0, 59, "minute", date_header)?;
    let sec = bounded_date_field(s, 0, 60, "second", date_header)?;

    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Parses one numeric field of an HTTP `Date` header and requires it to fall
/// inside its real calendar range. Both halves matter: the parse rejects
/// non-numeric text, and the range is what keeps the value away from the
/// unchecked multiplications in [`http_date_to_unix`] and
/// [`days_from_civil`], where `overflow-checks` would turn an extreme value
/// into a wasm trap instead of this typed error.
fn bounded_date_field(
    raw: &str,
    lo: i64,
    hi: i64,
    field: &str,
    date_header: &str,
) -> Result<i64, String> {
    let v: i64 = raw
        .parse()
        .map_err(|_| format!("bad {field} in HTTP date: {date_header:?}"))?;
    if !(lo..=hi).contains(&v) {
        return Err(format!(
            "{field} out of range {lo}..={hi} in HTTP date: {date_header:?}"
        ));
    }
    Ok(v)
}

/// Howard Hinnant's `days_from_civil`: proleptic-Gregorian (year, month,
/// day) to days since the unix epoch. Public-domain algorithm; correct for
/// all dates the HTTP `Date` header can carry.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// True when a price row is stale as of `now_unix` (normally
/// `http_date_to_unix` of the same prices response's `Date` header).
/// `saturating_sub` rather than `-`: `parse_int` already bounds every
/// payload timestamp, but this is `pub` and one unchecked subtraction here
/// would be a wasm trap under `overflow-checks`, not a typed error.
pub fn price_is_stale(now_unix: i64, row: &PriceRow) -> bool {
    now_unix.saturating_sub(row.timestamp) > row.max_age_s
}

// ---------------------------------------------------------------------
// Snapshot codec.
// ---------------------------------------------------------------------

/// Encodes a snapshot to its opaque wire form. Never fails: on a non-finite
/// field, returns an empty string, which `decode_snapshot` then treats as
/// "no prior" like any other garbled input.
///
/// The non-finite check is explicit because `serde_json::to_string` does not
/// fail on one — it writes `null`, so `unwrap_or_default` never fires. That
/// produced a snapshot which *looked* valid, showed `"ltv":null` in the tool
/// output, and could never be decoded back. An infinite `ltv` is reachable:
/// it is how `map_obligation` reports debt outstanding against zero
/// liquidatable deposit. Returning nothing is the honest encoding of "no
/// snapshot to carry forward".
pub fn encode_snapshot(s: &Snapshot) -> String {
    if !(s.ltv.is_finite() && s.liq_ltv.is_finite() && s.collateral_price.is_finite()) {
        return String::new();
    }
    serde_json::to_string(s).unwrap_or_default()
}

/// Decodes a snapshot from its opaque wire form. A spec invariant: ANY
/// failure (garbled string, wrong version, truncated JSON) degrades to
/// `None` — "no prior snapshot" — never an `Err`; the caller's call still
/// succeeds.
pub fn decode_snapshot(s: &str) -> Option<Snapshot> {
    serde_json::from_str(s).ok()
}
