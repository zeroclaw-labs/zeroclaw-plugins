//! Pure charge core. No wasm dependency — compiles and tests on the host.
//!
//! Custody: T1. This module cannot move funds, sign anything, or reach the
//! network. It renders a Solana Pay URL whose recipient is ALWAYS the
//! operator's configured merchant address. The model chooses an item id or a
//! capped free amount — nothing else.

use std::collections::HashMap;

use kiosk_core::{b58, pay::TransferRequest, shape};

/// Mainnet USDC mint, the shipped default. Operators override in config
/// (e.g. devnet USDC) — never the model.
pub const DEFAULT_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const DEFAULT_MAX_AMOUNT: f64 = 100.0;
pub const USDC_DECIMALS: u8 = 6;

#[derive(Debug)]
pub struct ChargeConfig {
    pub merchant_address: String,
    pub usdc_mint: String,
    /// item id -> decimal amount string, parsed from `price_list`
    /// (`"cold_drink:1.5, snack:0.75"`).
    pub price_list: HashMap<String, String>,
    pub max_amount: f64,
    pub label: Option<String>,
    /// Optional cosmetic fiat display (e.g. "BRL") shown alongside the USDC
    /// amount. The on-chain amount is ALWAYS the USDC figure; this is a static,
    /// operator-set convenience only (no oracle, no price feed).
    pub display_currency: Option<String>,
    /// Static units-of-`display_currency` per 1 USDC. Only used when
    /// `display_currency` is also set.
    pub display_rate: Option<f64>,
}

#[derive(Debug, PartialEq)]
pub enum ChargeError {
    /// Operator config is missing/invalid — refuse to operate at all.
    Config(String),
    /// Caller arguments rejected (unknown item, over cap, malformed).
    Args(String),
}

impl core::fmt::Display for ChargeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChargeError::Config(m) => write!(f, "config error: {m}"),
            ChargeError::Args(m) => write!(f, "invalid request: {m}"),
        }
    }
}

impl ChargeConfig {
    /// Build from the flat `string -> string` section the host injects as
    /// `__config`. Fail closed: without a valid merchant address this plugin
    /// refuses to produce anything.
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, ChargeError> {
        let merchant_address = section
            .get("merchant_address")
            .cloned()
            .ok_or_else(|| ChargeError::Config("merchant_address is required".into()))?;
        if b58::decode_pubkey(&merchant_address).is_none() {
            return Err(ChargeError::Config(
                "merchant_address is not a valid 32-byte base58 pubkey".into(),
            ));
        }
        let usdc_mint = section
            .get("usdc_mint")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_USDC_MINT.to_string());
        if b58::decode_pubkey(&usdc_mint).is_none() {
            return Err(ChargeError::Config(
                "usdc_mint is not a valid pubkey".into(),
            ));
        }
        let mut price_list = HashMap::new();
        if let Some(raw) = section.get("price_list") {
            for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                let (item, amount) = entry
                    .split_once(':')
                    .ok_or_else(|| ChargeError::Config(format!("bad price entry `{entry}`")))?;
                price_list.insert(item.trim().to_string(), amount.trim().to_string());
            }
        }
        let max_amount = match section.get("max_amount_usdc") {
            Some(v) => v
                .parse::<f64>()
                .ok()
                .filter(|m| *m > 0.0)
                .ok_or_else(|| ChargeError::Config("max_amount_usdc must be > 0".into()))?,
            None => DEFAULT_MAX_AMOUNT,
        };
        let display_currency = section
            .get("display_currency")
            .filter(|v| !v.is_empty())
            .cloned();
        let display_rate = match section.get("display_rate").filter(|v| !v.is_empty()) {
            Some(v) => Some(
                v.parse::<f64>()
                    .ok()
                    .filter(|r| r.is_finite() && *r > 0.0)
                    .ok_or_else(|| {
                        ChargeError::Config("display_rate must be a positive number".into())
                    })?,
            ),
            None => None,
        };
        Ok(Self {
            merchant_address,
            usdc_mint,
            price_list,
            max_amount,
            label: section.get("label").filter(|v| !v.is_empty()).cloned(),
            display_currency,
            display_rate,
        })
    }
}

/// Arguments the model may pass. `deny_unknown_fields` makes smuggled keys
/// (`recipient`, `mint`, …) a hard error — injection drill case #4.
#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ChargeArgs {
    /// Item id from the operator's price list (preferred).
    pub item_id: Option<String>,
    /// Free amount in USDC as a decimal string; only when no item_id, and
    /// always bounded by the operator's `max_amount_usdc`.
    pub amount_usdc: Option<String>,
    /// Short free-text note shown in the wallet (percent-encoded, inert).
    pub note: Option<String>,
}

#[derive(Debug)]
pub struct ChargeOutput {
    pub url: String,
    pub reference: String,
    pub amount: String,
    pub item: Option<String>,
    /// Human/LLM-facing summary, token-budgeted.
    pub summary: String,
}

/// Build a charge. `reference32` and `now_ms` are supplied by the shim (or the
/// test) so this core stays fully deterministic.
pub fn execute_charge(
    args: &ChargeArgs,
    cfg: &ChargeConfig,
    reference32: [u8; 32],
    _now_ms: u64,
) -> Result<ChargeOutput, ChargeError> {
    let (amount, item): (String, Option<String>) = match (&args.item_id, &args.amount_usdc) {
        (Some(item), _) => {
            let price = cfg
                .price_list
                .get(item)
                .ok_or_else(|| ChargeError::Args(format!("unknown item `{item}`")))?;
            (price.clone(), Some(item.clone()))
        }
        (None, Some(amount)) => (amount.clone(), None),
        (None, None) => return Err(ChargeError::Args("provide item_id or amount_usdc".into())),
    };

    let reference = b58::encode(&reference32);
    let note = args.note.as_deref().map(|n| {
        let mut n = n.to_string();
        n.truncate(64);
        n
    });
    let request = TransferRequest::new(
        &cfg.merchant_address,
        &amount,
        USDC_DECIMALS,
        cfg.max_amount,
        Some(&cfg.usdc_mint),
        Some(&reference),
        cfg.label.as_deref(),
        note.as_deref(),
        item.as_deref(),
    )
    .map_err(|e| ChargeError::Args(e.to_string()))?;

    let url = request.url();
    let what = item.clone().unwrap_or_else(|| "custom amount".to_string());
    // Optional cosmetic fiat hint (e.g. "≈ BRL 7.50"). Never changes the
    // on-chain amount — that is always the USDC figure above.
    let fiat = match (&cfg.display_currency, cfg.display_rate) {
        (Some(cur), Some(rate)) => amount
            .parse::<f64>()
            .ok()
            .map(|a| format!(" (≈ {cur} {:.2})", a * rate))
            .unwrap_or_default(),
        _ => String::new(),
    };
    let summary = shape::clamp(
        &format!(
            "Charge created: {amount} USDC{fiat} for `{what}`. Show this Solana Pay link/QR to the customer. Reference for payment-watch: {reference}. URL: {url}"
        ),
        shape::DEFAULT_BUDGET_TOKENS,
    );

    Ok(ChargeOutput {
        url,
        reference,
        amount,
        item,
        summary,
    })
}
