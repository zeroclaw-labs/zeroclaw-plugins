//! Pure invoice-status core. No wit-bindgen or wasm dependency so it compiles
//! and tests on the host with a plain `cargo test`, while the wasm component
//! reuses the exact same logic through `lib.rs`.
//!
//! Network I/O is injected via [`HttpTransport`] so host tests can pass
//! fixture [`SignatureInfo`] lists to [`evaluate_status`] without HTTP.

use std::cmp::Ordering;
use std::collections::HashMap;

use serde_json::Value;
use solana_wasm_core::amount::compare_units_to_decimal;
use solana_wasm_core::{
    derive_reference, status_from_signatures, status_from_signatures_verified, HttpTransport,
    RpcClient, SignatureInfo, UsdcReceipt, USDC_MINT,
};

/// Default Solana mainnet public RPC (operator should override in production).
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// Default `getSignaturesForAddress` lookback when the tool call omits it.
pub const DEFAULT_LOOKBACK: u64 = 25;

/// Hard ceiling on `getTransaction` calls in one status check, so a caller
/// passing an enormous `lookback` cannot turn one tool call into hundreds of
/// RPC requests.
///
/// Every successful signature the lookback returned is checked up to this
/// bound, so in practice the window is `lookback` itself (default
/// [`DEFAULT_LOOKBACK`] = 25) and the ceiling only binds above 64.
///
/// It used to be 5, which was the bug: six successful dust transactions on the
/// reference pushed a genuine older payment out of the checked window, and a
/// paid invoice reported PENDING for the price of six network fees.
///
/// A ceiling is still a window, and pretending otherwise would be the same
/// mistake one size larger. When it truncates the scan, the signatures left
/// unchecked are counted, and the verdict degrades to
/// `SIG OK (valor não verificado)` rather than asserting a shortfall the tool
/// did not establish.
pub const MAX_VALUE_CHECKS: usize = 64;

/// Plugin config resolved from the host-injected `__config` section.
#[derive(Debug, Clone)]
pub struct StatusConfig {
    pub rpc_url: String,
    pub merchant_solana: String,
    pub usdc_mint: String,
}

impl Default for StatusConfig {
    fn default() -> Self {
        Self {
            rpc_url: DEFAULT_RPC_URL.to_string(),
            merchant_solana: String::new(),
            usdc_mint: USDC_MINT.to_string(),
        }
    }
}

impl StatusConfig {
    /// Build from the flat `string -> string` section the host injects.
    /// Absent or empty keys fall back to defaults.
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        let mut cfg = Self::default();
        if let Some(v) = map.get("rpc_url").filter(|s| !s.trim().is_empty()) {
            cfg.rpc_url = v.trim().to_string();
        }
        if let Some(v) = map.get("merchant_solana") {
            cfg.merchant_solana = v.trim().to_string();
        }
        if let Some(v) = map.get("usdc_mint").filter(|s| !s.trim().is_empty()) {
            cfg.usdc_mint = v.trim().to_string();
        }
        cfg
    }

    /// Alias used by callers that already hold a config section map.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        Self::from_map(section)
    }
}

/// Tool-call request for a dual-rail invoice status check.
#[derive(Debug, Clone)]
pub struct StatusRequest {
    pub invoice_id: String,
    pub reference: Option<String>,
    pub expected_usdc: Option<String>,
    pub pix_marked_paid: bool,
    pub lookback: u64,
}

impl Default for StatusRequest {
    fn default() -> Self {
        Self {
            invoice_id: String::new(),
            reference: None,
            expected_usdc: None,
            pix_marked_paid: false,
            lookback: DEFAULT_LOOKBACK,
        }
    }
}

impl StatusRequest {
    /// Effective lookback for RPC (`0` → [`DEFAULT_LOOKBACK`]).
    pub fn effective_lookback(&self) -> u64 {
        if self.lookback == 0 {
            DEFAULT_LOOKBACK
        } else {
            self.lookback
        }
    }
}

/// Resolve the Solana Pay reference used as the watch address.
///
/// Prefer an explicit `reference` when provided; otherwise derive one from
/// `invoice_id` + merchant pubkey via [`derive_reference`].
pub fn resolve_reference(
    invoice_id: &str,
    reference: Option<&str>,
    merchant_solana: &str,
) -> Result<String, String> {
    if let Some(r) = reference.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(r.to_string());
    }
    let id = invoice_id.trim();
    if id.is_empty() {
        return Err(
            "invoice_status: provide invoice_id (with merchant_solana in config) or reference"
                .to_string(),
        );
    }
    let merchant = merchant_solana.trim();
    if merchant.is_empty() {
        return Err(
            "invoice_status: merchant_solana is required in config to derive reference when reference is omitted"
                .to_string(),
        );
    }
    Ok(derive_reference(id, merchant))
}

/// Pure path for tests: given signatures, produce the status string.
///
/// Resolves the reference first; on resolution failure returns the error text
/// so callers (and the wasm shim) can surface it without panicking.
pub fn evaluate_status(req: &StatusRequest, cfg: &StatusConfig, sigs: &[SignatureInfo]) -> String {
    let reference = match resolve_reference(
        &req.invoice_id,
        req.reference.as_deref(),
        &cfg.merchant_solana,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };

    status_from_signatures(
        &req.invoice_id,
        &reference,
        sigs,
        req.expected_usdc.as_deref(),
        req.pix_marked_paid,
    )
}

/// Pure verified path for tests: given signatures and an already-resolved
/// [`UsdcReceipt`] (from `getTransaction`), produce the value-aware status.
///
/// `verified == None` means the amount could not be confirmed (RPC didn't
/// return the transaction), which degrades honestly to `USDC: SIG OK` — never
/// to PAID.
pub fn evaluate_status_verified(
    req: &StatusRequest,
    cfg: &StatusConfig,
    sigs: &[SignatureInfo],
    verified: Option<UsdcReceipt>,
) -> String {
    let reference = match resolve_reference(
        &req.invoice_id,
        req.reference.as_deref(),
        &cfg.merchant_solana,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };

    status_from_signatures_verified(
        &req.invoice_id,
        &reference,
        sigs,
        verified,
        req.expected_usdc.as_deref(),
        req.pix_marked_paid,
    )
}

/// Fetch signatures for the invoice reference over `http`, then verify the
/// amount actually received by the merchant and evaluate status.
///
/// Flow: `getSignaturesForAddress(reference, lookback)` → **every** successful
/// signature it returned → `getTransaction(sig)` each → exact integer sum of
/// the net USDC received by `merchant_solana` for `usdc_mint` → value-aware
/// verdict + shareable receipt when paid.
///
/// Scanning all of them, rather than the newest few, is what stops cheap spam
/// from hiding a real payment: anyone can emit dust transactions naming the
/// invoice reference, and a window smaller than the lookback would let six of
/// them bury the transfer that actually settled the invoice. RPC cost stays
/// bounded by `lookback` (default 25) and by [`MAX_VALUE_CHECKS`], and the scan
/// **stops early** as soon as the running total reaches `expected_usdc`, so the
/// common settled case still costs a couple of calls.
///
/// The amount cannot be confirmed — and the status degrades to
/// `USDC: SIG OK (valor não verificado …)`, never to PAID — when the merchant
/// pubkey is unknown, when `getTransaction` fails or omits the transaction,
/// when the transactions that did arrive disagree on the mint's decimals, or
/// when part of the scan could not be read and the running total does not yet
/// cover `expected_usdc`. That last case is why the incomplete scan is
/// counted: a partial total is a lower bound, and a lower bound may confirm a
/// payment but may never be published as a shortfall.
pub fn fetch_and_status<T: HttpTransport>(
    req: &StatusRequest,
    cfg: &StatusConfig,
    http: T,
) -> Result<String, String> {
    let reference = resolve_reference(
        &req.invoice_id,
        req.reference.as_deref(),
        &cfg.merchant_solana,
    )?;

    if cfg.rpc_url.trim().is_empty() {
        return Err("invoice_status: rpc_url is empty".to_string());
    }

    let client = RpcClient::new(cfg.rpc_url.trim(), http);
    let sigs = client
        .get_signatures_for_address(&reference, req.effective_lookback())
        .map_err(|e| format!("invoice_status: rpc failed: {}", e.message))?;

    // Sum the verified value over *every* successful signature the lookback
    // returned (newest first). A single invoice can be settled across multiple
    // partial transfers, and dust transactions touching the reference must not
    // mask an older real payment — so neither one tx nor "the newest five" is
    // enough. The scan stops as soon as the expected amount is reached.
    let merchant = cfg.merchant_solana.trim();
    let expected = req
        .expected_usdc
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let mut received_units: u128 = 0;
    // Decimals of the mint, learned from the first transaction that actually
    // moved funds. Zero-delta transactions carry no usable decimals.
    let mut decimals: Option<u32> = None;
    let mut any_verified = false;
    let mut inconsistent = false;
    let mut block_time: Option<i64> = None;
    let mut settled = false;
    // Successful signatures the scan could not account for: either the ceiling
    // cut them off, or `getTransaction` would not answer for them.
    let successful = sigs.iter().filter(|s| s.is_success()).count();
    let mut unverifiable = successful.saturating_sub(MAX_VALUE_CHECKS);

    // Need the merchant pubkey to filter received balances; without it the
    // amount cannot be verified, so degrade honestly rather than guess.
    if !merchant.is_empty() {
        for sig in sigs
            .iter()
            .filter(|s| s.is_success())
            .take(MAX_VALUE_CHECKS)
        {
            // A tx the RPC cannot return (no result / no meta / unreadable
            // token balances / transport error) is unverifiable. Skip it — but
            // count it, because the running total is then only a lower bound
            // and a lower bound may not be published as a shortfall.
            let r = match client.get_transaction(&sig.signature, cfg.usdc_mint.trim(), merchant) {
                Ok(Some(r)) => r,
                _ => {
                    unverifiable += 1;
                    continue;
                }
            };
            any_verified = true;
            // A zero delta contributes nothing and says nothing about the
            // mint's decimals — an unrelated outgoing transfer in a tx
            // touching the reference must not subtract from the total either.
            if r.received_units == 0 {
                continue;
            }
            // Receipt date comes from the newest transaction that actually
            // moved funds, never from a dust tx that merely touched the
            // reference.
            if block_time.is_none() {
                block_time = r.block_time.or(sig.block_time);
            }
            match decimals {
                None => decimals = Some(r.decimals),
                // Decimals are fixed per mint: a disagreement means the sum
                // would be nonsense. Refuse to build a verdict from it.
                Some(d) if d != r.decimals => {
                    inconsistent = true;
                    break;
                }
                Some(_) => {}
            }
            received_units = match received_units.checked_add(r.received_units) {
                Some(t) => t,
                None => {
                    inconsistent = true;
                    break;
                }
            };

            // Early stop: the invoice is covered, further RPC calls would only
            // add signatures nobody is waiting on. Whatever they hold cannot
            // change a verdict that is already settled, so the transactions
            // left unscanned here do not make the answer a lower bound.
            settled = match (expected, decimals) {
                (Some(exp), Some(d)) => compare_units_to_decimal(received_units, d, exp)
                    .map(|c| c.expected_units > 0 && c.ordering != Ordering::Less)
                    .unwrap_or(false),
                _ => false,
            };
            if settled {
                unverifiable = 0;
                break;
            }
        }
    }

    // `received_units` is a *lower bound* whenever part of the scan is missing.
    // A lower bound is enough to confirm a payment (it already covers the
    // invoice) but never enough to assert a shortfall: publishing
    // `UNDERPAID … faltam 7.27` because the public RPC rate-limited us halfway
    // through is the same lie as claiming PAID without checking, pointed the
    // other way. So an incomplete scan that has not yet covered the invoice
    // degrades to `SIG OK (valor não verificado)`.
    let complete = unverifiable == 0;
    let verified = if !any_verified || inconsistent || (!complete && !settled) {
        None
    } else {
        Some(UsdcReceipt {
            received_units,
            decimals: decimals.unwrap_or(0),
            block_time,
        })
    };

    Ok(status_from_signatures_verified(
        &req.invoice_id,
        &reference,
        &sigs,
        verified,
        req.expected_usdc.as_deref(),
        req.pix_marked_paid,
    ))
}

/// Build a successful fixture signature for host unit tests.
pub fn fixture_success_sig(signature: &str, memo: Option<&str>) -> SignatureInfo {
    SignatureInfo {
        signature: signature.into(),
        slot: 1,
        err: None,
        memo: memo.map(|s| s.into()),
        block_time: Some(1),
        confirmation_status: Some("finalized".into()),
    }
}

/// Build a failed fixture signature for host unit tests.
pub fn fixture_failed_sig(signature: &str) -> SignatureInfo {
    SignatureInfo {
        signature: signature.into(),
        slot: 1,
        err: Some(Value::String("InstructionError".into())),
        memo: None,
        block_time: Some(1),
        confirmation_status: Some("finalized".into()),
    }
}
