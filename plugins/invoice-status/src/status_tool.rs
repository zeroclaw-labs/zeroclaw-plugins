//! Pure invoice-status core. No wit-bindgen or wasm dependency so it compiles
//! and tests on the host with a plain `cargo test`, while the wasm component
//! reuses the exact same logic through `lib.rs`.
//!
//! Network I/O is injected via [`HttpTransport`] so host tests can pass
//! fixture [`SignatureInfo`] lists to [`evaluate_status`] without HTTP.

use std::collections::HashMap;

use serde_json::Value;
use solana_wasm_core::{
    derive_reference, status_from_signatures, status_from_signatures_verified, HttpTransport,
    RpcClient, SignatureInfo, UsdcReceipt, USDC_MINT,
};

/// Default Solana mainnet public RPC (operator should override in production).
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// Default `getSignaturesForAddress` lookback when the tool call omits it.
pub const DEFAULT_LOOKBACK: u64 = 25;

/// Upper bound of `getTransaction` value checks per status call. Partial
/// payments across several transfers are summed up to this many recent
/// successful signatures.
pub const MAX_VALUE_CHECKS: usize = 5;

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
pub fn evaluate_status(
    req: &StatusRequest,
    cfg: &StatusConfig,
    sigs: &[SignatureInfo],
) -> String {
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
/// Flow: `getSignaturesForAddress(reference)` → up to [`MAX_VALUE_CHECKS`]
/// recent successful sigs → `getTransaction(sig)` each → sum of net USDC
/// received by `merchant_solana` for `usdc_mint` → value-aware verdict +
/// shareable receipt when paid. Summing covers invoices settled by multiple
/// partial transfers and spam txs touching the reference.
///
/// If the merchant pubkey is unknown, or `getTransaction` fails / omits the
/// transaction, the amount cannot be confirmed and the status degrades to
/// `USDC: SIG OK (valor não verificado …)` — it is never reported as PAID.
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

    // Sum the verified value over the most recent successful signatures
    // (newest first). A single invoice can be settled across multiple partial
    // transfers, and spam txs touching the reference must not mask an older
    // real payment — so one tx is not enough. RPC cost is bounded by
    // MAX_VALUE_CHECKS.
    let merchant = cfg.merchant_solana.trim();

    let mut received_sum = 0.0_f64;
    let mut any_verified = false;
    let mut block_time: Option<i64> = None;

    // Need the merchant pubkey to filter received balances; without it the
    // amount cannot be verified, so degrade honestly rather than guess.
    if !merchant.is_empty() {
        for sig in sigs
            .iter()
            .filter(|s| s.is_success())
            .take(MAX_VALUE_CHECKS)
        {
            // A tx the RPC cannot return (no result / no meta / transport
            // error) is simply unverifiable: skip it and let the txs that did
            // verify stand as an honest lower bound of what arrived.
            if let Ok(Some(r)) =
                client.get_transaction(&sig.signature, cfg.usdc_mint.trim(), merchant)
            {
                any_verified = true;
                // Only positive deltas count as received; an unrelated
                // outgoing transfer in a tx touching the reference must not
                // subtract from the settlement sum.
                if r.ui_amount > 0.0 {
                    received_sum += r.ui_amount;
                }
                if block_time.is_none() {
                    block_time = r.block_time.or(sig.block_time);
                }
            }
        }
    }

    let verified = if any_verified {
        Some(UsdcReceipt {
            received_ui: received_sum,
            block_time,
        })
    } else {
        None
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
