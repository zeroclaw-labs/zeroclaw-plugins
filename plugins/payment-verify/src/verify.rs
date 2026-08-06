//! The payment verifier: order → finalized chain evidence → verdict.
//!
//! Pure logic, zero wasm dependency. Reads only; never signs, submits, or
//! stores. The reference is re-derived from the order, so verification needs
//! no record of the invoice ever having been created.

use safe_hands_core::crypto::parse_pubkey;
use safe_hands_core::invoice::{
    derive_reference, raw_to_decimal_string, verify_payment_agreed, InvoiceRequest,
    PaymentExpectation, PaymentVerdict,
};
use safe_hands_core::rpc::{fetch_classic_mint_decimals, RpcTransport};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct Args {
    order_id: String,
    amount_raw: String,
    #[serde(default)]
    expiry_unix: Option<i64>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    memo: Option<String>,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

pub struct ExecuteOutput {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

impl ExecuteOutput {
    fn ok(value: Value) -> Self {
        Self {
            success: true,
            output: value.to_string(),
            error: None,
        }
    }

    fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            output: String::new(),
            error: Some(message.into()),
        }
    }
}

/// Operator-facing guidance per verdict. Deliberately explicit that a reported
/// payer address is evidence, not permission to send money back to it.
fn next_step(verdict: &PaymentVerdict) -> &'static str {
    match verdict {
        PaymentVerdict::Unpaid => {
            "Not paid yet. Send payment_url (or its QR) to the customer out-of-band, then check \
             this same order_id again — the link is re-derived, not stored, so it never expires \
             and never drifts."
        }
        PaymentVerdict::Paid(_) => {
            "Paid in full. To refund, the payer address must already be in the operator's static \
             allowed_recipients policy — this result does not authorize anything by itself."
        }
        PaymentVerdict::Underpaid(e) if e.late => {
            "Less than the invoiced amount arrived, and it arrived after expiry. Decide manually: \
             accept, request the balance, or refund what was received."
        }
        PaymentVerdict::Underpaid(_) => {
            "Less than the invoiced amount arrived. Decide manually: accept, request the balance, \
             or refund what was received."
        }
        PaymentVerdict::Overpaid(e) if e.late => {
            "More than the invoiced amount arrived, and it arrived after expiry. Decide manually; \
             the excess is not auto-refunded."
        }
        PaymentVerdict::Overpaid(_) => {
            "More than the invoiced amount arrived. Decide manually; the excess is not \
             auto-refunded."
        }
        PaymentVerdict::Late(_) => {
            "Payment arrived after expiry. Decide manually whether to honour or refund it."
        }
        PaymentVerdict::Review { .. } => {
            "Money moved but could not be attributed to a single owner-signed transfer. A human \
             must inspect the listed signatures. No refund may be prepared from this result."
        }
        PaymentVerdict::Unknown { .. } => {
            "Evidence could not be trusted, so nothing is claimed either way. This is not proof of \
             non-payment. Retry; if it persists, check both RPC endpoints."
        }
    }
}

pub fn run(
    args_json: &str,
    primary: Option<&dyn RpcTransport>,
    fallback: Option<&dyn RpcTransport>,
) -> ExecuteOutput {
    let args: Args = match serde_json::from_str(args_json) {
        Ok(args) => args,
        Err(error) => return ExecuteOutput::err(format!("invalid arguments: {error}")),
    };

    // Merchant identity and salt are host configuration, never caller
    // arguments: the reference must be the one the invoice was issued under.
    let Some(merchant_owner) = args.config.get("merchant_owner").map(String::as_str) else {
        return ExecuteOutput::err(
            "no merchant_owner is configured — fail closed. Set it in the plugin config section.",
        );
    };
    let merchant = match parse_pubkey(merchant_owner) {
        Ok(merchant) => merchant,
        Err(error) => {
            return ExecuteOutput::err(format!("invalid configured merchant_owner: {error}"))
        }
    };
    let salt = args
        .config
        .get("invoice_salt")
        .map(String::as_str)
        .unwrap_or("");

    // The settlement mint is host configuration, never a caller argument.
    //
    // A merchant settles in one currency. If the model could choose the mint,
    // a prompt injection — or simply a hallucinated address, which is what a
    // live run produced — could invoice a customer in a worthless lookalike
    // token. There is no argument for this field, so there is nothing to
    // redirect.
    let Some(mint) = args.config.get("default_mint").map(String::to_owned) else {
        return ExecuteOutput::err(
            "no default_mint is configured — fail closed. Set the merchant's settlement mint in \
             the plugin config section.",
        );
    };
    if let Err(error) = parse_pubkey(&mint) {
        return ExecuteOutput::err(format!("invalid configured default_mint: {error}"));
    }

    let requested_amount_raw = match args.amount_raw.trim().parse::<u64>() {
        Ok(amount) if amount > 0 => amount,
        Ok(_) => return ExecuteOutput::err("amount_raw must be greater than zero"),
        Err(_) => {
            return ExecuteOutput::err(format!(
                "amount_raw must be a raw smallest-unit integer, got {:?}",
                args.amount_raw
            ))
        }
    };

    // Two independent endpoints must agree. One endpoint is not evidence.
    let (Some(primary), Some(fallback)) = (primary, fallback) else {
        return ExecuteOutput::err(
            "payment verification requires two independent RPC endpoints (rpc_url and \
             rpc_url_fallback) so that no single endpoint can mark an invoice paid — fail closed",
        );
    };

    let reference = match derive_reference(&merchant, &args.order_id, salt) {
        Ok(reference) => reference,
        Err(error) => return ExecuteOutput::err(error),
    };

    let expectation = PaymentExpectation {
        merchant_owner: merchant.to_string(),
        mint: mint.clone(),
        reference: reference.to_string(),
        requested_amount_raw,
        // A zero or negative expiry is not a 1970 deadline; models emit it as
        // a stand-in for "none", and honouring it would mark everything late.
        expiry_unix: args.expiry_unix.filter(|e| *e > 0),
    };
    let verdict = verify_payment_agreed(primary, fallback, &expectation);

    // Decimals are for display and for rendering the payment link. They must
    // never gate the verdict, so a failure here degrades output, not safety.
    let decimals = fetch_classic_mint_decimals(primary, &mint).ok();
    let display = |raw: u64| match decimals {
        Some(decimals) => json!(raw_to_decimal_string(raw, decimals)),
        None => Value::Null,
    };

    // Because nothing is stored, an invoice is derived rather than created:
    // the payment link for an unpaid order is simply re-rendered here. There
    // is no separate "create invoice" step and no record that can drift.
    let payment_url = decimals.and_then(|decimals| {
        InvoiceRequest {
            merchant_owner: merchant.to_string(),
            mint: mint.clone(),
            reference: reference.to_string(),
            amount_raw: requested_amount_raw,
            decimals,
            label: args.label,
            message: args.message,
            memo: args.memo,
        }
        .url()
        .ok()
    });

    let mut body = json!({
        "order_id": args.order_id,
        "status": verdict.tag(),
        "reference": reference.to_string(),
        "payment_url": payment_url,
        "mint": mint,
        "requested_amount_raw": requested_amount_raw.to_string(),
        "requested_amount_display": display(requested_amount_raw),
        "commitment": "finalized",
        "rpc_agreement": "primary and fallback agreed",
        "custody": "T0 — read only. This tool holds no keys and authorizes nothing.",
        "next_step": next_step(&verdict),
    });
    let object = body.as_object_mut().expect("object");

    if let Some(evidence) = verdict.evidence() {
        object.insert("signature".into(), json!(evidence.signature));
        object.insert("slot".into(), json!(evidence.slot));
        object.insert("block_time".into(), json!(evidence.block_time));
        object.insert(
            "observed_amount_raw".into(),
            json!(evidence.observed_amount_raw.to_string()),
        );
        object.insert(
            "observed_amount_display".into(),
            display(evidence.observed_amount_raw),
        );
        // Named `payer_owner_evidence` so it can never read as an approved
        // destination. A refund still has to clear the static policy.
        object.insert("payer_owner_evidence".into(), json!(evidence.payer_owner));
        // Reported alongside the amount rather than replacing it: a payment can
        // be both late and the wrong amount, and the operator needs both.
        object.insert("late".into(), json!(evidence.late));
        object.insert(
            "refund_authorization".into(),
            json!(
                "none — a refund to this address is only possible if the operator has already \
                 placed it in allowed_recipients; solana-tx-authorize checks that independently"
            ),
        );
    }
    match &verdict {
        PaymentVerdict::Review { reason, signatures } => {
            object.insert("reason".into(), json!(reason));
            object.insert("signatures".into(), json!(signatures));
        }
        PaymentVerdict::Unknown { reason } => {
            object.insert("reason".into(), json!(reason));
            object.insert("rpc_agreement".into(), json!("not established"));
        }
        _ => {}
    }

    ExecuteOutput::ok(body)
}

#[cfg(test)]
mod tests;
