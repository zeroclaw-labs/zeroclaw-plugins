//! Pure T0 payment-watch core (Solana Pay reference pattern).
//!
//! Solana Pay puts `reference` as an account on the transfer tx. Watching
//! `getSignaturesForAddress(reference)` detects settlement without custody.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Paid,
    Unpaid,
    Inconclusive,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WatchInput {
    /// Solana Pay reference pubkey (required for reliable detection).
    pub reference: String,
    #[serde(default)]
    pub expected_amount: Option<String>,
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub invoice_label: Option<String>,
    #[serde(default = "default_locale")]
    pub locale: String,
}

fn default_locale() -> String {
    "en".into()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservedSig {
    pub signature: String,
    #[serde(default)]
    pub err: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WatchReport {
    pub status: PaymentStatus,
    pub summary: String,
    pub matching_signature: Option<String>,
    pub signatures_seen: usize,
    pub custody_tier: &'static str,
}

const INJECT: &[&str] = &[
    "ignore previous",
    "private key",
    "send all funds",
    "jailbreak",
    "bypass safety",
];

pub fn detect_prompt_injection(raw: &str) -> bool {
    let l = raw.to_ascii_lowercase();
    INJECT.iter().any(|m| l.contains(m))
}

/// Decide paid/unpaid from already-fetched signature rows (host tests inject these).
pub fn evaluate_signatures(
    input: &WatchInput,
    sigs: &[ObservedSig],
) -> Result<WatchReport, String> {
    if detect_prompt_injection(&input.reference)
        || input
            .invoice_label
            .as_deref()
            .map(detect_prompt_injection)
            .unwrap_or(false)
    {
        return Err("prompt_injection_fail_closed".into());
    }
    if input.reference.len() < 32 {
        return Err("reference_invalid".into());
    }

    let ok_sigs: Vec<&ObservedSig> = sigs
        .iter()
        .filter(|s| s.err.is_none() || s.err.as_ref().is_some_and(|e| e.is_null()))
        .filter(|s| !s.signature.is_empty())
        .collect();

    let label = input.invoice_label.as_deref().unwrap_or("invoice");
    let amt = input.expected_amount.as_deref().unwrap_or("?");

    if ok_sigs.is_empty() {
        let summary = match input.locale.as_str() {
            "fr" => format!("NON PAYE: {label} ({amt}) — aucune sig sur reference"),
            "pt" => format!("NAO PAGO: {label} ({amt}) — nenhuma sig na reference"),
            _ => format!("UNPAID: {label} ({amt}) — no signatures on reference yet"),
        };
        return Ok(WatchReport {
            status: PaymentStatus::Unpaid,
            summary,
            matching_signature: None,
            signatures_seen: sigs.len(),
            custody_tier: "T0",
        });
    }

    let sig = ok_sigs[0].signature.clone();
    let summary = match input.locale.as_str() {
        "fr" => format!("PAYE: {label} ({amt}) — sig {}…", truncate(&sig, 10)),
        "pt" => format!("PAGO: {label} ({amt}) — sig {}…", truncate(&sig, 10)),
        _ => format!("PAID: {label} ({amt}) — sig {}…", truncate(&sig, 10)),
    };

    Ok(WatchReport {
        status: PaymentStatus::Paid,
        summary,
        matching_signature: Some(sig),
        signatures_seen: sigs.len(),
        custody_tier: "T0",
    })
}

pub fn parse_signatures_rpc(body: &str) -> Result<Vec<ObservedSig>, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| format!("rpc_json: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("rpc_error: {err}"));
    }
    let arr = v
        .pointer("/result")
        .and_then(|r| r.as_array())
        .ok_or_else(|| "rpc_missing_result_array".to_string())?;
    let mut out = Vec::new();
    for item in arr {
        let signature = item
            .get("signature")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let err = item.get("err").cloned();
        out.push(ObservedSig { signature, err });
    }
    Ok(out)
}

pub fn build_get_signatures_body(reference: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            reference,
            { "limit": 10, "commitment": "confirmed" }
        ]
    })
    .to_string()
}

pub fn rpc_url_allowed(url: &str) -> bool {
    let u = url.trim().to_ascii_lowercase();
    if !u.starts_with("https://") {
        return false;
    }
    u.contains("api.mainnet-beta.solana.com")
        || u.contains("api.devnet.solana.com")
        || u.contains("api.testnet.solana.com")
        || u.contains("helius-rpc.com")
        || u.contains("helius.xyz")
        || u.contains("rpc.ankr.com/solana")
        || u.contains("solana-mainnet.g.alchemy.com")
}

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
