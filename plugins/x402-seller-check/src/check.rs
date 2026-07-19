//! Pure T0 x402 seller security heuristics (no signing, no network in tests).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Go,
    NoGo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SellerReport {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub summary: String,
    pub custody_tier: &'static str,
}

const INJECT_MARKERS: &[&str] = &[
    "ignore previous",
    "send all funds",
    "private key",
    "bypass safety",
    "jailbreak",
    "disregard all previous",
    "exfiltrate",
];

fn push(findings: &mut Vec<Finding>, severity: &str, code: &str, detail: &str) {
    findings.push(Finding {
        severity: severity.into(),
        code: code.into(),
        detail: detail.into(),
    });
}

pub fn detect_prompt_injection(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    INJECT_MARKERS.iter().any(|m| lower.contains(m))
}

/// Analyze seller snippet / challenge JSON text for unsafe patterns.
///
/// Heuristics are fail-closed: any high/critical → NO-GO; medium-only → NO-GO;
/// empty findings → GO. Unknown / ambiguous blobs that look like payment rails
/// without verify stay NO-GO.
pub fn analyze_seller_blob(blob: &str, locale: &str) -> SellerReport {
    let lower = blob.to_ascii_lowercase();
    let mut findings = Vec::new();

    if detect_prompt_injection(blob) {
        push(
            &mut findings,
            "critical",
            "prompt_injection",
            "seller blob contains prompt-injection / fund-exfil markers",
        );
    }

    if lower.contains(".tolowercase()") && (lower.contains("address") || lower.contains("pubkey")) {
        push(
            &mut findings,
            "critical",
            "solana_base58_tolower",
            "base58 address lowercasing breaks Solana pubkeys",
        );
    }

    if lower.contains("settle") && lower.contains("before") && lower.contains("verify") {
        push(
            &mut findings,
            "critical",
            "settle_before_verify",
            "settle appears ordered before verify",
        );
    }

    if (lower.contains("skip") || lower.contains("bypass"))
        && (lower.contains("verify")
            || lower.contains("signature")
            || lower.contains("facilitator"))
    {
        push(
            &mut findings,
            "critical",
            "verify_bypass",
            "verify/signature/facilitator bypass hinted",
        );
    }

    if lower.contains("private key")
        || lower.contains("secretkey")
        || lower.contains("secret_key")
        || lower.contains("bs58.decode") && lower.contains("key")
    {
        push(
            &mut findings,
            "critical",
            "private_key_in_seller",
            "private/signing key material referenced in seller path",
        );
    }

    if !lower.contains("verify") && (lower.contains("402") || lower.contains("x402")) {
        push(
            &mut findings,
            "high",
            "missing_verify_mention",
            "402/x402 flow without verify step mentioned",
        );
    }

    if lower.contains("facilitator") && lower.contains("skip") {
        push(
            &mut findings,
            "high",
            "facilitator_skip",
            "facilitator verification skip hinted",
        );
    }

    if lower.contains("replay") && !lower.contains("nonce") && !lower.contains("idempoten") {
        push(
            &mut findings,
            "medium",
            "replay_without_nonce",
            "replay discussed without nonce/idempotency",
        );
    }

    if lower.contains("http://")
        && (lower.contains("payto")
            || lower.contains("resource")
            || lower.contains("facilitator")
            || lower.contains("callback"))
    {
        push(
            &mut findings,
            "high",
            "insecure_http_endpoint",
            "payment rail uses cleartext http://",
        );
    }

    if (lower.contains("maxamount") || lower.contains("max_amount"))
        && (lower.contains("amount"))
        && (lower.contains(">") || lower.contains("exceed") || lower.contains("mismatch"))
    {
        push(
            &mut findings,
            "high",
            "amount_vs_max_mismatch",
            "amount vs maxAmount mismatch / over-cap pattern",
        );
    }

    if lower.contains("network")
        && (lower.contains("ethereum")
            || lower.contains("eip-155")
            || lower.contains("base-sepolia"))
        && (lower.contains("solana") || lower.contains("mainnet-beta"))
    {
        push(
            &mut findings,
            "high",
            "network_mismatch_hint",
            "mixed EVM + Solana network identifiers in one challenge",
        );
    }

    if lower.contains("payto")
        && lower.contains("facilitator")
        && (lower.contains("same") || lower.contains("==") || lower.contains("equals"))
    {
        push(
            &mut findings,
            "high",
            "payto_equals_facilitator",
            "payTo appears equal to facilitator (self-deal risk)",
        );
    }

    if (lower.contains("\"scheme\"") || lower.contains("scheme:"))
        && !lower.contains("exact")
        && !lower.contains("upto")
        && !lower.contains("up_to")
    {
        // Soft signal only if 402 challenge-shaped and scheme present without known values.
        if lower.contains("402") || lower.contains("accepts") {
            push(
                &mut findings,
                "medium",
                "unknown_payment_scheme",
                "accepts/scheme present without exact|upTo",
            );
        }
    }

    if lower.contains("refund") && lower.contains("never") {
        push(
            &mut findings,
            "medium",
            "refund_never",
            "refund path explicitly never — document buyer risk",
        );
    }

    if lower.contains("deadline")
        && lower.contains("ignore")
        && (lower.contains("payment") || lower.contains("timeout"))
    {
        push(
            &mut findings,
            "high",
            "deadline_ignored",
            "payment deadline/timeout ignored",
        );
    }

    // Fail-closed: any finding (critical/high/medium) → NO-GO.
    let verdict = if findings.is_empty() {
        Verdict::Go
    } else {
        Verdict::NoGo
    };

    let label = match (locale, &verdict) {
        ("fr", Verdict::Go) => "GO",
        ("fr", Verdict::NoGo) => "NO-GO",
        ("pt", Verdict::Go) => "GO",
        ("pt", Verdict::NoGo) => "NAO-GO",
        ("de", Verdict::Go) => "GO",
        ("de", Verdict::NoGo) => "NEIN-GO",
        ("es", Verdict::Go) => "GO",
        ("es", Verdict::NoGo) => "NO-GO",
        ("zh", Verdict::Go) => "GO",
        ("zh", Verdict::NoGo) => "NO-GO",
        ("ja", Verdict::Go) => "GO",
        ("ja", Verdict::NoGo) => "NO-GO",
        ("ru", Verdict::Go) => "GO",
        ("ru", Verdict::NoGo) => "NO-GO",
        (_, Verdict::Go) => "GO",
        (_, Verdict::NoGo) => "NO-GO",
    };

    let summary = format!(
        "[{label}] findings={} · tier=T0 · heuristic_only",
        findings.len()
    );

    SellerReport {
        verdict,
        findings,
        summary,
        custody_tier: "T0",
    }
}
