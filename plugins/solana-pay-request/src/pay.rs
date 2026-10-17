//! Pure T1 Solana Pay transfer-request builder (no signing).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
pub struct PayRequestInput {
    pub recipient: String,
    pub amount: String,
    #[serde(default)]
    pub spl_token: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
    /// Solana Pay `reference` (pubkey) — used by payment-watch to detect settlement.
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default = "default_locale")]
    pub locale: String,
}

fn default_locale() -> String {
    "en".into()
}

#[derive(Clone, Debug, Serialize)]
pub struct QrPayload {
    /// Exact string to encode in a QR (the solana: URL).
    pub text: String,
    pub mime_hint: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct PayRequestOutput {
    pub solana_pay_url: String,
    pub qr: QrPayload,
    pub human_summary: String,
    pub reference: Option<String>,
    pub custody_tier: &'static str,
    pub requires_human_signature: bool,
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

pub fn build_pay_request(input: &PayRequestInput) -> Result<PayRequestOutput, String> {
    if detect_prompt_injection(&input.recipient)
        || input
            .memo
            .as_deref()
            .map(detect_prompt_injection)
            .unwrap_or(false)
        || input
            .message
            .as_deref()
            .map(detect_prompt_injection)
            .unwrap_or(false)
    {
        return Err("prompt_injection_fail_closed".into());
    }

    if input.recipient.len() < 32 {
        return Err("recipient_invalid".into());
    }
    if input
        .amount
        .parse::<f64>()
        .ok()
        .filter(|a| *a > 0.0)
        .is_none()
    {
        return Err("amount_invalid".into());
    }
    if let Some(r) = &input.reference {
        if r.len() < 32 {
            return Err("reference_invalid".into());
        }
    }
    if let Some(t) = &input.spl_token {
        if t.len() < 32 {
            return Err("spl_token_invalid".into());
        }
    }

    let mut url = format!("solana:{}?amount={}", input.recipient, input.amount);
    if let Some(t) = &input.spl_token {
        url.push_str("&spl-token=");
        url.push_str(&urlencoding::encode(t));
    }
    if let Some(r) = &input.reference {
        url.push_str("&reference=");
        url.push_str(&urlencoding::encode(r));
    }
    if let Some(m) = &input.memo {
        url.push_str("&memo=");
        url.push_str(&urlencoding::encode(m));
    }
    if let Some(l) = &input.label {
        url.push_str("&label=");
        url.push_str(&urlencoding::encode(l));
    }
    if let Some(m) = &input.message {
        url.push_str("&message=");
        url.push_str(&urlencoding::encode(m));
    }

    let token_bit = input
        .spl_token
        .as_ref()
        .map(|t| format!(" ({})", truncate(t, 6)))
        .unwrap_or_default();
    let ref_bit = input
        .reference
        .as_ref()
        .map(|r| format!(" ref={}", truncate(r, 6)))
        .unwrap_or_default();

    let summary = match input.locale.as_str() {
        "fr" => format!(
            "Solana Pay {}{} → {}{} — humain signe / scan QR",
            input.amount,
            token_bit,
            truncate(&input.recipient, 8),
            ref_bit
        ),
        "pt" => format!(
            "Solana Pay {}{} → {}{} — humano assina / QR",
            input.amount,
            token_bit,
            truncate(&input.recipient, 8),
            ref_bit
        ),
        _ => format!(
            "Solana Pay {}{} → {}{} — human must approve / scan QR",
            input.amount,
            token_bit,
            truncate(&input.recipient, 8),
            ref_bit
        ),
    };

    Ok(PayRequestOutput {
        qr: QrPayload {
            text: url.clone(),
            mime_hint: "text/plain",
        },
        solana_pay_url: url,
        human_summary: summary,
        reference: input.reference.clone(),
        custody_tier: "T1",
        requires_human_signature: true,
    })
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
