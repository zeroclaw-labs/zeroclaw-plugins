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
pub struct PayRequestOutput {
    pub solana_pay_url: String,
    pub human_summary: String,
    pub custody_tier: &'static str,
    pub requires_human_signature: bool,
}

const INJECT: &[&str] = &[
    "ignore previous",
    "private key",
    "send all funds",
    "jailbreak",
];

pub fn detect_prompt_injection(raw: &str) -> bool {
    let l = raw.to_ascii_lowercase();
    INJECT.iter().any(|m| l.contains(m))
}

pub fn build_pay_request(input: &PayRequestInput) -> Result<PayRequestOutput, String> {
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

    let mut url = format!("solana:{}?amount={}", input.recipient, input.amount);
    if let Some(t) = &input.spl_token {
        url.push_str("&spl-token=");
        url.push_str(&urlencoding::encode(t));
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

    let summary = match input.locale.as_str() {
        "fr" => format!(
            "Paiement Solana Pay: {} → {} (humain doit approuver)",
            input.amount,
            truncate(&input.recipient, 8)
        ),
        "pt" => format!(
            "Pagamento Solana Pay: {} → {} (humano deve aprovar)",
            input.amount,
            truncate(&input.recipient, 8)
        ),
        _ => format!(
            "Solana Pay request: {} to {} (human must approve)",
            input.amount,
            truncate(&input.recipient, 8)
        ),
    };

    Ok(PayRequestOutput {
        solana_pay_url: url,
        human_summary: summary,
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
