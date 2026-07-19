//! Pure T0 narrator for settlement / Merkle-style proof JSON.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Default)]
pub struct ProofInput {
    #[serde(default)]
    pub fixture_id: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub valid: Option<bool>,
    #[serde(default)]
    pub merkle_root: Option<String>,
    #[serde(default)]
    pub program_id: Option<String>,
    #[serde(default)]
    pub locale: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Narration {
    pub text: String,
    pub custody_tier: &'static str,
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

pub fn narrate(input: &ProofInput) -> Narration {
    let locale = input.locale.as_deref().unwrap_or("en");
    let valid = input.valid.unwrap_or(false);
    let fixture = input.fixture_id.as_deref().unwrap_or("?");
    let outcome = input.outcome.as_deref().unwrap_or("unknown");
    let root = input
        .merkle_root
        .as_deref()
        .map(|r| truncate(r, 10))
        .unwrap_or_else(|| "n/a".into());

    let text = match (locale, valid) {
        ("fr", true) => format!(
            "Preuve settlement OK pour fixture {fixture}: outcome={outcome}, racine Merkle {root}. Fail-closed si invalide."
        ),
        ("fr", false) => format!(
            "Preuve settlement INVALIDE pour fixture {fixture} (outcome={outcome}). Ne pas payer."
        ),
        ("pt", true) => format!(
            "Prova de settlement OK para fixture {fixture}: outcome={outcome}, Merkle {root}."
        ),
        ("pt", false) => format!(
            "Prova INVALIDA para fixture {fixture}. Nao liquidar."
        ),
        ("es", true) => format!(
            "Prueba settlement OK para fixture {fixture}: outcome={outcome}, Merkle {root}."
        ),
        ("es", false) => format!(
            "Prueba INVALIDA para fixture {fixture}. No liquidar."
        ),
        (_, true) => format!(
            "Settlement proof VALID for fixture {fixture}: outcome={outcome}, Merkle root {root}. Fail-closed if invalid."
        ),
        (_, false) => format!(
            "Settlement proof INVALID for fixture {fixture} (outcome={outcome}). Do not pay out."
        ),
    };

    Narration {
        text,
        custody_tier: "T0",
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
