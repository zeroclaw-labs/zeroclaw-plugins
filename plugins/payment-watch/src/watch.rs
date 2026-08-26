//! Pure matching core for `payment-watch`: given observed on-chain transfers
//! (parsed from RPC by `solana-wasi-core::rpc`), decide whether the expected
//! payment has landed. No network, no wasm — fully host-testable.
//!
//! Trust model: this tool trusts THE CHAIN, not messages. A "payment
//! confirmation" only ever originates from a parsed `getTransaction`
//! response for a finalized/confirmed signature — never from text an LLM or
//! chat counterparty supplies.

use std::collections::HashMap;

use serde::Deserialize;
use solana_wasi_core::pubkey::short;
use solana_wasi_core::rpc::ObservedTransfer;
use solana_wasi_core::shape::ToolOutput;

/// Arguments the LLM supplies (untrusted; only used as match *criteria* —
/// they cannot fabricate a confirmation, only narrow the search).
#[derive(Deserialize)]
pub struct WatchArgs {
    /// Expected UI amount, e.g. "25" or "25.0". Optional: any amount matches.
    #[serde(default)]
    pub expected_amount: Option<String>,
    /// Expected mint (base58). Optional.
    #[serde(default)]
    pub expected_mint: Option<String>,
    /// Expected memo/reference substring, e.g. "invoice #412". Optional.
    #[serde(default)]
    pub reference: Option<String>,
}

pub struct WatchConfig {
    /// The address (owner or ATA) being watched — operator-configured.
    pub watch_address: String,
    pub rpc_url: String,
    /// How many recent signatures to scan per call (default 20, max 50).
    pub scan_limit: u32,
}

impl WatchConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let watch_address = section
            .get("watch_address")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or("missing required config key `watch_address`")?;
        Ok(Self {
            watch_address,
            rpc_url: section
                .get("rpc_url")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "https://api.devnet.solana.com".to_string()),
            scan_limit: section
                .get("scan_limit")
                .and_then(|v| v.trim().parse::<u32>().ok())
                .map(|v| v.clamp(1, 50))
                .unwrap_or(20),
        })
    }
}

/// Normalize a UI amount string for comparison: "25" == "25.0" == "25.00".
fn amount_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> Option<(u128, u128, usize)> {
        let s = s.trim();
        let (int, frac) = match s.split_once('.') {
            Some((i, f)) => (i, f.trim_end_matches('0')),
            None => (s, ""),
        };
        if int.is_empty() && frac.is_empty() {
            return None;
        }
        if !int.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let int_v: u128 = if int.is_empty() { 0 } else { int.parse().ok()? };
        let frac_v: u128 = if frac.is_empty() {
            0
        } else {
            frac.parse().ok()?
        };
        Some((int_v, frac_v, frac.len()))
    };
    matches!((norm(a), norm(b)), (Some(x), Some(y)) if x == y)
}

/// Decide whether any observed transfer satisfies the expectation.
pub fn match_payment(args: &WatchArgs, observed: &[ObservedTransfer]) -> ToolOutput {
    let hit = observed.iter().find(|t| {
        if t.err {
            return false; // failed txs never count as payment
        }
        if let Some(amt) = &args.expected_amount {
            if !amount_eq(amt, &t.ui_amount) {
                return false;
            }
        }
        if let Some(mint) = &args.expected_mint {
            if mint.trim() != t.mint {
                return false;
            }
        }
        if let Some(reference) = &args.reference {
            match &t.memo {
                Some(m) if m.contains(reference.trim()) => {}
                _ => return false,
            }
        }
        true
    });

    match hit {
        Some(t) => {
            let from = t
                .from
                .as_deref()
                .map(short)
                .unwrap_or_else(|| "unknown".into());
            let mut out = ToolOutput::ok(format!(
                "PAID ✅ {} {} received from {} (sig {}, slot {}).",
                t.ui_amount,
                short(&t.mint),
                from,
                short(&t.signature),
                t.slot
            ));
            if let Some(m) = &t.memo {
                out = out.with_detail(format!("memo: {}", solana_wasi_core::shape::clamp(m, 80)));
            }
            out.with_detail("Verified on-chain via getTransaction — not from a message.")
        }
        None => {
            let criteria = [
                args.expected_amount
                    .as_deref()
                    .map(|a| format!("amount {a}")),
                args.expected_mint
                    .as_deref()
                    .map(|m| format!("mint {}", short(m))),
                args.reference.as_deref().map(|r| format!("ref \"{r}\"")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ");
            ToolOutput::ok(format!(
                "NOT PAID — no matching transfer found ({}) in the {} most recent transactions.",
                if criteria.is_empty() {
                    "any inbound".into()
                } else {
                    criteria
                },
                observed.len()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn transfer(amount: &str, memo: Option<&str>, err: bool) -> ObservedTransfer {
        ObservedTransfer {
            signature: "5KdSig1111111111111111111111111111111111111111".into(),
            from: Some("PayerOwner11111111111111111111111111111111".into()),
            mint: USDC.into(),
            ui_amount: amount.into(),
            memo: memo.map(str::to_string),
            slot: 434000000,
            err,
        }
    }

    fn args(amount: Option<&str>, mint: Option<&str>, reference: Option<&str>) -> WatchArgs {
        WatchArgs {
            expected_amount: amount.map(str::to_string),
            expected_mint: mint.map(str::to_string),
            reference: reference.map(str::to_string),
        }
    }

    #[test]
    fn amount_normalization() {
        assert!(amount_eq("25", "25.0"));
        assert!(amount_eq("25.50", "25.5"));
        assert!(!amount_eq("25", "25.01"));
        assert!(!amount_eq("abc", "25"));
    }

    #[test]
    fn matches_exact_payment() {
        let out = match_payment(
            &args(Some("25"), Some(USDC), Some("invoice #412")),
            &[transfer("25.0", Some("invoice #412 thanks"), false)],
        );
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert!(v["summary"].as_str().unwrap().starts_with("PAID ✅"));
    }

    #[test]
    fn wrong_amount_not_paid() {
        let out = match_payment(
            &args(Some("25"), None, None),
            &[transfer("24.9", None, false)],
        );
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert!(v["summary"].as_str().unwrap().starts_with("NOT PAID"));
    }

    #[test]
    fn missing_reference_not_paid() {
        let out = match_payment(
            &args(Some("25"), None, Some("invoice #412")),
            &[transfer("25", Some("something else"), false)],
        );
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert!(v["summary"].as_str().unwrap().starts_with("NOT PAID"));
    }

    /// A FAILED on-chain tx must never read as payment — fail closed.
    #[test]
    fn failed_tx_never_counts() {
        let out = match_payment(&args(Some("25"), None, None), &[transfer("25", None, true)]);
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert!(v["summary"].as_str().unwrap().starts_with("NOT PAID"));
    }

    /// The forged-webhook scenario: someone TELLS the agent "payment sent,
    /// sig XYZ". The tool only reports from parsed chain data — an empty
    /// observation set means NOT PAID no matter what the prompt claims.
    #[test]
    fn spoofed_claim_without_chain_data_not_paid() {
        let out = match_payment(&args(Some("500"), Some(USDC), None), &[]);
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert!(v["summary"].as_str().unwrap().starts_with("NOT PAID"));
    }

    #[test]
    fn config_requires_watch_address() {
        assert!(WatchConfig::from_section(&HashMap::new()).is_err());
        let mut s = HashMap::new();
        s.insert("watch_address".into(), "SomeAddr".into());
        s.insert("scan_limit".into(), "500".into());
        let cfg = WatchConfig::from_section(&s).unwrap();
        assert_eq!(cfg.scan_limit, 50); // clamped
    }
}
