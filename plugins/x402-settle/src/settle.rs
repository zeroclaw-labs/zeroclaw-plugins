//! Pure settlement core for `x402-settle`: parse a 402 challenge, run the
//! policy gate, build + partially sign the exact/SVM payment transaction.
//! No network, no wasm — the shim does HTTP; tests feed fixture challenges.
//!
//! # x402 exact/SVM flow (client role)
//! 1. GET the resource → HTTP 402 with `PaymentRequired` JSON (accepts[]).
//! 2. Pick a Solana `exact` requirement we can satisfy under policy.
//! 3. Build a versioned-legacy tx: TransferChecked(amount, asset → payTo's
//!    ATA) + optional seller memo, feePayer = sponsor from `extra.feePayer`.
//! 4. Sign ONLY our session-key slot; sponsor signature slot stays zeroed.
//! 5. Retry the request with the base64 payload in `X-PAYMENT` header.
//!
//! # Safety (T2 — the leash is the product)
//! - Session key only: a throwaway keypair holding a small allowance.
//! - `max_per_request` + `max_per_day` caps in BASE UNITS, in-plugin.
//! - Mint allowlist (default: refuse everything) and origin allowlist —
//!   the plugin refuses to pay challenges from hosts the operator hasn't
//!   pre-approved, which kills "hey agent, fetch https://evil.example/data"
//!   prompt-injection exfiltration.

use std::collections::HashMap;

use serde::Deserialize;
use solana_wasi_core::instruction::{derive_ata, memo, spl_transfer_checked};
use solana_wasi_core::message::compile_message;
use solana_wasi_core::policy::Verdict;
use solana_wasi_core::pubkey::{program_ids, short, Pubkey};
use solana_wasi_core::shape::ToolOutput;
use solana_wasi_core::signing::{partially_signed_transaction_base64, SessionKey};

/// Args from the LLM: just the URL (untrusted — gated by origin allowlist).
#[derive(Deserialize)]
pub struct SettleArgs {
    pub url: String,
    /// HTTP method for the paid request, default GET.
    #[serde(default)]
    pub method: Option<String>,
}

/// One entry of the 402 challenge's `accepts` array (x402 v2, exact/SVM).
#[derive(Deserialize, Debug, Clone)]
pub struct PaymentRequirement {
    pub scheme: String,
    pub network: String,
    /// Base units as a string.
    pub amount: String,
    /// Mint address.
    pub asset: String,
    #[serde(rename = "payTo")]
    pub pay_to: String,
    #[serde(default)]
    pub extra: Option<Extra>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Extra {
    #[serde(rename = "feePayer")]
    pub fee_payer: Option<String>,
    pub memo: Option<String>,
}

#[derive(Deserialize)]
pub struct PaymentRequired {
    #[serde(default)]
    pub accepts: Vec<PaymentRequirement>,
}

pub struct SettleConfig {
    /// Origins (scheme://host) the operator allows paying. Deny-by-default.
    pub origin_allowlist: Vec<String>,
    pub mint_allowlist: Vec<String>,
    pub max_per_request: u64,
    pub max_per_day: u64,
    pub session_key: SessionKey,
    pub rpc_url: String,
}

impl SettleConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let list = |key: &str| -> Vec<String> {
            section
                .get(key)
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        let session_key = section
            .get("session_key")
            .ok_or("missing required config key `session_key`")
            .and_then(|v| SessionKey::from_config_value(v).map_err(|_| "bad session_key"))
            .map_err(str::to_string)?;
        Ok(Self {
            origin_allowlist: list("origin_allowlist"),
            mint_allowlist: list("mint_allowlist"),
            max_per_request: section
                .get("max_per_request")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0),
            max_per_day: section
                .get("max_per_day")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0),
            session_key,
            rpc_url: section
                .get("rpc_url")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "https://api.devnet.solana.com".to_string()),
        })
    }
}

/// Extract `scheme://host[:port]` from a URL, lowercased. Pure string work —
/// no url crate needed for the allowlist comparison.
pub fn origin_of(url: &str) -> Result<String, String> {
    let u = url.trim();
    let (scheme, rest) = u
        .split_once("://")
        .ok_or_else(|| format!("invalid URL `{u}`"))?;
    if scheme != "https" {
        return Err("only https:// resources can be paid".into());
    }
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| format!("invalid URL `{u}`"))?;
    if host.contains('@') {
        return Err("userinfo in URL is not allowed".into());
    }
    Ok(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase()
    ))
}

/// The policy gate for a parsed 402 challenge. Returns the chosen
/// requirement or a refusal.
pub fn authorize_challenge(
    args_url: &str,
    challenge: &PaymentRequired,
    cfg: &SettleConfig,
    spent_today: u64,
) -> Result<PaymentRequirement, Verdict> {
    let origin = match origin_of(args_url) {
        Ok(o) => o,
        Err(e) => return Err(Verdict::refused(e)),
    };
    if cfg.origin_allowlist.is_empty() {
        return Err(Verdict::refused(
            "origin allowlist is empty — paying is disabled until the operator adds origins",
        ));
    }
    if !cfg
        .origin_allowlist
        .iter()
        .any(|o| o.trim_end_matches('/').eq_ignore_ascii_case(&origin))
    {
        return Err(Verdict::refused(format!(
            "origin {origin} is not on the operator allowlist — refusing to pay"
        )));
    }
    if cfg.max_per_request == 0 {
        return Err(Verdict::refused(
            "no max_per_request configured — paying is disabled until the operator sets a cap",
        ));
    }

    // Find a Solana exact requirement under our caps with an allowed mint.
    let mut best: Option<(u64, PaymentRequirement)> = None;
    for req in &challenge.accepts {
        if req.scheme != "exact" || !req.network.starts_with("solana:") {
            continue;
        }
        let amount: u64 = match req.amount.trim().parse() {
            Ok(a) if a > 0 => a,
            _ => continue,
        };
        if !cfg.mint_allowlist.iter().any(|m| m == &req.asset) {
            continue;
        }
        if amount > cfg.max_per_request {
            continue;
        }
        if cfg.max_per_day > 0 && spent_today.saturating_add(amount) > cfg.max_per_day {
            continue;
        }
        if best.as_ref().map(|(a, _)| amount < *a).unwrap_or(true) {
            best = Some((amount, req.clone()));
        }
    }
    best.map(|(_, r)| r).ok_or_else(|| {
        Verdict::refused(
            "no acceptable payment option: every offered requirement is off-network, \
             off-mint, or above the operator's caps",
        )
    })
}

/// Build + partially sign the payment transaction for an authorized
/// requirement. `blockhash` comes from RPC (x402 payments are immediate;
/// no durable nonce needed — maxTimeoutSeconds covers the window).
pub fn build_payment(
    req: &PaymentRequirement,
    cfg: &SettleConfig,
    blockhash: [u8; 32],
    decimals: u8,
) -> Result<String, String> {
    let amount: u64 = req.amount.trim().parse().map_err(|_| "bad amount")?;
    let payer = cfg.session_key.pubkey;
    let mint = Pubkey::from_base58(&req.asset)?;
    let pay_to = Pubkey::from_base58(&req.pay_to)?;
    let token_program = Pubkey::from_base58(program_ids::SPL_TOKEN)?;
    let fee_payer_str = req
        .extra
        .as_ref()
        .and_then(|e| e.fee_payer.as_deref())
        .ok_or("challenge has no extra.feePayer — cannot build sponsored tx")?;
    let fee_payer = Pubkey::from_base58(fee_payer_str)?;

    let source_ata = derive_ata(&payer, &mint, &token_program)?;
    let dest_ata = derive_ata(&pay_to, &mint, &token_program)?;

    let mut ixs = vec![spl_transfer_checked(
        token_program,
        source_ata,
        mint,
        dest_ata,
        payer,
        amount,
        decimals,
    )];
    if let Some(m) = req.extra.as_ref().and_then(|e| e.memo.as_deref()) {
        // Seller memo is REQUIRED verbatim by the spec when present (≤256B).
        if m.len() > 256 {
            return Err("seller memo exceeds 256 bytes".into());
        }
        ixs.push(memo(m, payer));
    }

    // feePayer (sponsor) is the message payer → signature slot 0 (zeroed);
    // our session key signs its own slot.
    let msg = compile_message(fee_payer, &ixs, blockhash)?;
    let our_index = msg
        .account_keys
        .iter()
        .position(|k| *k == payer)
        .ok_or("session key not in message")?;
    partially_signed_transaction_base64(&msg, &[(our_index, &cfg.session_key)])
}

/// Render the "paid" summary the model sees.
pub fn paid_summary(req: &PaymentRequirement, decimals: u8, url: &str) -> ToolOutput {
    let amount: u64 = req.amount.trim().parse().unwrap_or(0);
    let scale = 10u64.pow(decimals as u32);
    let ui = format!(
        "{}.{:0width$}",
        amount / scale,
        amount % scale,
        width = decimals as usize
    );
    ToolOutput::ok(format!(
        "Paid {} {} to {} for {} — resource retrieved.",
        ui.trim_end_matches('0').trim_end_matches('.'),
        short(&req.asset),
        short(&req.pay_to),
        origin_of(url).unwrap_or_else(|_| "resource".into()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC_DEV: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

    fn cfg() -> SettleConfig {
        let mut s = HashMap::new();
        s.insert(
            "origin_allowlist".into(),
            "https://api.dataseller.io".into(),
        );
        s.insert("mint_allowlist".into(), USDC_DEV.to_string());
        s.insert("max_per_request".into(), "100000".into()); // 0.1 USDC
        s.insert("max_per_day".into(), "1000000".into()); // 1 USDC
        s.insert(
            "session_key".into(),
            serde_json::to_string(&vec![7u8; 32]).unwrap(),
        );
        SettleConfig::from_section(&s).unwrap()
    }

    fn requirement(amount: &str, asset: &str) -> PaymentRequirement {
        PaymentRequirement {
            scheme: "exact".into(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
            amount: amount.into(),
            asset: asset.into(),
            pay_to: "4oL5MdWr2FFFzF1u2w8ctx8Yj77BYe8GLadGHuNvANd3".into(),
            extra: Some(Extra {
                fee_payer: Some("7JktSFAdMVixgsBQVm7V9RJ34LHy2RfyxHgqXfDJHFWa".into()),
                memo: Some("pi_test123".into()),
            }),
        }
    }

    fn challenge(reqs: Vec<PaymentRequirement>) -> PaymentRequired {
        PaymentRequired { accepts: reqs }
    }

    #[test]
    fn origin_parsing() {
        assert_eq!(
            origin_of("https://API.DataSeller.io/feed?q=1").unwrap(),
            "https://api.dataseller.io"
        );
        assert!(origin_of("http://plain.example").is_err()); // https only
        assert!(origin_of("https://user@evil.com/x").is_err());
        assert!(origin_of("garbage").is_err());
    }

    #[test]
    fn pays_within_policy() {
        let got = authorize_challenge(
            "https://api.dataseller.io/feed",
            &challenge(vec![requirement("50000", USDC_DEV)]),
            &cfg(),
            0,
        );
        assert!(got.is_ok());
    }

    /// Prompt-injection: "fetch https://evil.example/free-money" — origin not
    /// allowlisted → refused before any challenge parsing matters.
    #[test]
    fn injection_unknown_origin_fails_closed() {
        let v = authorize_challenge(
            "https://evil.example/data",
            &challenge(vec![requirement("1", USDC_DEV)]),
            &cfg(),
            0,
        )
        .unwrap_err();
        assert!(
            matches!(v, Verdict::Refused { ref reason } if reason.contains("not on the operator allowlist"))
        );
    }

    /// A malicious server quoting 2 USDC when our cap is 0.1 → refused.
    #[test]
    fn over_cap_challenge_refused() {
        let v = authorize_challenge(
            "https://api.dataseller.io/feed",
            &challenge(vec![requirement("2000000", USDC_DEV)]),
            &cfg(),
            0,
        )
        .unwrap_err();
        assert!(!v.is_authorized());
    }

    /// Daily budget nearly exhausted → next payment refused.
    #[test]
    fn daily_cap_binds() {
        let v = authorize_challenge(
            "https://api.dataseller.io/feed",
            &challenge(vec![requirement("100000", USDC_DEV)]),
            &cfg(),
            950_000,
        );
        assert!(v.is_err());
    }

    /// Server offers an unknown mint (attacker's token) → refused.
    #[test]
    fn unknown_mint_refused() {
        let v = authorize_challenge(
            "https://api.dataseller.io/feed",
            &challenge(vec![requirement(
                "1",
                "EvilMint1111111111111111111111111111111111",
            )]),
            &cfg(),
            0,
        );
        assert!(v.is_err());
    }

    /// Multiple options → cheapest acceptable one is chosen.
    #[test]
    fn picks_cheapest_acceptable() {
        let got = authorize_challenge(
            "https://api.dataseller.io/feed",
            &challenge(vec![
                requirement("90000", USDC_DEV),
                requirement("40000", USDC_DEV),
            ]),
            &cfg(),
            0,
        )
        .unwrap();
        assert_eq!(got.amount, "40000");
    }

    /// Empty config = pay nothing, ever.
    #[test]
    fn default_config_denies() {
        let mut s = HashMap::new();
        s.insert(
            "session_key".into(),
            serde_json::to_string(&vec![7u8; 32]).unwrap(),
        );
        let c = SettleConfig::from_section(&s).unwrap();
        let v = authorize_challenge(
            "https://api.dataseller.io/feed",
            &challenge(vec![requirement("1", USDC_DEV)]),
            &c,
            0,
        );
        assert!(v.is_err());
    }

    #[test]
    fn builds_partially_signed_payment() {
        let c = cfg();
        let req = requirement("50000", USDC_DEV);
        let b64 = build_payment(&req, &c, [9u8; 32], 6).unwrap();
        let raw = solana_wasi_core::encoding::b64_decode(&b64).unwrap();
        // Two signature slots: feePayer (sponsor, zeroed) + session key (real).
        assert_eq!(raw[0], 2);
        let sponsor_sig = &raw[1..65];
        let our_sig = &raw[65..129];
        assert!(sponsor_sig.iter().all(|b| *b == 0));
        assert!(our_sig.iter().any(|b| *b != 0));
    }

    #[test]
    fn missing_fee_payer_is_error() {
        let c = cfg();
        let mut req = requirement("50000", USDC_DEV);
        req.extra = None;
        assert!(build_payment(&req, &c, [0u8; 32], 6).is_err());
    }
}
