//! Pure builder core for `nonce-transfer-build`: policy check → instruction
//! assembly → unsigned durable-nonce transaction. No network, no wasm — the
//! shim feeds it RPC responses it fetched via `waki`; tests feed fixtures.

use std::collections::HashMap;

use serde::Deserialize;
use solana_wasi_core::instruction::{
    advance_nonce_account, create_ata_idempotent, derive_ata, memo, spl_transfer_checked,
};
use solana_wasi_core::message::{compile_message, unsigned_transaction_base64};
use solana_wasi_core::nonce::NonceState;
use solana_wasi_core::policy::{SpendPolicy, Verdict};
use solana_wasi_core::pubkey::{program_ids, short, Pubkey};
use solana_wasi_core::shape::ToolOutput;

/// Arguments the LLM supplies. UNTRUSTED — everything is validated against
/// operator config before any transaction bytes exist.
#[derive(Deserialize)]
pub struct BuildArgs {
    /// Recipient owner address (base58) — must be on the operator allowlist.
    pub recipient: String,
    /// Mint address (base58) — must be on the operator allowlist.
    pub mint: String,
    /// Human-readable amount, e.g. "25" or "25.5".
    pub amount: String,
    /// Optional memo for invoice reconciliation.
    #[serde(default)]
    pub memo: Option<String>,
}

/// Operator configuration (the plugin's jailed config section).
pub struct OperatorConfig {
    pub policy: SpendPolicy,
    /// The treasury owner whose ATA funds move FROM (fee payer + authority).
    pub payer: String,
    /// The durable nonce account this agent's proposals anchor to.
    pub nonce_account: String,
    pub rpc_url: String,
}

impl OperatorConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let get = |k: &str| -> Result<String, String> {
            section
                .get(k)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("missing required config key `{k}`"))
        };
        Ok(Self {
            policy: SpendPolicy::from_section(section),
            payer: get("payer")?,
            nonce_account: get("nonce_account")?,
            rpc_url: section
                .get("rpc_url")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "https://api.devnet.solana.com".to_string()),
        })
    }
}

/// Convert a decimal string amount to base units. Fails closed on garbage,
/// negatives, and precision beyond the mint's decimals.
pub fn to_base_units(amount: &str, decimals: u8) -> Result<u64, String> {
    let s = amount.trim();
    if s.is_empty() || s.starts_with('-') || s.starts_with('+') {
        return Err(format!("invalid amount `{amount}`"));
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(format!("invalid amount `{amount}`"));
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err(format!("invalid amount `{amount}`"));
    }
    if frac_part.len() > decimals as usize {
        return Err(format!(
            "amount `{amount}` has more precision than the mint's {decimals} decimals"
        ));
    }
    let scale = 10u64
        .checked_pow(decimals as u32)
        .ok_or("decimals too large")?;
    let int_val: u64 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().map_err(|_| "amount too large")?
    };
    let mut frac_val: u64 = if frac_part.is_empty() {
        0
    } else {
        frac_part.parse().map_err(|_| "amount too large")?
    };
    frac_val *= 10u64.pow((decimals as usize - frac_part.len()) as u32);
    int_val
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| "amount overflows u64".to_string())
}

/// The full build path. `nonce_state` and `decimals` come from RPC (the shim
/// fetches them); everything else is deterministic.
pub fn build_transfer(
    args: &BuildArgs,
    cfg: &OperatorConfig,
    nonce_state: &NonceState,
    decimals: u8,
    spent_today: u64,
) -> ToolOutput {
    // 1. Parse amount first (cheap, no policy implications).
    let base_units = match to_base_units(&args.amount, decimals) {
        Ok(v) => v,
        Err(e) => return ToolOutput::refused(format!("refused: {e}")),
    };

    // 2. THE GATE. Policy speaks before any key material or tx bytes exist.
    match cfg
        .policy
        .authorize(&args.recipient, &args.mint, base_units, spent_today)
    {
        Verdict::Authorized => {}
        Verdict::Refused { reason } => {
            return ToolOutput::refused(format!("refused: {reason}"))
                .with_detail("No transaction was built. This decision is enforced by operator config and cannot be overridden from chat.");
        }
    }

    // 3. Parse keys (post-policy: allowlisted strings are operator-vetted).
    let parse = |label: &str, s: &str| -> Result<Pubkey, String> {
        Pubkey::from_base58(s).map_err(|e| format!("{label}: {e}"))
    };
    let assembled = (|| -> Result<(String, String), String> {
        let payer = parse("payer", &cfg.payer)?;
        let recipient = parse("recipient", &args.recipient)?;
        let mint_key = parse("mint", &args.mint)?;
        let nonce_acct = parse("nonce_account", &cfg.nonce_account)?;
        let token_program = Pubkey::from_base58(program_ids::SPL_TOKEN)?;

        let source_ata = derive_ata(&payer, &mint_key, &token_program)?;
        let dest_ata = derive_ata(&recipient, &mint_key, &token_program)?;

        let mut ixs = vec![
            // Durable nonce: MUST be first. The tx stays valid until the
            // human approves — minutes or days later.
            advance_nonce_account(nonce_acct, nonce_state.authority),
            create_ata_idempotent(payer, dest_ata, recipient, mint_key, token_program),
            spl_transfer_checked(
                token_program,
                source_ata,
                mint_key,
                dest_ata,
                payer,
                base_units,
                decimals,
            ),
        ];
        if let Some(m) = &args.memo {
            let clamped = solana_wasi_core::shape::clamp(m, 120);
            ixs.push(memo(&clamped, payer));
        }

        let msg = compile_message(payer, &ixs, nonce_state.durable_nonce)?;
        let tx = unsigned_transaction_base64(&msg);
        Ok((tx, dest_ata.to_base58()))
    })();

    match assembled {
        Ok((tx, dest_ata)) => ToolOutput::ok(format!(
            "Built unsigned transfer of {} {} to {} (nonce-anchored — does not expire awaiting approval). Requires signature from {}.",
            args.amount.trim(),
            short(&args.mint),
            short(&args.recipient),
            short(&cfg.payer),
        ))
        .with_tx(tx)
        .with_detail(format!("destination ATA {}", short(&dest_ata)))
        .with_detail("Sign with the treasury wallet or import into Squads; the AdvanceNonceAccount instruction keeps it valid indefinitely."),
        Err(e) => ToolOutput::refused(format!("refused: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYER: &str = "4oL5MdWr2FFFzF1u2w8ctx8Yj77BYe8GLadGHuNvANd3";
    const BOB: &str = "7JktSFAdMVixgsBQVm7V9RJ34LHy2RfyxHgqXfDJHFWa";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const NONCE_ACCT: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    fn cfg() -> OperatorConfig {
        let mut section = HashMap::new();
        section.insert("recipient_allowlist".into(), BOB.to_string());
        section.insert("mint_allowlist".into(), USDC.to_string());
        section.insert("max_per_tx".into(), "50000000".into());
        section.insert("max_per_day".into(), "100000000".into());
        section.insert("payer".into(), PAYER.to_string());
        section.insert("nonce_account".into(), NONCE_ACCT.to_string());
        OperatorConfig::from_section(&section).unwrap()
    }

    fn nonce_state() -> NonceState {
        NonceState {
            authority: Pubkey::from_base58(PAYER).unwrap(),
            durable_nonce: [7u8; 32],
            lamports_per_signature: 5000,
        }
    }

    fn args(recipient: &str, amount: &str) -> BuildArgs {
        BuildArgs {
            recipient: recipient.into(),
            mint: USDC.into(),
            amount: amount.into(),
            memo: Some("invoice #412".into()),
        }
    }

    #[test]
    fn amount_conversion() {
        assert_eq!(to_base_units("25", 6).unwrap(), 25_000_000);
        assert_eq!(to_base_units("25.5", 6).unwrap(), 25_500_000);
        assert_eq!(to_base_units("0.000001", 6).unwrap(), 1);
        assert!(to_base_units("25.1234567", 6).is_err()); // over-precision
        assert!(to_base_units("-5", 6).is_err());
        assert!(to_base_units("1e6", 6).is_err());
        assert!(to_base_units("", 6).is_err());
        assert!(to_base_units(".", 6).is_err());
    }

    #[test]
    fn happy_path_builds_nonce_anchored_tx() {
        let out = build_transfer(&args(BOB, "25"), &cfg(), &nonce_state(), 6, 0);
        let rendered = out.render();
        let v: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(v["status"], "ok");
        let tx_b64 = v["unsigned_tx_base64"].as_str().unwrap();
        let raw = solana_wasi_core::encoding::b64_decode(tx_b64).unwrap();
        // 1 required signature, zeroed.
        assert_eq!(raw[0], 1);
        assert!(raw[1..65].iter().all(|b| *b == 0));
        // recent_blockhash field == our durable nonce value, proving the tx
        // is nonce-anchored, not blockhash-anchored.
        let msg = &raw[65..];
        let n_keys = msg[3] as usize;
        let bh_offset = 4 + n_keys * 32;
        assert_eq!(&msg[bh_offset..bh_offset + 32], &[7u8; 32]);
    }

    #[test]
    fn injection_unknown_recipient_fails_closed() {
        let attacker = "Attacker9999999999999999999999999999999999";
        let out = build_transfer(&args(attacker, "25"), &cfg(), &nonce_state(), 6, 0);
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert_eq!(v["status"], "refused");
        assert!(v.get("unsigned_tx_base64").is_none());
        assert!(v["summary"].as_str().unwrap().contains("allowlist"));
    }

    #[test]
    fn injection_over_cap_fails_closed() {
        let out = build_transfer(&args(BOB, "51"), &cfg(), &nonce_state(), 6, 0);
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert_eq!(v["status"], "refused");
        assert!(v.get("unsigned_tx_base64").is_none());
    }

    #[test]
    fn injection_daily_cap_fails_closed() {
        let out = build_transfer(&args(BOB, "25"), &cfg(), &nonce_state(), 6, 90_000_000);
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert_eq!(v["status"], "refused");
    }

    #[test]
    fn injection_unknown_mint_fails_closed() {
        let mut a = args(BOB, "25");
        a.mint = "FakeUSDC111111111111111111111111111111111111".into();
        let out = build_transfer(&a, &cfg(), &nonce_state(), 6, 0);
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert_eq!(v["status"], "refused");
    }

    #[test]
    fn unconfigured_policy_denies_by_default() {
        let mut section = HashMap::new();
        section.insert("payer".into(), PAYER.to_string());
        section.insert("nonce_account".into(), NONCE_ACCT.to_string());
        let cfg = OperatorConfig::from_section(&section).unwrap();
        let out = build_transfer(&args(BOB, "1"), &cfg, &nonce_state(), 6, 0);
        let v: serde_json::Value = serde_json::from_str(&out.render()).unwrap();
        assert_eq!(v["status"], "refused");
    }

    #[test]
    fn missing_config_keys_error() {
        assert!(OperatorConfig::from_section(&HashMap::new()).is_err());
    }
}
