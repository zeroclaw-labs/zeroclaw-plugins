//! Simulation-based validation — two layers that compose before the unsigned
//! tx is returned to the caller.
//!
//! **Layer A — balance diff**: diffs `preTokenBalances` vs `postTokenBalances`.
//! Every touched mint must be in `mint_allowlist`. Net outflow from
//! `signer_pubkey` per mint must be ≤ `per_call_outflow_cap`. Any account with
//! net inflow must be in `recipient_allowlist` (if non-empty). Simulation `err`
//! is a hard reject.
//!
//! **Layer B — token-account state diff**: decodes writable SPL Token /
//! Token-2022 accounts from `sim.accounts` (165-byte AccountLayout). Rejects if
//! any account's `delegate` field is non-null AND not in
//! `expected_delegates_allowlist`, or if `close_authority` is set, or if the
//! `owner` field doesn't match any known owner from pre/post balances.
//!
//! Layer B catches CPI-based `approve` that the top-level discriminator block
//! in `idl.rs` can't see — e.g. a fake "reward claim" that internally CPIs
//! into `spl_token::approve` surfaces here as an unexpected delegate.

use std::collections::{HashMap, HashSet};

use base64::Engine;

use crate::builder::{err, SimulationReport, TokenBalance};
use crate::policy::{PolicyConfig, SPL_TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM};

/// Result of running both validation layers.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub passed: bool,
    pub error: Option<String>,
    /// signer_pubkey → (mint → base-unit outflow). Consumed by the summary.
    pub signer_outflows: HashMap<String, u64>,
    pub mints_touched: HashSet<String>,
    pub units_consumed: u64,
}

/// Run Layer A + Layer B. Returns the first rejection or a passing report.
pub fn validate(report: &SimulationReport, cfg: &PolicyConfig) -> ValidationReport {
    // Layer 0: simulation error → hard reject.
    if let Some(sim_err) = &report.err {
        return reject(
            err::SIMULATION_FAILED,
            format!("simulation error: {sim_err}"),
        );
    }

    let flows = compute_flows(&report.pre_token_balances, &report.post_token_balances);

    let mints_touched: HashSet<String> = flows.iter().map(|f| f.mint.clone()).collect();

    // Layer A — mint allowlist.
    for mint in &mints_touched {
        if !cfg.is_mint_allowed(mint) {
            return reject(
                err::MINT_NOT_ALLOWED,
                format!("mint {mint} not in allowlist"),
            );
        }
    }

    // Layer A — signer outflow per mint.
    let mut signer_outflows: HashMap<String, u64> = HashMap::new();
    for f in &flows {
        if f.owner == cfg.signer_pubkey && f.delta < 0 {
            let out = u64::try_from(-f.delta).unwrap_or(u64::MAX);
            *signer_outflows.entry(f.mint.clone()).or_default() += out;
        }
    }
    for (mint, amt) in &signer_outflows {
        if !cfg.is_within_cap(mint, *amt) {
            return reject(
                err::OUTFLOW_CAP_EXCEEDED,
                format!("mint {mint} outflow {amt} exceeds cap"),
            );
        }
    }

    // Layer A — recipient allowlist (non-empty = enforced).
    if !cfg.recipient_allowlist.is_empty() {
        for f in &flows {
            if f.owner != cfg.signer_pubkey && f.delta > 0 && !cfg.is_recipient_allowed(&f.owner) {
                return reject(
                    err::RECIPIENT_NOT_ALLOWED,
                    format!("recipient {} not in allowlist", f.owner),
                );
            }
        }
    }

    // Layer B — token-account state diff.
    let known_owners: HashSet<String> = report
        .pre_token_balances
        .iter()
        .chain(report.post_token_balances.iter())
        .map(|tb| tb.owner.clone())
        .collect();

    for acct in &report.accounts {
        if !acct.writable {
            continue;
        }
        if acct.owner != SPL_TOKEN_PROGRAM && acct.owner != SPL_TOKEN_2022_PROGRAM {
            continue;
        }
        let raw = match &acct.data_base64 {
            Some(b64) => b64,
            None => continue,
        };
        let data = match base64::engine::general_purpose::STANDARD.decode(raw) {
            Ok(bytes) if bytes.len() >= 165 => bytes,
            _ => continue,
        };

        // delegate COption at offset 72: tag [72..76], value [76..108].
        if data[72] != 0 {
            let delegate_b58 = bs58::encode(&data[76..108]).into_string();
            if !cfg.is_delegate_expected(&delegate_b58) {
                return reject(
                    err::UNEXPECTED_DELEGATE,
                    format!("unexpected delegate: {delegate_b58}"),
                );
            }
        }

        // close_authority COption at offset 129: tag [129..133].
        if data[129] != 0 {
            return reject(
                err::CLOSE_AUTHORITY_CHANGED,
                "close_authority changed mid-sim".to_string(),
            );
        }

        // owner field at offset [32..64] — must match a known owner.
        let owner_b58 = bs58::encode(&data[32..64]).into_string();
        if !is_all_zero(&data[32..64]) && !known_owners.contains(&owner_b58) {
            return reject(err::OWNER_CHANGED, format!("owner changed: {owner_b58}"));
        }
    }

    ValidationReport {
        passed: true,
        error: None,
        signer_outflows,
        mints_touched,
        units_consumed: report.units_consumed,
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

struct Flow {
    mint: String,
    owner: String,
    delta: i128,
}

fn compute_flows(pre: &[TokenBalance], post: &[TokenBalance]) -> Vec<Flow> {
    let pre_map: HashMap<u32, &TokenBalance> =
        pre.iter().map(|tb| (tb.account_index, tb)).collect();
    let post_map: HashMap<u32, &TokenBalance> =
        post.iter().map(|tb| (tb.account_index, tb)).collect();

    let mut all_indices: HashSet<u32> = pre_map.keys().copied().collect();
    all_indices.extend(post_map.keys().copied());

    let mut flows = Vec::new();
    for idx in all_indices {
        let pre_amt = pre_map
            .get(&idx)
            .and_then(|tb| tb.amount.parse::<i128>().ok())
            .unwrap_or(0);
        let post_amt = post_map
            .get(&idx)
            .and_then(|tb| tb.amount.parse::<i128>().ok())
            .unwrap_or(0);
        let delta = post_amt - pre_amt;
        if delta != 0 {
            let tb = post_map.get(&idx).or(pre_map.get(&idx)).unwrap();
            flows.push(Flow {
                mint: tb.mint.clone(),
                owner: tb.owner.clone(),
                delta,
            });
        }
    }
    flows
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn reject(error_tag: &str, detail: String) -> ValidationReport {
    ValidationReport {
        passed: false,
        error: Some(format!("{error_tag}: {detail}")),
        signer_outflows: HashMap::new(),
        mints_touched: HashSet::new(),
        units_consumed: 0,
    }
}

// ─── self-check ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{SimulatedAccount, TokenBalance};
    use crate::policy::PolicyConfig;

    const SIGNER: &str = "9WZDXwBbmkg8ZTbNMqUxvQRAyrZzDSjDxXfaoFYmBbGX";
    const USDC: &str = "EPjFWcc5VB1U3BdVJU6dQqXxVV7iLPmsZ3jLGqxQzG2d";
    const ATTACKER_MINT: &str = "SoGreatDealFakeMintAttackAttackAttackAttacHKM";
    const RECIPIENT: &str = "7Np41oeYqPefeJQ5WqVcZHykOxrxXtPHuSdYXdXw3jWi";
    const ATTACKER: &str = "AttaCK3rAddressOneTwoThreeFourFiveSixSevenEightNne";
    const SOURCE_ATA: &str = "SrcTokenATAkk11111111111111111111111111111111";

    fn tb(idx: u32, mint: &str, owner: &str, amount: &str) -> TokenBalance {
        TokenBalance {
            account_index: idx,
            mint: mint.to_string(),
            owner: owner.to_string(),
            program_id: SPL_TOKEN_PROGRAM.to_string(),
            amount: amount.to_string(),
        }
    }

    fn policy_with(outflow: u64) -> PolicyConfig {
        let mut cfg = PolicyConfig {
            signer_pubkey: SIGNER.to_string(),
            ..Default::default()
        };
        cfg.per_call_outflow_cap.insert(USDC.to_string(), outflow);
        cfg.mint_allowlist = vec![USDC.to_string()];
        cfg
    }

    fn ok_sim() -> SimulationReport {
        SimulationReport {
            err: None,
            pre_token_balances: vec![
                tb(0, USDC, SIGNER, "100000000"),
                tb(1, USDC, RECIPIENT, "0"),
            ],
            post_token_balances: vec![
                tb(0, USDC, SIGNER, "95000000"),
                tb(1, USDC, RECIPIENT, "5000000"),
            ],
            accounts: vec![],
            units_consumed: 5_000,
            logs: vec![],
        }
    }

    fn token_account_data(
        delegate: Option<[u8; 32]>,
        close_authority: Option<[u8; 32]>,
        owner_override: Option<[u8; 32]>,
    ) -> String {
        let mut data = vec![0u8; 165];
        if let Some(o) = owner_override {
            data[32..64].copy_from_slice(&o);
        }
        if let Some(d) = delegate {
            data[72] = 1;
            data[76..108].copy_from_slice(&d);
        }
        data[108] = 1; // Initialized
        if let Some(ca) = close_authority {
            data[129] = 1;
            data[133..165].copy_from_slice(&ca);
        }
        base64::engine::general_purpose::STANDARD.encode(&data)
    }

    fn writable_acct(data: &str) -> SimulatedAccount {
        SimulatedAccount {
            pubkey: SOURCE_ATA.to_string(),
            owner: SPL_TOKEN_PROGRAM.to_string(),
            lamports: 10_000_000,
            data_base64: Some(data.to_string()),
            writable: true,
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn happy_path_passes() {
        let cfg = policy_with(100_000_000);
        let rpt = validate(&ok_sim(), &cfg);
        assert!(rpt.passed, "{}", rpt.error.unwrap_or_default());
        assert_eq!(rpt.units_consumed, 5_000);
        assert_eq!(rpt.signer_outflows.get(USDC), Some(&5_000_000u64));
    }

    #[test]
    fn sim_err_rejects() {
        let cfg = policy_with(100_000_000);
        let mut sim = ok_sim();
        sim.err = Some("InstructionError(0, InsufficientFunds)".into());
        let rpt = validate(&sim, &cfg);
        assert!(!rpt.passed);
        assert!(rpt
            .error
            .unwrap()
            .to_ascii_lowercase()
            .contains(err::SIMULATION_FAILED));
    }

    #[test]
    fn disallowed_mint_rejects() {
        let cfg = policy_with(100_000_000);
        let sim = SimulationReport {
            err: None,
            pre_token_balances: vec![tb(0, ATTACKER_MINT, SIGNER, "1000")],
            post_token_balances: vec![tb(0, ATTACKER_MINT, SIGNER, "0")],
            accounts: vec![],
            units_consumed: 3_000,
            logs: vec![],
        };
        let rpt = validate(&sim, &cfg);
        assert!(!rpt.passed);
        assert!(rpt
            .error
            .unwrap()
            .to_ascii_lowercase()
            .contains(err::MINT_NOT_ALLOWED));
    }

    #[test]
    fn cap_exceeded_rejects() {
        let cfg = policy_with(100_000_000); // 100 USDC
        let sim = SimulationReport {
            err: None,
            pre_token_balances: vec![tb(0, USDC, SIGNER, "2000000000")],
            post_token_balances: vec![
                tb(0, USDC, SIGNER, "1000000000"),
                tb(1, USDC, RECIPIENT, "1000000000"),
            ],
            accounts: vec![],
            units_consumed: 4_000,
            logs: vec![],
        };
        let rpt = validate(&sim, &cfg);
        assert!(!rpt.passed);
        assert!(rpt
            .error
            .unwrap()
            .to_ascii_lowercase()
            .contains(err::OUTFLOW_CAP_EXCEEDED));
    }

    #[test]
    fn disallowed_recipient_rejects() {
        let mut cfg = policy_with(100_000_000);
        cfg.recipient_allowlist = vec![RECIPIENT.to_string()];
        let sim = SimulationReport {
            err: None,
            pre_token_balances: vec![tb(0, USDC, SIGNER, "100000000")],
            post_token_balances: vec![
                tb(0, USDC, SIGNER, "95000000"),
                tb(1, USDC, ATTACKER, "5000000"),
            ],
            accounts: vec![],
            units_consumed: 4_000,
            logs: vec![],
        };
        let rpt = validate(&sim, &cfg);
        assert!(!rpt.passed);
        assert!(rpt
            .error
            .unwrap()
            .to_ascii_lowercase()
            .contains(err::RECIPIENT_NOT_ALLOWED));
    }

    #[test]
    fn unexpected_delegate_rejects() {
        let cfg = policy_with(100_000_000);
        let delegate = [0xBBu8; 32];
        let mut sim = ok_sim();
        sim.accounts = vec![writable_acct(&token_account_data(
            Some(delegate),
            None,
            None,
        ))];
        let rpt = validate(&sim, &cfg);
        assert!(!rpt.passed);
        assert!(rpt
            .error
            .unwrap()
            .to_ascii_lowercase()
            .contains(err::UNEXPECTED_DELEGATE));
    }

    #[test]
    fn expected_delegate_passes() {
        let delegate = [0xBBu8; 32];
        let delegate_b58 = bs58::encode(&delegate).into_string();
        let mut cfg = policy_with(100_000_000);
        cfg.expected_delegates_allowlist = vec![delegate_b58];

        let mut sim = ok_sim();
        sim.accounts = vec![writable_acct(&token_account_data(
            Some(delegate),
            None,
            None,
        ))];
        let rpt = validate(&sim, &cfg);
        assert!(rpt.passed, "{}", rpt.error.unwrap_or_default());
    }

    #[test]
    fn close_authority_rejects() {
        let cfg = policy_with(100_000_000);
        let mut sim = ok_sim();
        sim.accounts = vec![writable_acct(&token_account_data(
            None,
            Some([0xCCu8; 32]),
            None,
        ))];
        let rpt = validate(&sim, &cfg);
        assert!(!rpt.passed);
        assert!(rpt
            .error
            .unwrap()
            .to_ascii_lowercase()
            .contains(err::CLOSE_AUTHORITY_CHANGED));
    }

    #[test]
    fn owner_change_rejects() {
        let cfg = policy_with(100_000_000);
        let mut sim = ok_sim();
        sim.accounts = vec![writable_acct(&token_account_data(
            None,
            None,
            Some([0xDDu8; 32]),
        ))];
        let rpt = validate(&sim, &cfg);
        assert!(!rpt.passed);
        assert!(rpt
            .error
            .unwrap()
            .to_ascii_lowercase()
            .contains(err::OWNER_CHANGED));
    }

    #[test]
    fn non_writable_accounts_skipped() {
        let cfg = policy_with(100_000_000);
        let mut sim = ok_sim();
        let mut acct = writable_acct(&token_account_data(Some([0xBBu8; 32]), None, None));
        acct.writable = false;
        sim.accounts = vec![acct];
        let rpt = validate(&sim, &cfg);
        assert!(rpt.passed, "non-writable accounts must be skipped");
    }
}
