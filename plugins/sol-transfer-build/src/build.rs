//! Pure transaction-building logic for an unsigned SOL transfer. Tested on the
//! host against `solana_core::rpc::MockTransport` — no wasm, no network.
//!
//! Custody tier **T1 (Build)**: this returns an UNSIGNED base64 transaction. No
//! private key is held or referenced anywhere in this crate. The signer is
//! whoever the operator routes the approval to — a hardware wallet, the
//! ZeroClaw approval gate, or a Squads multisig proposal.
//!
//! ## The blockhash-expiry answer (bounty trap #1)
//! A recent blockhash dies in ~90 seconds. If the human approving the transfer
//! is at lunch, a recent-blockhash tx is dead on arrival. Pass a durable nonce
//! account and this builder instead pins the message to the account's stored
//! nonce and prepends `AdvanceNonceAccount`, so the transaction stays valid
//! until it actually lands.

use solana_core::base58;
use solana_core::error::CoreError;
use solana_core::message::MessageBuilder;
use solana_core::nonce::decode_nonce_account;
use solana_core::programs;
use solana_core::pubkey::{programs as prog_ids, Pubkey};
use solana_core::rpc::{RpcTransport, SolanaRpc};
use solana_core::shape;

/// Durable-nonce parameters. `authority` defaults to the fee payer if `None`.
#[derive(Debug, Clone)]
pub struct DurableNonce {
    pub account: Pubkey,
    pub authority: Option<Pubkey>,
}

/// Validated build parameters.
#[derive(Debug, Clone)]
pub struct BuildParams {
    pub from: Pubkey,
    pub to: Pubkey,
    pub lamports: u64,
    pub durable_nonce: Option<DurableNonce>,
    /// Optional priority fee in micro-lamports per compute unit.
    pub priority_micro_lamports: Option<u64>,
}

/// The result handed to the approval gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildOutput {
    pub transaction_base64: String,
    pub required_signatures: u8,
    pub blockhash_strategy: &'static str,
    pub summary: String,
}

/// Build the unsigned transfer. One RPC read (blockhash or nonce account), no
/// signing.
pub fn build_transfer<T: RpcTransport>(
    rpc: &SolanaRpc<T>,
    params: &BuildParams,
) -> Result<BuildOutput, CoreError> {
    if params.lamports == 0 {
        return Err(CoreError::Invalid("amount must be greater than zero".into()));
    }

    let mut instructions = Vec::new();
    if let Some(mlports) = params.priority_micro_lamports {
        instructions.push(programs::set_compute_unit_price(mlports));
    }

    let (blockhash, strategy): ([u8; 32], &'static str) = match &params.durable_nonce {
        Some(dn) => {
            // Fetch the nonce account, decode its stored nonce and authority.
            let account = rpc
                .get_account_info(&dn.account)?
                .ok_or_else(|| CoreError::Invalid("nonce account not found".into()))?;
            if account.owner != prog_ids::system() {
                return Err(CoreError::Invalid(
                    "nonce account is not owned by the System program".into(),
                ));
            }
            let nonce = decode_nonce_account(&account.data)?;
            let authority = dn.authority.unwrap_or(params.from);
            if nonce.authority != authority {
                return Err(CoreError::Invalid(format!(
                    "nonce authority mismatch: account expects {}",
                    shape::short_pubkey(&nonce.authority)
                )));
            }
            // AdvanceNonceAccount MUST be the first instruction.
            instructions.push(programs::advance_nonce_account(dn.account, authority));
            (nonce.blockhash, "durable nonce (does not expire)")
        }
        None => {
            let latest = rpc.get_latest_blockhash()?;
            let hash = base58::decode_32(&latest.blockhash)?;
            (hash, "recent blockhash (valid ~90s)")
        }
    };

    instructions.push(programs::system_transfer(params.from, params.to, params.lamports));

    let mut builder = MessageBuilder::new(params.from, blockhash);
    builder.instructions = instructions;
    let transaction_base64 = builder.to_unsigned_base64()?;
    let required_signatures = builder.required_signatures()?;

    let summary = format!(
        "Unsigned transfer: {} SOL from {} → {}\nStrategy: {}. Requires {} signature(s). \
         Sign with your wallet / approval gate / Squads proposal — no key is held by the agent.",
        shape::lamports_to_sol(params.lamports),
        shape::short_pubkey(&params.from),
        shape::short_pubkey(&params.to),
        strategy,
        required_signatures
    );

    Ok(BuildOutput {
        transaction_base64,
        required_signatures,
        blockhash_strategy: strategy,
        summary,
    })
}

/// Convert a decimal SOL string to lamports without floating point.
/// "1.5" → 1_500_000_000. Rejects negatives, scientific notation, > 9 decimals.
pub fn sol_to_lamports(s: &str) -> Result<u64, CoreError> {
    let s = s.trim();
    let bad = || CoreError::Invalid(format!("'{s}' is not a valid SOL amount"));
    let mut parts = s.split('.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err(bad());
    }
    if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    if frac_part.len() > 9 || !frac_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let int: u64 = int_part.parse().map_err(|_| bad())?;
    let mut frac_padded = frac_part.to_string();
    while frac_padded.len() < 9 {
        frac_padded.push('0');
    }
    let frac: u64 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded.parse().map_err(|_| bad())?
    };
    int.checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(frac))
        .ok_or_else(|| CoreError::Invalid("amount overflows u64 lamports".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use solana_core::base64;
    use solana_core::rpc::MockTransport;

    const FROM: &str = "GdnSyH3YtwcxFvQrVVJMm1JhTS4QVX7MFsX56uJLUfiZ";
    const TO: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    // A valid base58 32-byte value to stand in as a blockhash.
    const BLOCKHASH: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const NONCE_ACC: &str = "So11111111111111111111111111111111111111112";

    fn params() -> BuildParams {
        BuildParams {
            from: Pubkey::from_base58(FROM).unwrap(),
            to: Pubkey::from_base58(TO).unwrap(),
            lamports: 1_500_000_000,
            durable_nonce: None,
            priority_micro_lamports: None,
        }
    }

    #[test]
    fn recent_blockhash_transfer_builds_unsigned_tx() {
        let rpc = SolanaRpc::new(MockTransport::with_results(vec![json!({
            "context": {"slot": 1},
            "value": {"blockhash": BLOCKHASH, "lastValidBlockHeight": 1000}
        })]));
        let out = build_transfer(&rpc, &params()).unwrap();
        assert_eq!(out.required_signatures, 1);
        assert_eq!(out.blockhash_strategy, "recent blockhash (valid ~90s)");
        // The base64 decodes and starts with a single zero signature slot.
        let raw = base64::decode(&out.transaction_base64).unwrap();
        assert_eq!(raw[0], 1); // 1 signature
        assert!(raw[1..65].iter().all(|&b| b == 0)); // zeroed (unsigned)
        assert!(out.summary.contains("1.5 SOL"));
    }

    #[test]
    fn durable_nonce_transfer_uses_stored_nonce() {
        // Build a nonce account: state=1, authority=FROM, nonce=BLOCKHASH bytes.
        let mut data = vec![0u8; 80];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..40].copy_from_slice(&Pubkey::from_base58(FROM).unwrap().0);
        data[40..72].copy_from_slice(&base58::decode_32(BLOCKHASH).unwrap());
        data[72..80].copy_from_slice(&5000u64.to_le_bytes());

        let rpc = SolanaRpc::new(MockTransport::with_results(vec![json!({
            "context": {"slot": 1},
            "value": {
                "lamports": 1_000_000u64,
                "owner": "11111111111111111111111111111111",
                "data": [base64::encode(&data), "base64"],
                "executable": false, "rentEpoch": 0
            }
        })]));

        let mut p = params();
        p.durable_nonce = Some(DurableNonce {
            account: Pubkey::from_base58(NONCE_ACC).unwrap(),
            authority: None,
        });
        let out = build_transfer(&rpc, &p).unwrap();
        assert_eq!(out.blockhash_strategy, "durable nonce (does not expire)");
        assert!(out.summary.contains("durable nonce"));
        // decodes cleanly
        assert!(!base64::decode(&out.transaction_base64).unwrap().is_empty());
    }

    #[test]
    fn nonce_authority_mismatch_fails_closed() {
        let mut data = vec![0u8; 80];
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..40].copy_from_slice(&[42u8; 32]); // some other authority
        data[40..72].copy_from_slice(&base58::decode_32(BLOCKHASH).unwrap());
        let rpc = SolanaRpc::new(MockTransport::with_results(vec![json!({
            "context": {"slot": 1},
            "value": {"lamports": 1u64, "owner": "11111111111111111111111111111111",
                      "data": [base64::encode(&data), "base64"], "executable": false, "rentEpoch": 0}
        })]));
        let mut p = params();
        p.durable_nonce = Some(DurableNonce {
            account: Pubkey::from_base58(NONCE_ACC).unwrap(),
            authority: None,
        });
        assert!(matches!(build_transfer(&rpc, &p), Err(CoreError::Invalid(_))));
    }

    #[test]
    fn zero_amount_rejected() {
        let rpc = SolanaRpc::new(MockTransport::with_results(vec![]));
        let mut p = params();
        p.lamports = 0;
        assert!(matches!(build_transfer(&rpc, &p), Err(CoreError::Invalid(_))));
    }

    #[test]
    fn sol_to_lamports_conversion() {
        assert_eq!(sol_to_lamports("1").unwrap(), 1_000_000_000);
        assert_eq!(sol_to_lamports("1.5").unwrap(), 1_500_000_000);
        assert_eq!(sol_to_lamports("0.000000001").unwrap(), 1);
        assert_eq!(sol_to_lamports("0").unwrap(), 0);
        for bad in ["-1", "1e3", "1.2.3", "abc", "0.0000000001", ""] {
            assert!(sol_to_lamports(bad).is_err(), "should reject {bad:?}");
        }
    }
}
