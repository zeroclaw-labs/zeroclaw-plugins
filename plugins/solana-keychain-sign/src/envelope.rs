//! Envelope-only transaction guards.
//!
//! The signer does **NOT** inspect transaction content — all financial
//! policy (mints, recipients, amounts, approve-family blocklist) lives in
//! the `solana-build-tx` plugin via simulation-based validation. The three
//! guards here check only the tx SHAPE:
//!
//!   1. `message_bytes.len() <= cfg.max_message_bytes` (default 1 KiB)
//!   2. `instructions.len() <= cfg.max_instructions` (default 1, locked v0)
//!   3. `message.fee_payer == cfg.signer_pubkey` (operator-configured
//!      backend pubkey)
//!
//! On violation: [`check`] returns the matching [`EnvelopeError`] variant;
//! the wasm shim (`lib.rs`) turns that into
//! `ToolResult { success: false, error: Some(reason) }` and emits a
//! `log-record` at `warn` with `action=Reject`. Never inspect instruction
//! data, never parse args, never check mints (that's build-tx's job).
//!
//! ## Guard ordering
//!
//! Guards run cheapest-first: size (an integer compare), then instruction
//! count (an integer compare), then fee-payer match (a string compare). A
//! malicious payload cannot force the plugin to do work on a guard that
//! fires earlier — the first violation short-circuits.

/// Envelope-only configuration. Lives under
/// `[plugins.entries.solana-keychain-sign.config]` and is deserialized by the
/// wasm shim from the `__config` map the host injects.
///
/// Defaults match the bounty HANDOFF §3 envelope spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeConfig {
    /// Maximum serialized message size accepted by the signer. 1 KiB is the
    /// bounty default; large enough for a single SPL transfer with one ALT,
    /// small enough to reject anything trying to smuggle a composite blob.
    pub max_message_bytes: usize,
    /// Maximum number of instructions in the message. Locked to 1 for v0
    /// (single-instruction txs only); composite txs are a v1+ concern.
    pub max_instructions: usize,
    /// The base58 Ed25519 pubkey the configured backend will sign for. The
    /// assembled message's `fee_payer` MUST equal this; otherwise the
    /// operator and the agent disagree on who is paying, which is always a
    /// prompt-injection signature.
    pub signer_pubkey: String,
}

impl Default for EnvelopeConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: 1024,
            max_instructions: 1,
            signer_pubkey: String::new(),
        }
    }
}

/// Reject reason for a guard violation. Operator-facing; carries no secrets.
///
/// Each variant's `Display` impl is the exact string that lands in
/// `ToolResult.error` and in the `log-record` attrs — keep them specific so
/// the operator can audit which guard fired without grepping code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// `message_bytes.len()` exceeded `cfg.max_message_bytes`.
    TooLarge { actual: usize, limit: usize },
    /// `instructions.len()` exceeded `cfg.max_instructions`.
    TooManyInstructions { actual: usize, limit: usize },
    /// Message fee_payer did not equal `cfg.signer_pubkey`.
    FeePayerMismatch { actual: String, expected: String },
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { actual, limit } => {
                write!(f, "message too large: {actual} bytes > {limit} byte limit")
            }
            Self::TooManyInstructions { actual, limit } => write!(
                f,
                "too many instructions: {actual} > {limit} (v0 allows single-instruction txs only)"
            ),
            Self::FeePayerMismatch { actual, expected } => write!(
                f,
                "fee_payer mismatch: message pays {actual}, signer is {expected}"
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Check the three envelope guards in cheapest-first order.
///
/// Arguments are the three things the caller already has post-assembly:
///   - `message_bytes_len` — serialized versioned message byte length
///   - `instructions_len` — count of instructions in the message
///   - `fee_payer_b58` — base58 pubkey string the message pays for
///
/// Returns `Ok(())` if all three pass; the first failing guard
/// short-circuits and returns its [`EnvelopeError`].
///
/// **Never** inspects instruction data, args, mints, or recipients — those
/// are `solana-build-tx`'s job via simulation-based policy.
pub fn check(
    cfg: &EnvelopeConfig,
    message_bytes_len: usize,
    instructions_len: usize,
    fee_payer_b58: &str,
) -> Result<(), EnvelopeError> {
    if message_bytes_len > cfg.max_message_bytes {
        return Err(EnvelopeError::TooLarge {
            actual: message_bytes_len,
            limit: cfg.max_message_bytes,
        });
    }
    if instructions_len > cfg.max_instructions {
        return Err(EnvelopeError::TooManyInstructions {
            actual: instructions_len,
            limit: cfg.max_instructions,
        });
    }
    if fee_payer_b58 != cfg.signer_pubkey {
        return Err(EnvelopeError::FeePayerMismatch {
            actual: fee_payer_b58.to_string(),
            expected: cfg.signer_pubkey.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> EnvelopeConfig {
        EnvelopeConfig {
            max_message_bytes: 1024,
            max_instructions: 1,
            signer_pubkey: "9XJSignerPubkeyBase58".to_string(),
        }
    }

    // ── happy path ──────────────────────────────────────────────────────────

    #[test]
    fn check_passes_when_all_three_guards_are_satisfied() {
        let result = check(&cfg(), 512, 1, "9XJSignerPubkeyBase58");
        assert!(result.is_ok(), "should pass: {result:?}");
    }

    #[test]
    fn check_passes_at_exact_size_limit() {
        // `<= limit` is allowed — boundary at exactly the cap.
        let result = check(&cfg(), 1024, 1, "9XJSignerPubkeyBase58");
        assert!(result.is_ok(), "should pass at limit: {result:?}");
    }

    #[test]
    fn check_passes_at_exact_instruction_limit() {
        // max_instructions = 1; exactly 1 is allowed.
        let result = check(&cfg(), 100, 1, "9XJSignerPubkeyBase58");
        assert!(result.is_ok(), "should pass at ix limit: {result:?}");
    }

    #[test]
    fn check_passes_with_zero_instructions_when_limit_allows_zero() {
        // Edge case: a tx with 0 instructions is structurally weird but not
        // the envelope guard's job to police — that's a semantic concern.
        // Empty-tx policy lives upstream (build-tx) if it ever matters.
        let mut loose = cfg();
        loose.max_instructions = 5;
        assert!(check(&loose, 100, 0, "9XJSignerPubkeyBase58").is_ok());
    }

    // ── guard 1: size ────────────────────────────────────────────────────────

    #[test]
    fn check_rejects_message_one_byte_over_size_limit() {
        let err = check(&cfg(), 1025, 1, "9XJSignerPubkeyBase58").expect_err("must reject");
        match err {
            EnvelopeError::TooLarge { actual, limit } => {
                assert_eq!(actual, 1025);
                assert_eq!(limit, 1024);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn check_rejects_message_far_over_size_limit_with_actual_value() {
        // The error must carry the actual byte count so the operator can
        // audit what landed (not just "<limit>").
        let err = check(&cfg(), 50_000, 1, "9XJSignerPubkeyBase58").expect_err("must reject");
        match err {
            EnvelopeError::TooLarge { actual, .. } => assert_eq!(actual, 50_000),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    // ── guard 2: instruction count ─────────────────────────────────────────

    #[test]
    fn check_rejects_composite_tx_when_limit_is_one() {
        // The canonical v0 case: agent smuggles a second instruction. The
        // envelope guard must catch it before reaching the backend.
        let err = check(&cfg(), 100, 2, "9XJSignerPubkeyBase58").expect_err("must reject");
        match err {
            EnvelopeError::TooManyInstructions { actual, limit } => {
                assert_eq!(actual, 2);
                assert_eq!(limit, 1);
                // The reason must mention v0 / single-instruction so the
                // operator knows this is a deliberate stance, not a bug.
                let msg = err.to_string();
                assert!(msg.contains("single-instruction"), "msg: {msg}");
            }
            other => panic!("expected TooManyInstructions, got {other:?}"),
        }
    }

    // ── guard 3: fee-payer match ───────────────────────────────────────────

    #[test]
    fn check_rejects_when_fee_payer_does_not_match_signer_pubkey() {
        // The classic prompt-injection signature: agent substitutes its own
        // fee_payer so it can drain gas from a different account, OR asks
        // the signer to pay for an account it does not control. Either way
        // the strings disagree — guard fires.
        let err = check(&cfg(), 100, 1, "AttackerPubkey").expect_err("must reject");
        match err {
            EnvelopeError::FeePayerMismatch { actual, expected } => {
                assert_eq!(actual, "AttackerPubkey");
                assert_eq!(expected, "9XJSignerPubkeyBase58");
            }
            other => panic!("expected FeePayerMismatch, got {other:?}"),
        }
    }

    #[test]
    fn check_rejects_empty_fee_payer_when_signer_pubkey_is_configured() {
        // Defensive: missing fee_payer (e.g. caller passed "" by mistake)
        // is caught by the string-compare against the operator-configured
        // pubkey.
        let err = check(&cfg(), 100, 1, "").expect_err("must reject");
        assert!(matches!(err, EnvelopeError::FeePayerMismatch { .. }));
    }

    #[test]
    fn check_treats_unconfigured_signer_pubkey_as_match_only_for_empty_actual() {
        // If the operator did NOT configure signer_pubkey (left it empty),
        // the only fee_payer the guard accepts is "" — which is itself a
        // sign of an unconfigured pipeline. This is intentionally loose:
        // the operator MUST configure signer_pubkey before going live; an
        // empty config + empty actual still passes the eq check.
        let mut loose = cfg();
        loose.signer_pubkey = String::new();
        assert!(check(&loose, 100, 1, "").is_ok());
        // But any non-empty fee_payer fails because it disagrees with "".
        let err = check(&loose, 100, 1, "Anyone").expect_err("must reject");
        assert!(matches!(err, EnvelopeError::FeePayerMismatch { .. }));
    }

    // ── guard ordering: cheapest-first ─────────────────────────────────────

    #[test]
    fn check_short_circuits_on_size_before_checking_ix_count() {
        // Two guards would fire (size + ix count). Size is cheaper, runs
        // first, returns its specific error.
        let err = check(&cfg(), 10_000, 50, "9XJSignerPubkeyBase58").expect_err("must reject");
        assert!(
            matches!(err, EnvelopeError::TooLarge { .. }),
            "size guard should fire first, got {err:?}"
        );
    }

    #[test]
    fn check_short_circuits_on_ix_count_before_fee_payer_match() {
        // Two guards would fire (ix count + fee_payer). Ix count is cheaper,
        // runs first.
        let err = check(&cfg(), 100, 50, "WrongPayer").expect_err("must reject");
        assert!(
            matches!(err, EnvelopeError::TooManyInstructions { .. }),
            "ix-count guard should fire before fee-payer, got {err:?}"
        );
    }

    // ── error rendering ────────────────────────────────────────────────────

    #[test]
    fn envelope_errors_render_human_readable_reasons() {
        let s = EnvelopeError::TooLarge {
            actual: 2048,
            limit: 1024,
        }
        .to_string();
        assert!(s.contains("2048") && s.contains("1024"), "msg: {s}");

        let s = EnvelopeError::TooManyInstructions {
            actual: 2,
            limit: 1,
        }
        .to_string();
        assert!(s.contains("v0 allows single-instruction"), "msg: {s}");

        let s = EnvelopeError::FeePayerMismatch {
            actual: "AttackerPubkey".into(),
            expected: "VaultPubkey".into(),
        }
        .to_string();
        assert!(
            s.contains("AttackerPubkey") && s.contains("VaultPubkey"),
            "msg: {s}"
        );
    }

    // ── defaults ────────────────────────────────────────────────────────────

    #[test]
    fn default_config_matches_bounty_spec() {
        let c = EnvelopeConfig::default();
        assert_eq!(c.max_message_bytes, 1024);
        assert_eq!(c.max_instructions, 1);
        assert!(c.signer_pubkey.is_empty(), "operator must configure this");
    }

    #[test]
    fn default_config_accepts_empty_fee_payer() {
        // Round-trips the unconfigured-pipeline case end-to-end: default
        // config + empty actual → check() returns Ok. Useful for tests that
        // want to drive the submit flow without setting up real config.
        let c = EnvelopeConfig::default();
        assert!(check(&c, 100, 1, "").is_ok());
    }
}
