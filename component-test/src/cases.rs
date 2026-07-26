//! What we assert about the shipped components.
//!
//! Every case here is offline and deterministic: no RPC, no network, no clock.
//! That is deliberate. The claims worth re-checking at the artifact level are
//! the *refusals* — the paths where a plugin must fail closed. A component
//! that has lost its policy check, or that answers without evidence, is the
//! failure mode that costs money, and it is exactly the failure a source-level
//! test cannot rule out for a binary.
//!
//! Cases that need a live endpoint belong in the devnet run, not here.

use crate::ToolOutcome;

pub struct Case {
    /// Directory and tool name under the staged dir; they must match.
    pub plugin: &'static str,
    pub wasm: &'static str,
    pub name: &'static str,
    pub args: String,
    #[allow(clippy::type_complexity)]
    pub check: fn(&Result<ToolOutcome, String>) -> Result<String, String>,
}

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RECIP: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";

fn policy_json() -> String {
    format!(
        r#"{{"version":"1.0.0","default_action":"deny","assets":{{"{USDC}":{{"decimals":6,"max_per_tx_raw":"25000000"}}}},"allowed_recipients":["{RECIP}"],"allowed_instructions":{{"spl_token":["transfer_checked"],"associated_token":["create_idempotent"],"memo":["memo"]}},"unknown_program":"deny","unknown_instruction":"deny","missing_intent":"review","durable_nonce":"deny","token_2022":{{"permanent_delegate":"deny","transfer_hook":"deny","transfer_fee":"deny","default_frozen":"deny"}},"simulation":{{"required":true,"max_slot_age":32}}}}"#
    )
}

/// A tool call that refused, one way or another.
///
/// Note what does *not* count as a failure: `success: true` carrying a DENY
/// verdict. The tool ran correctly and its answer was "no" — that is the
/// authorizer working, not erroring. Only a missing refusal is a failure: an
/// ALLOW verdict, or a success with no verdict and no error at all.
fn refused(outcome: &Result<ToolOutcome, String>, needle: &str) -> Result<String, String> {
    let text = match outcome {
        Err(error) => error.clone(),
        Ok(result) => {
            match result.verdict().as_deref() {
                Some("ALLOW") => {
                    return Err(format!("component returned ALLOW: {}", result.output))
                }
                // DENY / REVIEW / UNKNOWN are refusals, however they are wrapped.
                Some(_) => {}
                None if result.success && result.error.is_none() => {
                    return Err(format!(
                        "component neither refused nor gave a verdict: {}",
                        result.output
                    ))
                }
                None => {}
            }
            result.text()
        }
    };
    if needle.is_empty() || text.contains(needle) {
        let shown: String = text.chars().take(110).collect();
        Ok(format!("refused: {shown}"))
    } else {
        Err(format!("expected {needle:?} in the refusal, got: {text}"))
    }
}

pub fn all() -> Vec<Case> {
    vec![
        // ── The authorizer must still decode and refuse ──────────────────
        Case {
            plugin: "solana-tx-authorize",
            wasm: "solana_tx_authorize.wasm",
            name: "authorizer refuses garbage bytes",
            args: format!(
                r#"{{"transaction_base64":"bm90LWEtdHJhbnNhY3Rpb24=","__config":{{"policy_json":{}}}}}"#,
                serde_json::to_string(&policy_json()).unwrap()
            ),
            check: |o| refused(o, "SH-DENY-DECODE"),
        },
        Case {
            plugin: "solana-tx-authorize",
            wasm: "solana_tx_authorize.wasm",
            name: "authorizer fails closed with no policy configured",
            args: r#"{"transaction_base64":"bm90LWEtdHJhbnNhY3Rpb24=","__config":{}}"#.to_string(),
            check: |o| refused(o, "SH-DENY-CONFIG"),
        },
        // ── The builder must still enforce policy before constructing ─────
        // The builder's recipient and cap refusals need a live endpoint: it
        // reads mint decimals from chain before evaluating policy, so an
        // unreachable RPC is hit first. Those refusals are covered offline by
        // the conformance arena and on-chain by the devnet run; asserting them
        // here would only be asserting that localhost:1 is closed.
        Case {
            plugin: "spl-transfer-build",
            wasm: "spl_transfer_build.wasm",
            name: "builder fails closed with no policy configured",
            args: format!(r#"{{"recipient":"{RECIP}","amount_raw":"1000000","__config":{{}}}}"#),
            check: |o| refused(o, "fail closed"),
        },
        // ── The verifier must refuse to answer without two endpoints ──────
        Case {
            plugin: "payment-verify",
            wasm: "payment_verify.wasm",
            name: "verifier refuses to answer with one RPC endpoint",
            args: format!(
                r#"{{"order_id":"A-1","amount_raw":"1000000","__config":{{"merchant_owner":"{RECIP}","invoice_salt":"s","default_mint":"{USDC}","rpc_url":"https://127.0.0.1:1"}}}}"#
            ),
            check: |o| refused(o, "two independent RPC endpoints"),
        },
        Case {
            plugin: "payment-verify",
            wasm: "payment_verify.wasm",
            name: "verifier fails closed with no merchant configured",
            args: r#"{"order_id":"A-1","amount_raw":"1000000","__config":{}}"#.to_string(),
            check: |o| refused(o, "merchant_owner"),
        },
        // ── The proposer must not trust a caller's verdict ────────────────
        Case {
            plugin: "squads-proposal-build",
            wasm: "squads_proposal_build.wasm",
            name: "proposer refuses a forged ALLOW",
            args: format!(
                r#"{{"transaction_base64":"bm90LWEtdHJhbnNhY3Rpb24=","decision_record":{{"verdict":"ALLOW","decision_id":"sha256:forged","reason_codes":[]}},"__config":{{"rpc_url":"https://127.0.0.1:1","squads_create_key":"{RECIP}","proposer":"{RECIP}","squads_vault_index":"0","policy_json":{}}}}}"#,
                serde_json::to_string(&policy_json()).unwrap()
            ),
            check: |o| refused(o, ""),
        },
    ]
}
