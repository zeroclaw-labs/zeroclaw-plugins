//! The proposer: independently re-authorize, then build the Squads proposal.
//!
//! THE TRUST BOUNDARY. A caller (the agent) hands us a transaction and,
//! optionally, a prior "authorization decision". We never trust that record:
//! we load the operator policy from OUR OWN host-injected config, re-decode
//! the transaction, re-simulate it, and re-run the full deterministic policy
//! evaluation. Only if OUR evaluation says ALLOW do we build the proposal. A
//! caller-supplied ALLOW that disagrees with our evaluation is evidence of
//! tampering — reported as SH-TRUST-FORGED, never honored.
//!
//! Pure logic, zero wasm dependency — the component shim in `lib.rs` calls
//! [`run`] with a real transport; host tests call it with mocks.

use safe_hands_core::codec::{base64_decode, base64_encode};
use safe_hands_core::crypto::parse_pubkey;
use safe_hands_core::decode::decode;
use safe_hands_core::policy::{evaluate, policy_from_config, Intent, Verdict};
use safe_hands_core::rpc::RpcTransport;
use safe_hands_core::squads;
use safe_hands_core::{bincode, bs58, solana_hash::Hash, solana_message::Message, solana_pubkey};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Largest accepted base64 payload (1,232-byte tx + margin).
const MAX_B64_CHARS: usize = 2_048;

#[derive(Debug, Deserialize)]
struct Args {
    transaction_base64: String,
    #[serde(default)]
    intent: Option<Intent>,
    /// Optional prior decision record from solana-tx-authorize. Audited, never
    /// trusted: if it claims ALLOW while our own evaluation disagrees, that is
    /// tamper evidence (SH-TRUST-FORGED).
    #[serde(default)]
    decision_record: Option<Value>,
    #[serde(default)]
    memo: Option<String>,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

/// What the shim returns to the host: (success, output, error).
pub struct ExecuteOutput {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

impl ExecuteOutput {
    fn ok(value: Value) -> Self {
        Self {
            success: true,
            output: value.to_string(),
            error: None,
        }
    }
    fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            output: String::new(),
            error: Some(message.into()),
        }
    }
}

/// Run one proposal build. Required config keys:
/// - `squads_create_key`: the multisig's create_key (its PDA is derived here)
/// - `proposer`: the member pubkey that creates proposals (Initiate-only is
///   the recommended role — it cannot approve or execute)
/// - `rpc_url`, `policy_json` — same contract as the authorizer
/// Optional: `squads_vault_index` (default 0).
pub fn run(args_json: &str, transport: Option<&dyn RpcTransport>) -> ExecuteOutput {
    let args: Args = match serde_json::from_str(args_json) {
        Ok(a) => a,
        Err(e) => return ExecuteOutput::err(format!("invalid arguments: {e}")),
    };

    // --- 0. Config -------------------------------------------------------
    let policy = match policy_from_config(&args.config) {
        Ok(p) => p,
        Err(e) => {
            return ExecuteOutput::err(format!("no spend policy is configured — fail closed ({e})"))
        }
    };
    let create_key = match args.config.get("squads_create_key") {
        Some(k) => match parse_pubkey(k) {
            Ok(k) => k,
            Err(e) => return ExecuteOutput::err(format!("config squads_create_key invalid: {e}")),
        },
        None => return ExecuteOutput::err("config key `squads_create_key` is required"),
    };
    let proposer = match args.config.get("proposer") {
        Some(k) => match parse_pubkey(k) {
            Ok(k) => k,
            Err(e) => return ExecuteOutput::err(format!("config proposer invalid: {e}")),
        },
        None => return ExecuteOutput::err("config key `proposer` is required"),
    };
    let vault_index: u8 = args
        .config
        .get("squads_vault_index")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let rpc = match transport {
        Some(t) => t,
        None => {
            return ExecuteOutput::err("no RPC transport available (rpc_url missing or not https)")
        }
    };

    // --- 1. Independent re-authorization (we NEVER trust the caller) -----
    let tx_b64 = args.transaction_base64.trim();
    let tx_bytes = match base64_decode(tx_b64, MAX_B64_CHARS) {
        Ok(b) => b,
        Err(e) => return ExecuteOutput::err(format!("transaction_base64 invalid: {e}")),
    };
    let decoded = match decode(&tx_bytes) {
        Ok(d) => d,
        Err(e) => {
            return ExecuteOutput::err(format!(
                "transaction could not be decoded — refuse to propose ({e})"
            ))
        }
    };

    let mut facts = decoded.facts.clone();
    facts.intent = args.intent.clone();
    facts.simulation_ok = match simulate(rpc, tx_b64) {
        SimOutcome::Ok => true,
        SimOutcome::Failed => false,
        SimOutcome::Unavailable => {
            return ExecuteOutput::err(
                "simulation unavailable — refuse to propose without evidence (fail closed)",
            )
        }
    };
    let report = evaluate(&policy, &facts);

    // --- 2. The forge test: caller's record vs our evaluation ------------
    if let Some(record) = &args.decision_record {
        let caller_verdict = record
            .get("verdict")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_uppercase();
        if caller_verdict == "ALLOW" && report.verdict != Verdict::Allow {
            return ExecuteOutput::err(format!(
                "SH-TRUST-FORGED: caller-provided verdict is not trusted. The supplied decision record claims ALLOW, but independent re-evaluation returned {} ({}). No proposal constructed.",
                report.verdict.as_str(),
                report.reason_codes.join(", ")
            ));
        }
    }
    if report.verdict != Verdict::Allow {
        return ExecuteOutput::err(format!(
            "independent re-evaluation returned {} ({}) — refuse to construct a proposal",
            report.verdict.as_str(),
            report.reason_codes.join(", ")
        ));
    }

    // --- 3. Multisig state -----------------------------------------------
    let multisig = squads::multisig_pda(&create_key);
    let info = match fetch_multisig(rpc, &multisig) {
        Ok(i) => i,
        Err(e) => return ExecuteOutput::err(format!("could not load multisig account: {e}")),
    };
    let new_index = info.transaction_index + 1;
    let transaction_pda = squads::transaction_pda(&multisig, new_index);
    let proposal_pda = squads::proposal_pda(&multisig, new_index);
    let vault = squads::vault_pda(&multisig, vault_index);

    // --- 4. Recompile the inner message with the vault as fee payer ------
    let blockhash = match fetch_blockhash(rpc) {
        Ok(h) => h,
        Err(e) => return ExecuteOutput::err(format!("could not fetch recent blockhash: {e}")),
    };
    let mut inner = Message::new(&decoded.raw_instructions, Some(&vault));
    inner.recent_blockhash = blockhash;
    let inner_bytes = match bincode::serialize(&inner) {
        Ok(b) => b,
        Err(e) => return ExecuteOutput::err(format!("inner message serialize failed: {e}")),
    };

    // --- 5. Build the proposal transaction (unsigned, proposer pays) -----
    let ixs = vec![
        squads::vault_transaction_create(
            &multisig,
            &transaction_pda,
            &proposer,
            &proposer,
            vault_index,
            0,
            &inner_bytes,
            args.memo.as_deref(),
        ),
        squads::proposal_create(
            &multisig,
            &proposal_pda,
            &proposer,
            &proposer,
            new_index,
            false,
        ),
    ];
    let mut proposal_msg = Message::new(&ixs, Some(&proposer));
    proposal_msg.recent_blockhash = blockhash;
    let proposal_bytes = match bincode::serialize(&proposal_msg) {
        Ok(b) => b,
        Err(e) => return ExecuteOutput::err(format!("proposal serialize failed: {e}")),
    };

    ExecuteOutput::ok(json!({
        "transaction_base64": base64_encode(&proposal_bytes),
        "multisig": multisig.to_string(),
        "vault": vault.to_string(),
        "transaction_index": new_index,
        "transaction_pda": transaction_pda.to_string(),
        "proposal_pda": proposal_pda.to_string(),
        "human_summary": format!(
            "Squads proposal #{new_index} created (unsigned). A proposer-signed submission creates it on-chain; {}-of-N members then approve from their wallets. The agent holds no keys and cannot approve.",
            info.threshold
        ),
        "unsigned": true,
        "re_authorization": {
            "verdict": "ALLOW",
            "caller_verdict_trusted": false,
            "note": "independently re-evaluated from operator config before proposal construction",
        },
    }))
}

enum SimOutcome {
    Ok,
    Failed,
    Unavailable,
}

fn simulate(rpc: &dyn RpcTransport, tx_b64: &str) -> SimOutcome {
    let params = json!([
        tx_b64,
        {"encoding": "base64", "sigVerify": false, "replaceRecentBlockhash": true}
    ]);
    match rpc.call("simulateTransaction", params) {
        Ok(resp) => match resp.pointer("/result/value/err") {
            Some(Value::Null) | None => SimOutcome::Ok,
            _ => SimOutcome::Failed,
        },
        Err(_) => SimOutcome::Unavailable,
    }
}

fn fetch_multisig(
    rpc: &dyn RpcTransport,
    multisig: &solana_pubkey::Pubkey,
) -> Result<squads::MultisigInfo, String> {
    let resp = rpc.call(
        "getAccountInfo",
        json!([multisig.to_string(), {"encoding": "base64"}]),
    )?;
    let data = resp
        .pointer("/result/value/data/0")
        .and_then(Value::as_str)
        .ok_or("multisig account not found — is squads_create_key correct for this cluster?")?;
    let bytes = base64_decode(data, 65_536)?;
    squads::parse_multisig_account(&bytes)
}

fn fetch_blockhash(rpc: &dyn RpcTransport) -> Result<Hash, String> {
    let resp = rpc.call("getLatestBlockhash", json!([]))?;
    let b58 = resp
        .pointer("/result/value/blockhash")
        .and_then(Value::as_str)
        .ok_or("no blockhash in response")?;
    let bytes = bs58::decode(b58)
        .into_vec()
        .map_err(|e| format!("bad blockhash: {e}"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "blockhash not 32 bytes")?;
    Ok(Hash::new_from_array(arr))
}

#[cfg(test)]
mod tests;
