//! Independently authorize a vault-native draft, then build a Squads proposal.
//!
//! Caller verdicts are never trusted. Only an independently derived ALLOW can
//! produce a canonical unsigned proposal transaction.

use safe_hands_core::codec::{
    base64_decode, unsigned_transaction_base64, unsigned_transaction_bytes,
};
use safe_hands_core::crypto::parse_pubkey;
use safe_hands_core::decode::{decode, DecodedTx};
use safe_hands_core::policy::{evaluate, policy_from_config, Intent, Verdict};
use safe_hands_core::rpc::{
    simulate_strict, verify_classic_transfer_mints, RpcTransport, SimulationOutcome,
};
use safe_hands_core::squads;
use safe_hands_core::{bincode, bs58, solana_hash::Hash, solana_message::Message, solana_pubkey};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

const MAX_B64_CHARS: usize = 2_048;

#[derive(Debug, Deserialize)]
struct Args {
    transaction_base64: String,
    #[serde(default)]
    intent: Option<Intent>,
    #[serde(default)]
    decision_record: Option<Value>,
    #[serde(default)]
    memo: Option<String>,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

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

pub fn run(args_json: &str, transport: Option<&dyn RpcTransport>) -> ExecuteOutput {
    let args: Args = match serde_json::from_str(args_json) {
        Ok(args) => args,
        Err(error) => return ExecuteOutput::err(format!("invalid arguments: {error}")),
    };
    let policy = match policy_from_config(&args.config) {
        Ok(policy) => policy,
        Err(error) => {
            return ExecuteOutput::err(format!(
                "no spend policy is configured — fail closed ({error})"
            ))
        }
    };
    let create_key = match args.config.get("squads_create_key") {
        Some(key) => match parse_pubkey(key) {
            Ok(key) => key,
            Err(error) => {
                return ExecuteOutput::err(format!("config squads_create_key invalid: {error}"))
            }
        },
        None => return ExecuteOutput::err("config key `squads_create_key` is required"),
    };
    let proposer = match args.config.get("proposer") {
        Some(key) => match parse_pubkey(key) {
            Ok(key) => key,
            Err(error) => return ExecuteOutput::err(format!("config proposer invalid: {error}")),
        },
        None => return ExecuteOutput::err("config key `proposer` is required"),
    };
    let vault_index = match args.config.get("squads_vault_index") {
        Some(index) => match index.parse::<u8>() {
            Ok(index) => index,
            Err(_) => return ExecuteOutput::err("config squads_vault_index must be a u8"),
        },
        None => 0,
    };
    let rpc = match transport {
        Some(rpc) => rpc,
        None => {
            return ExecuteOutput::err("no RPC transport available (rpc_url missing or not https)")
        }
    };

    // Custody boundary: derive the only permitted signer before authorization.
    let (multisig, multisig_bump) = squads::multisig_pda_with_bump(&create_key);
    let vault = squads::vault_pda(&multisig, vault_index);

    let transaction_bytes = match base64_decode(args.transaction_base64.trim(), MAX_B64_CHARS) {
        Ok(bytes) => bytes,
        Err(error) => return ExecuteOutput::err(format!("transaction_base64 invalid: {error}")),
    };
    let decoded = match decode(&transaction_bytes) {
        Ok(decoded) => decoded,
        Err(error) => {
            return ExecuteOutput::err(format!(
                "transaction could not be decoded — refuse to propose ({error})"
            ))
        }
    };
    if let Err(error) = validate_vault_native_draft(&decoded, &vault, &transaction_bytes) {
        return ExecuteOutput::err(format!("draft is not vault-native: {error}"));
    }

    if let Err(error) = verify_classic_transfer_mints(rpc, &decoded) {
        return ExecuteOutput::err(format!(
            "SH-UNKNOWN-MINT-EVIDENCE-053: classic mint evidence unavailable, malformed, or inconsistent with TransferChecked: {error}"
        ));
    }

    let mut facts = decoded.facts.clone();
    facts.intent = args.intent.clone();
    facts.simulation_ok = match simulate_strict(rpc, &decoded, policy.simulation.max_slot_age) {
        SimulationOutcome::Ok { .. } => true,
        SimulationOutcome::Failed { reason } => {
            return ExecuteOutput::err(format!(
                "simulation failed — refuse to propose (fail closed): {reason}"
            ))
        }
        SimulationOutcome::Stale {
            simulation_slot,
            current_slot,
        } => {
            return ExecuteOutput::err(format!(
                "simulation evidence is stale ({simulation_slot} vs {current_slot}) — refuse to propose"
            ))
        }
        SimulationOutcome::Unavailable { reason } => {
            return ExecuteOutput::err(format!(
                "simulation unavailable — refuse to propose without evidence (fail closed): {reason}"
            ))
        }
    };
    let report = evaluate(&policy, &facts);

    if let Some(record) = &args.decision_record {
        let caller_verdict = record
            .get("verdict")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_uppercase();
        let independent_verdict = report.verdict.as_str();
        if caller_verdict != independent_verdict {
            let code = if caller_verdict == "ALLOW" && report.verdict != Verdict::Allow {
                "SH-TRUST-FORGED"
            } else {
                "SH-TRUST-MISMATCH"
            };
            return ExecuteOutput::err(format!(
                "{code}: caller-provided verdict is audit context only and must match independent re-evaluation. The supplied decision record says {}, but independent re-evaluation returned {} ({}). No proposal constructed.",
                if caller_verdict.is_empty() {
                    "MISSING_OR_MALFORMED"
                } else {
                    caller_verdict.as_str()
                },
                independent_verdict,
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

    let info = match fetch_multisig(rpc, &multisig) {
        Ok(info) => info,
        Err(error) => {
            return ExecuteOutput::err(format!("could not load multisig account: {error}"))
        }
    };
    if info.create_key != create_key {
        return ExecuteOutput::err(
            "could not load multisig account: account create_key does not match configuration",
        );
    }
    if squads::multisig_pda(&info.create_key) != multisig {
        return ExecuteOutput::err(
            "could not load multisig account: account create_key does not derive requested multisig PDA",
        );
    }
    if info.bump != multisig_bump {
        return ExecuteOutput::err(format!(
            "could not load multisig account: account bump {} does not match canonical PDA bump {multisig_bump}",
            info.bump
        ));
    }
    if info.stale_transaction_index > info.transaction_index {
        return ExecuteOutput::err(
            "could not load multisig account: stale_transaction_index exceeds transaction_index",
        );
    }
    // A Controlled multisig has a config_authority that can add members, change
    // the threshold and rotate the config authority itself — no vote, no
    // proposal. On such a multisig the Initiate-only check below proves
    // nothing: whoever holds that authority can grant themselves Vote and
    // Execute and then approve their own proposal.
    //
    // Safe Hands claims the agent can propose and can never approve. That claim
    // is only true on an Autonomous multisig, so refuse rather than emit a
    // proposal under a guarantee that does not hold.
    if info.config_authority != solana_pubkey::Pubkey::default() {
        return ExecuteOutput::err(
            "multisig is Controlled: its config_authority can add members and change the              threshold without a vote, so an Initiate-only proposer is not a guarantee that              the agent cannot approve. Use an Autonomous multisig (config_authority unset).",
        );
    }

    let proposer_member = info.members.iter().find(|member| member.key == proposer);
    match proposer_member {
        Some(member) if member.permissions == 1 => {}
        Some(member) => {
            return ExecuteOutput::err(format!(
                "configured proposer must have exactly Initiate permission (mask 1), got {}",
                member.permissions
            ))
        }
        None => {
            return ExecuteOutput::err("configured proposer is not a member of the Squads multisig")
        }
    }
    let transaction_index = match info.transaction_index.checked_add(1) {
        Some(index) => index,
        None => return ExecuteOutput::err("multisig transaction_index overflow"),
    };
    let transaction_pda = squads::transaction_pda(&multisig, transaction_index);
    let proposal_pda = squads::proposal_pda(&multisig, transaction_index);

    // Exact-artifact boundary: compile the decoded instructions unchanged.
    let inner_bytes = match squads::compile_inner_message(&decoded.raw_instructions, &vault) {
        Ok(bytes) => bytes,
        Err(error) => {
            return ExecuteOutput::err(format!("could not compile exact inner message: {error}"))
        }
    };

    let blockhash = match fetch_blockhash(rpc) {
        Ok(blockhash) => blockhash,
        Err(error) => {
            return ExecuteOutput::err(format!("could not fetch recent blockhash: {error}"))
        }
    };
    let instructions = vec![
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
            transaction_index,
            false,
        ),
    ];
    let mut proposal_message = Message::new(&instructions, Some(&proposer));
    proposal_message.recent_blockhash = blockhash;
    let serialized_message = match bincode::serialize(&proposal_message) {
        Ok(bytes) => bytes,
        Err(error) => return ExecuteOutput::err(format!("proposal serialize failed: {error}")),
    };
    let required_signatures = usize::from(proposal_message.header.num_required_signatures);
    let proposal_bytes = match unsigned_transaction_bytes(&serialized_message, required_signatures)
    {
        Ok(bytes) => bytes,
        Err(error) => {
            return ExecuteOutput::err(format!("proposal transaction assembly failed: {error}"))
        }
    };
    let proposal_base64 =
        match unsigned_transaction_base64(&serialized_message, required_signatures) {
            Ok(encoded) => encoded,
            Err(error) => {
                return ExecuteOutput::err(format!("proposal transaction assembly failed: {error}"))
            }
        };
    if base64_decode(&proposal_base64, 65_536).ok().as_deref() != Some(proposal_bytes.as_slice()) {
        return ExecuteOutput::err("canonical proposal transaction encoding mismatch");
    }

    ExecuteOutput::ok(json!({
        "transaction_base64": proposal_base64,
        "multisig": multisig.to_string(),
        "vault": vault.to_string(),
        "transaction_index": transaction_index,
        "transaction_pda": transaction_pda.to_string(),
        "proposal_pda": proposal_pda.to_string(),
        "human_summary": format!(
            "Squads proposal #{transaction_index} created (unsigned). A proposer-signed submission creates it on-chain; {}-of-N members then approve from their wallets. The agent holds no keys and cannot approve.",
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

fn validate_vault_native_draft(
    decoded: &DecodedTx,
    vault: &solana_pubkey::Pubkey,
    transaction_bytes: &[u8],
) -> Result<(), String> {
    if !decoded.has_signature_array {
        return Err(
            "bare message input is not accepted; canonical full transaction required".to_string(),
        );
    }
    if decoded.facts.signed {
        return Err("signed input is not accepted".to_string());
    }
    let canonical =
        unsigned_transaction_bytes(&decoded.serialized_message, decoded.required_signatures)?;
    if transaction_bytes != canonical {
        return Err(
            "input is not the exact canonical zero-signature full transaction artifact".to_string(),
        );
    }
    if decoded.required_signatures != 1 {
        return Err(format!(
            "exactly one required signer is required, got {}",
            decoded.required_signatures
        ));
    }
    if decoded.resolved_keys.first().map(String::as_str) != Some(vault.to_string().as_str()) {
        return Err("the first static signer key is not the derived vault".to_string());
    }
    let signer_metas: Vec<_> = decoded
        .raw_instructions
        .iter()
        .flat_map(|instruction| instruction.accounts.iter())
        .filter(|account| account.is_signer)
        .collect();
    if signer_metas.is_empty() {
        return Err("the derived vault is not used as an instruction signer".to_string());
    }
    if signer_metas.iter().any(|account| account.pubkey != *vault) {
        return Err("every signer meta must be exactly the derived vault".to_string());
    }
    Ok(())
}

fn fetch_multisig(
    rpc: &dyn RpcTransport,
    multisig: &solana_pubkey::Pubkey,
) -> Result<squads::MultisigInfo, String> {
    let response = rpc.call(
        "getAccountInfo",
        json!([multisig.to_string(), {"encoding": "base64"}]),
    )?;
    reject_rpc_error(&response, "getAccountInfo")?;
    let value = response
        .pointer("/result/value")
        .ok_or("getAccountInfo missing or null result.value")?;
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("multisig account owner missing or malformed")?;
    if owner != squads::SQUADS_PROGRAM {
        return Err(format!(
            "multisig account owner must be {}, got {owner}",
            squads::SQUADS_PROGRAM
        ));
    }
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or("multisig account data missing or malformed")?;
    if data.len() != 2 || data[1].as_str() != Some("base64") {
        return Err("multisig account data must be an exact [base64, \"base64\"] tuple".into());
    }
    let encoded = data[0]
        .as_str()
        .ok_or("multisig account base64 payload missing or malformed")?;
    squads::parse_multisig_account(&base64_decode(encoded, 65_536)?)
}

fn fetch_blockhash(rpc: &dyn RpcTransport) -> Result<Hash, String> {
    let response = rpc.call("getLatestBlockhash", json!([]))?;
    reject_rpc_error(&response, "getLatestBlockhash")?;
    let encoded = response
        .pointer("/result/value/blockhash")
        .and_then(Value::as_str)
        .ok_or("no blockhash in response")?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|error| format!("bad blockhash: {error}"))?;
    let hash: [u8; 32] = bytes.try_into().map_err(|_| "blockhash not 32 bytes")?;
    Ok(Hash::new_from_array(hash))
}

fn reject_rpc_error(response: &Value, method: &str) -> Result<(), String> {
    if let Some(error) = response.get("error").filter(|error| !error.is_null()) {
        Err(format!("{method} JSON-RPC error: {error}"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
