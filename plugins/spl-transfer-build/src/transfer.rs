//! The transfer builder: args → validated unsigned transaction + matching intent.
//!
//! Pure logic, zero wasm dependency. The builder never signs and emits only a
//! canonical unsigned transaction that its own policy engine evaluates ALLOW.

use safe_hands_core::codec::{
    base64_decode, unsigned_transaction_base64, unsigned_transaction_bytes,
};
use safe_hands_core::crypto::{ata_address, parse_pubkey};
use safe_hands_core::decode::decode;
use safe_hands_core::ix;
use safe_hands_core::policy::{evaluate, policy_from_config, Intent, Verdict};
use safe_hands_core::rpc::{fetch_classic_mint_decimals, RpcTransport};
use safe_hands_core::{bincode, bs58, solana_hash::Hash, solana_message::Message};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct Args {
    recipient: String,
    amount_raw: String,
    #[serde(default)]
    mint: Option<String>,
    #[serde(default)]
    memo: Option<String>,
    #[serde(default)]
    token_program: Option<String>,
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
    let mut args: Args = match serde_json::from_str(args_json) {
        Ok(args) => args,
        Err(error) => return ExecuteOutput::err(format!("invalid arguments: {error}")),
    };

    // An omitted optional field and one the model filled with "" mean the same
    // thing: absent. Models routinely emit empty strings for optionals, and
    // treating "" as a value turns a well-formed request into a parse error
    // about a field the caller never meant to set.
    let blank = |value: &Option<String>| value.as_deref().is_some_and(|v| v.trim().is_empty());
    for field in [&mut args.mint, &mut args.memo, &mut args.token_program] {
        if blank(field) {
            *field = None;
        }
    }

    // Policy is a construction prerequisite, not a best-effort post-check.
    let policy = match policy_from_config(&args.config) {
        Ok(policy) => policy,
        Err(error) => {
            return ExecuteOutput::err(format!(
                "no valid spend policy is configured — fail closed ({error})"
            ))
        }
    };

    let classic_token_program = ix::spl_token_program();
    if let Some(configured) = &args.token_program {
        let configured = match parse_pubkey(configured) {
            Ok(program) => program,
            Err(error) => return ExecuteOutput::err(format!("invalid token_program: {error}")),
        };
        if configured != classic_token_program {
            return ExecuteOutput::err(
                "unsupported token_program: safe v0.1 supports only classic SPL Token (Tokenkeg...)"
            );
        }
    }

    let recipient = match parse_pubkey(&args.recipient) {
        Ok(recipient) => recipient,
        Err(error) => return ExecuteOutput::err(format!("invalid recipient: {error}")),
    };
    let amount = match args.amount_raw.trim().parse::<u64>() {
        Ok(amount) if amount > 0 => amount,
        _ => {
            return ExecuteOutput::err("amount_raw must be a positive integer (raw smallest units)")
        }
    };
    let fee_payer = match args.config.get("fee_payer") {
        Some(fee_payer) => match parse_pubkey(fee_payer) {
            Ok(fee_payer) => fee_payer,
            Err(error) => {
                return ExecuteOutput::err(format!(
                    "config fee_payer is not a valid pubkey: {error}"
                ))
            }
        },
        None => {
            return ExecuteOutput::err(
                "config key `fee_payer` is required (the wallet that pays and owns the source)",
            )
        }
    };
    if args.memo.as_ref().is_some_and(|memo| memo.len() > 566) {
        return ExecuteOutput::err("memo exceeds Solana's 566-byte memo bound");
    }
    let rpc = match transport {
        Some(rpc) => rpc,
        None => {
            return ExecuteOutput::err("no RPC transport available (rpc_url missing or not https)")
        }
    };

    let mut instructions = Vec::new();
    let mut destination_desc = args.recipient.clone();
    match &args.mint {
        None => instructions.push(ix::system_transfer(&fee_payer, &recipient, amount)),
        Some(mint_string) => {
            let mint = match parse_pubkey(mint_string) {
                Ok(mint) => mint,
                Err(error) => return ExecuteOutput::err(format!("invalid mint: {error}")),
            };
            let decimals = match fetch_classic_mint_decimals(rpc, mint_string) {
                Ok(decimals) => decimals,
                Err(error) => {
                    return ExecuteOutput::err(format!("could not read mint decimals: {error}"))
                }
            };
            let destination = ata_address(&recipient, &classic_token_program, &mint);
            let source = ata_address(&fee_payer, &classic_token_program, &mint);
            instructions.push(ix::ata_create_idempotent(
                &fee_payer,
                &destination,
                &recipient,
                &mint,
                &classic_token_program,
            ));
            instructions.push(ix::transfer_checked(
                &classic_token_program,
                &source,
                &mint,
                &destination,
                &fee_payer,
                amount,
                decimals,
            ));
            destination_desc = destination.to_string();
        }
    }
    if let Some(memo) = &args.memo {
        instructions.push(ix::memo(memo));
    }

    // Durable-nonce mode. A recent blockhash dies in roughly ninety seconds,
    // which is shorter than a human takes to approve a refund; when the
    // operator configures a nonce account, the transaction's validity is
    // pinned to the nonce instead and survives the approval queue.
    //
    // Both the account and the authority come from host config. AdvanceNonce
    // is unshiftably instruction 0 because it is inserted at the front here,
    // and `solana-tx-authorize` independently re-checks both that position and
    // the nonce allowlist on the exact bytes.
    // A config key present but empty means "not configured". Clearing a value
    // through a config UI commonly leaves "" behind, and treating that as an
    // address turns an unset option into a hard failure.
    let config_value = |key: &str| {
        args.config
            .get(key)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let nonce_account = config_value("nonce_account");
    let nonce_authority = config_value("nonce_authority");
    let (blockhash, durable) = match (nonce_account, nonce_authority) {
        (Some(account), Some(authority)) => {
            if let Err(error) = parse_pubkey(account).and_then(|_| parse_pubkey(authority)) {
                return ExecuteOutput::err(format!("invalid nonce configuration: {error}"));
            }
            let nonce = match safe_hands_core::rpc::fetch_durable_nonce(rpc, account, authority) {
                Ok(nonce) => nonce,
                Err(error) => {
                    return ExecuteOutput::err(format!("durable nonce unusable: {error}"))
                }
            };
            let hash = match bs58::decode(&nonce)
                .into_vec()
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            {
                Some(bytes) => Hash::new_from_array(bytes),
                None => return ExecuteOutput::err("durable nonce is not a 32-byte value"),
            };
            let (account, authority) = (
                parse_pubkey(account).expect("validated above"),
                parse_pubkey(authority).expect("validated above"),
            );
            instructions.insert(0, ix::advance_nonce(&account, &authority));
            (hash, true)
        }
        (None, None) => match fetch_blockhash(rpc) {
            Ok(blockhash) => (blockhash, false),
            Err(error) => {
                return ExecuteOutput::err(format!("could not fetch recent blockhash: {error}"))
            }
        },
        _ => {
            return ExecuteOutput::err(
                "durable-nonce mode needs both nonce_account and nonce_authority — configuring \
                 one without the other is ambiguous, so it fails closed",
            )
        }
    };
    let mut message = Message::new(&instructions, Some(&fee_payer));
    message.recent_blockhash = blockhash;
    let serialized_message = match bincode::serialize(&message) {
        Ok(bytes) => bytes,
        Err(error) => return ExecuteOutput::err(format!("serialize failed: {error}")),
    };
    let required_signatures = usize::from(message.header.num_required_signatures);
    let transaction_base64 =
        match unsigned_transaction_base64(&serialized_message, required_signatures) {
            Ok(encoded) => encoded,
            Err(error) => {
                return ExecuteOutput::err(format!("unsigned transaction assembly failed: {error}"))
            }
        };
    let transaction_bytes =
        match unsigned_transaction_bytes(&serialized_message, required_signatures) {
            Ok(bytes) => bytes,
            Err(error) => {
                return ExecuteOutput::err(format!("unsigned transaction assembly failed: {error}"))
            }
        };

    // Decode and authorize the exact final artifact, including signature slots.
    let decoded = match decode(&transaction_bytes) {
        Ok(decoded) => decoded,
        Err(error) => {
            return ExecuteOutput::err(format!(
                "builder produced a malformed canonical transaction: {error}"
            ))
        }
    };
    let intent = Intent {
        action: if args.mint.is_some() {
            "spl_transfer".into()
        } else {
            "transfer".into()
        },
        mint: args.mint.clone(),
        amount_raw: amount.to_string(),
        recipient: args.recipient.clone(),
        memo: args.memo.clone(),
    };
    let mut facts = decoded.facts.clone();
    facts.simulation_ok = true; // construction-time semantic self-check only
    facts.intent = Some(intent);
    // Under an effects-required policy the engine treats absent evidence as
    // UNKNOWN, which is correct — but this builder never gathered any, so it
    // refused every draft under such a policy. The transactions whose effects
    // matter most were therefore the ones that could never reach the human
    // Squads gate, which inverts the intended safety story.
    //
    // Observe them here, from the same RPC, on the same terms as
    // solana-tx-authorize: evidence that cannot be obtained stays absent, so
    // the engine still says UNKNOWN rather than reading silence as "nothing
    // moved".
    if policy
        .effects
        .as_ref()
        .is_some_and(|effects| effects.required)
    {
        let observed = safe_hands_core::effects::observe(rpc, &decoded).ok();
        if observed
            .as_ref()
            .is_some_and(|o| !o.authority_changed.is_empty())
        {
            facts.authority_change = true;
        }
        facts.effects = observed.map(|observed| observed.movements());
    }
    let report = evaluate(&policy, &facts);
    if report.verdict != Verdict::Allow {
        return ExecuteOutput::err(format!(
            "builder refused: policy returned {} ({})",
            report.verdict.as_str(),
            report.reason_codes.join(", ")
        ));
    }

    let asset = args.mint.clone().unwrap_or_else(|| "SOL".into());
    let human_summary = format!(
        "Send {amount} raw {asset} to {}.{} Unsigned — a human or the host signs.",
        short_key(&args.recipient),
        args.memo
            .as_ref()
            .map(|memo| format!(" Memo: \"{memo}\"."))
            .unwrap_or_default(),
    );

    // Defensive equality check ensures the two shared canonical helpers agree.
    if base64_decode(&transaction_base64, 4_096).ok().as_deref()
        != Some(transaction_bytes.as_slice())
    {
        return ExecuteOutput::err("canonical transaction encoding mismatch");
    }

    ExecuteOutput::ok(json!({
        "transaction_base64": transaction_base64,
        "intent": {
            "action": if args.mint.is_some() { "spl_transfer" } else { "transfer" },
            "mint": args.mint,
            "amount_raw": amount.to_string(),
            "recipient": args.recipient,
            "memo": args.memo,
        },
        "destination_account": destination_desc,
        "human_summary": human_summary,
        "unsigned": true,
        "durable_nonce": durable,
        "validity": if durable {
            "pinned to the configured nonce account — survives an approval queue until the nonce advances"
        } else {
            "bound to a recent blockhash — expires in roughly 90 seconds"
        },
    }))
}

fn short_key(key: &str) -> String {
    if key.len() > 8 {
        format!("{}…{}", &key[..4], &key[key.len() - 4..])
    } else {
        key.to_string()
    }
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
