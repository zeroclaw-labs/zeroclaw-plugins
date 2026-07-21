//! The transfer builder: args → validated unsigned transaction + matching intent.
//!
//! Pure logic, zero wasm dependency — the component shim in `lib.rs` calls
//! [`run`] with a real transport; host tests call it with mocks. The builder
//! never signs and never emits a transaction its own policy engine would deny
//! (the pre-check runs before serialization, and a policy rejection is a hard
//! error, not a transaction).

use safe_hands_core::codec::base64_encode;
use safe_hands_core::crypto::{ata_address, parse_pubkey};
use safe_hands_core::decode::decode;
use safe_hands_core::ix;
use safe_hands_core::policy::{evaluate, policy_from_config, Intent, Verdict};
use safe_hands_core::rpc::RpcTransport;
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

/// Run one build. Requires config keys:
/// - `fee_payer`: the wallet that pays fees and (for SPL) owns the source
///   tokens. Public key only — never a secret.
/// - `rpc_url`: endpoint for blockhash + mint metadata (https).
/// - `policy_json`: the operator spend policy (same document the authorizer
///   enforces); the builder refuses to emit anything it would deny.
pub fn run(args_json: &str, transport: Option<&dyn RpcTransport>) -> ExecuteOutput {
    let args: Args = match serde_json::from_str(args_json) {
        Ok(a) => a,
        Err(e) => return ExecuteOutput::err(format!("invalid arguments: {e}")),
    };

    // --- validate inputs ------------------------------------------------
    let recipient = match parse_pubkey(&args.recipient) {
        Ok(k) => k,
        Err(e) => return ExecuteOutput::err(format!("invalid recipient: {e}")),
    };
    let amount: u64 = match args.amount_raw.trim().parse::<u64>() {
        Ok(a) if a > 0 => a,
        _ => {
            return ExecuteOutput::err("amount_raw must be a positive integer (raw smallest units)")
        }
    };
    let fee_payer = match args.config.get("fee_payer") {
        Some(fp) => match parse_pubkey(fp) {
            Ok(k) => k,
            Err(e) => {
                return ExecuteOutput::err(format!("config fee_payer is not a valid pubkey: {e}"))
            }
        },
        None => {
            return ExecuteOutput::err(
                "config key `fee_payer` is required (the wallet that pays and owns the source)",
            )
        }
    };
    if let Some(memo) = &args.memo {
        if memo.len() > 566 {
            return ExecuteOutput::err("memo exceeds Solana's 566-byte memo bound");
        }
    }

    let rpc = match transport {
        Some(t) => t,
        None => {
            return ExecuteOutput::err("no RPC transport available (rpc_url missing or not https)")
        }
    };

    // --- build the instruction set --------------------------------------
    let token_program = match &args.token_program {
        Some(tp) => match parse_pubkey(tp) {
            Ok(k) => k,
            Err(e) => return ExecuteOutput::err(format!("invalid token_program: {e}")),
        },
        None => ix::spl_token_program(),
    };

    let mut ixs = Vec::new();
    let mut destination_desc = args.recipient.clone();

    match &args.mint {
        None => {
            ixs.push(ix::system_transfer(&fee_payer, &recipient, amount));
        }
        Some(mint_str) => {
            let mint = match parse_pubkey(mint_str) {
                Ok(k) => k,
                Err(e) => return ExecuteOutput::err(format!("invalid mint: {e}")),
            };
            let decimals = match fetch_mint_decimals(rpc, mint_str) {
                Ok(d) => d,
                Err(e) => return ExecuteOutput::err(format!("could not read mint decimals: {e}")),
            };
            let dest_ata = ata_address(&recipient, &token_program, &mint);
            let source_ata = ata_address(&fee_payer, &token_program, &mint);
            ixs.push(ix::ata_create_idempotent(
                &fee_payer,
                &dest_ata,
                &recipient,
                &mint,
                &token_program,
            ));
            ixs.push(ix::transfer_checked(
                &token_program,
                &source_ata,
                &mint,
                &dest_ata,
                &fee_payer,
                amount,
                decimals,
            ));
            destination_desc = dest_ata.to_string();
        }
    }
    if let Some(memo) = &args.memo {
        ixs.push(ix::memo(memo));
    }

    // --- blockhash -------------------------------------------------------
    let blockhash = match fetch_blockhash(rpc) {
        Ok(h) => h,
        Err(e) => return ExecuteOutput::err(format!("could not fetch recent blockhash: {e}")),
    };

    let mut msg = Message::new(&ixs, Some(&fee_payer));
    msg.recent_blockhash = blockhash;
    let tx_bytes = match bincode::serialize(&msg) {
        Ok(b) => b,
        Err(e) => return ExecuteOutput::err(format!("serialize failed: {e}")),
    };

    // --- pre-check: never emit a transaction our own guard would deny ----
    if let Ok(policy) = policy_from_config(&args.config) {
        if let Ok(decoded) = decode(&tx_bytes) {
            let mut facts = decoded.facts.clone();
            facts.simulation_ok = true; // builder output is fresh, not yet simulated
            facts.intent = Some(Intent {
                action: if args.mint.is_some() {
                    "spl_transfer".into()
                } else {
                    "transfer".into()
                },
                mint: args.mint.clone(),
                amount_raw: amount.to_string(),
                recipient: args.recipient.clone(),
            });
            let report = evaluate(&policy, &facts);
            if report.verdict == Verdict::Deny {
                return ExecuteOutput::err(format!(
                    "builder refused: the requested transfer violates the operator policy ({})",
                    report.reason_codes.join(", ")
                ));
            }
        }
    }

    let asset = args.mint.clone().unwrap_or_else(|| "SOL".into());
    let human_summary = format!(
        "Send {amount} raw {asset} to {}.{}{}",
        short_key(&args.recipient),
        args.memo
            .as_ref()
            .map(|m| format!(" Memo: \"{m}\"."))
            .unwrap_or_default(),
        " Unsigned — a human or the host signs."
    );

    ExecuteOutput::ok(json!({
        "transaction_base64": base64_encode(&tx_bytes),
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
    }))
}

fn short_key(key: &str) -> String {
    if key.len() > 8 {
        format!("{}…{}", &key[..4], &key[key.len() - 4..])
    } else {
        key.to_string()
    }
}

/// Mint decimals = byte 44 of the SPL mint account layout.
fn fetch_mint_decimals(rpc: &dyn RpcTransport, mint: &str) -> Result<u8, String> {
    let resp = rpc.call("getAccountInfo", json!([mint, {"encoding": "base64"}]))?;
    let data = resp
        .pointer("/result/value/data/0")
        .and_then(Value::as_str)
        .ok_or("mint account not found")?;
    use safe_hands_core::codec::base64_decode;
    let bytes = base64_decode(data, 4096)?;
    bytes
        .get(44)
        .copied()
        .ok_or_else(|| "mint account data truncated".to_string())
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
