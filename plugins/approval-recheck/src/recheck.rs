//! Pure logic for `approval-recheck`.
//!
//! The gap between "the agent built this transaction" and "the human signed
//! it" is where agent-payment risk actually lives: state drifts, nonces get
//! consumed, and a chat transcript can claim anything about what a base64
//! blob does. This tool closes the gap from the chain's side of the table:
//! it decodes the pending bytes, re-fetches the accounts they touch, and
//! returns a verdict plus a plain-language account of what a signature would
//! authorize. Read-only; custody tier T0; holds nothing.

use std::collections::HashMap;

use aval_core::amount::{format_amount, LAMPORTS_PER_SOL_DECIMALS};
use aval_core::codec::b64_decode;
use aval_core::message::{parse_transaction, ParsedMessage};
use aval_core::nonce::parse_nonce_account;
use aval_core::pubkey::{
    ata_program, memo_program, system_program, token_2022_program, token_program, Pubkey,
};
use aval_core::rpc::{parse_token_account_amount, HttpPost, Rpc};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RecheckArgs {
    /// The pending unsigned transaction, base64.
    pub transaction_base64: String,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    /// Nonce fresh, balances hold, every instruction decoded cleanly:
    /// signing now lands exactly this. READY is only ever warning-free.
    Ready,
    /// Chain state holds, but the transaction contains something this tool
    /// could not fully explain (an unrecognized instruction, an authority
    /// mismatch). A human must read the warnings before signing.
    ReviewRequired,
    /// The durable nonce was consumed; the transaction can never land.
    Consumed,
    /// State moved underneath the transaction (balance below requirements).
    Drifted,
    /// Not anchored to a durable nonce; probably already expired.
    NotDurable,
    /// Structurally unusable (nonce account missing or invalid).
    Broken,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Ready => "READY",
            Verdict::ReviewRequired => "REVIEW_REQUIRED",
            Verdict::Consumed => "CONSUMED",
            Verdict::Drifted => "DRIFTED",
            Verdict::NotDurable => "NOT_DURABLE",
            Verdict::Broken => "BROKEN",
        }
    }
}

#[derive(Debug)]
pub struct RecheckReport {
    pub verdict: Verdict,
    /// One-line verdict explanation.
    pub headline: String,
    /// What a signature would authorize, decoded from bytes — never from the
    /// conversation.
    pub actions: Vec<String>,
    pub warnings: Vec<String>,
}

const ESTIMATED_FEE_LAMPORTS: u64 = 5_000;

pub fn recheck<H: HttpPost>(http: &H, args: &RecheckArgs) -> Result<RecheckReport, String> {
    let rpc_url = args
        .config
        .get("rpc_url")
        .cloned()
        .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
    let rpc = Rpc::new(http, &rpc_url);

    let bytes = b64_decode(args.transaction_base64.trim())?;
    let msg = parse_transaction(&bytes)?;

    let mut actions = Vec::new();
    let mut warnings = Vec::new();

    // 1. Durability: the first instruction must advance a nonce.
    let first = msg
        .instructions
        .first()
        .ok_or("transaction contains no instructions")?;
    let is_advance = first.program == system_program() && first.data == [4, 0, 0, 0];
    if !is_advance {
        decode_actions(&msg, &mut actions, &mut warnings);
        return Ok(RecheckReport {
            verdict: Verdict::NotDurable,
            headline: "Not anchored to a durable nonce — a recent-blockhash transaction \
                       this old has almost certainly expired. Rebuild it with durable_tx_build."
                .into(),
            actions,
            warnings,
        });
    }
    let nonce_account = *msg
        .account(first, 0)
        .ok_or("advance-nonce instruction is malformed")?;
    let nonce_authority = msg.account(first, 2).copied();

    // 2. Nonce freshness, from the chain right now.
    let Some(acct) = rpc.get_account(&nonce_account)? else {
        return Ok(RecheckReport {
            verdict: Verdict::Broken,
            headline: format!(
                "Nonce account {} no longer exists; this transaction can never land.",
                nonce_account.short()
            ),
            actions,
            warnings,
        });
    };
    let state = match parse_nonce_account(&acct.data) {
        Ok(s) => s,
        Err(e) => {
            return Ok(RecheckReport {
                verdict: Verdict::Broken,
                headline: format!("Nonce account {} is unusable: {e}", nonce_account.short()),
                actions,
                warnings,
            })
        }
    };
    if state.blockhash != msg.recent_blockhash {
        decode_actions(&msg, &mut actions, &mut warnings);
        return Ok(RecheckReport {
            verdict: Verdict::Consumed,
            headline: "The durable nonce has moved since this transaction was built — \
                       something else already consumed it. Signing is harmless but futile; \
                       rebuild with durable_tx_build."
                .into(),
            actions,
            warnings,
        });
    }
    if let Some(auth) = nonce_authority {
        if state.authority != auth {
            warnings.push(format!(
                "nonce authority on-chain ({}) differs from the transaction's signer ({})",
                state.authority.short(),
                auth.short()
            ));
        }
    }

    // 3. Decode what a signature would authorize.
    let sol_outflow = decode_actions(&msg, &mut actions, &mut warnings);

    // 4. Drift: does the fee payer still cover SOL outflow + fee, and do the
    // token sources still hold their amounts?
    let fee_payer = msg.account_keys[0];
    let balance = rpc.get_balance(&fee_payer)?;
    let needed = sol_outflow.saturating_add(ESTIMATED_FEE_LAMPORTS);
    if balance < needed {
        return Ok(RecheckReport {
            verdict: Verdict::Drifted,
            headline: format!(
                "Signer {} now holds {} SOL but this transaction needs about {} SOL — \
                 state drifted while it waited. Rebuild or top up.",
                fee_payer.short(),
                format_amount(balance, LAMPORTS_PER_SOL_DECIMALS),
                format_amount(needed, LAMPORTS_PER_SOL_DECIMALS)
            ),
            actions,
            warnings,
        });
    }

    for ix in &msg.instructions {
        let is_token = ix.program == token_program() || ix.program == token_2022_program();
        if is_token && ix.data.first() == Some(&12) && ix.data.len() >= 10 {
            let amount = u64::from_le_bytes(ix.data[1..9].try_into().expect("8 bytes"));
            if let Some(source) = msg.account(ix, 0) {
                match rpc.get_account(source)? {
                    Some(token_acct) => {
                        let held = parse_token_account_amount(&token_acct.data)?;
                        if held < amount {
                            return Ok(RecheckReport {
                                verdict: Verdict::Drifted,
                                headline: format!(
                                    "Token account {} no longer holds enough for this transfer \
                                     (has {held} base units, needs {amount}). Rebuild.",
                                    source.short()
                                ),
                                actions,
                                warnings,
                            });
                        }
                    }
                    None => {
                        return Ok(RecheckReport {
                            verdict: Verdict::Drifted,
                            headline: format!(
                                "Source token account {} no longer exists. Rebuild.",
                                source.short()
                            ),
                            actions,
                            warnings,
                        })
                    }
                }
            }
        }
    }

    // READY is a clean bill only: anything this tool could not fully explain
    // demotes the verdict, so a warning can never hide behind a green light.
    if warnings.is_empty() {
        Ok(RecheckReport {
            verdict: Verdict::Ready,
            headline: "Verified against the chain just now: the nonce is fresh and balances \
                       hold. A signature authorizes exactly the actions listed — nothing \
                       expires while the human decides."
                .into(),
            actions,
            warnings,
        })
    } else {
        Ok(RecheckReport {
            verdict: Verdict::ReviewRequired,
            headline: "Chain state holds, but this transaction contains instructions the \
                       recheck could not fully explain. Read every warning before signing; \
                       when in doubt, rebuild with durable_tx_build."
                .into(),
            actions,
            warnings,
        })
    }
}

/// Decode instructions into human sentences. Returns total SOL outflow from
/// the fee payer in lamports. Anything unrecognized becomes a warning — the
/// human should never sign bytes nobody can explain.
fn decode_actions(msg: &ParsedMessage, actions: &mut Vec<String>, warnings: &mut Vec<String>) -> u64 {
    let fee_payer = msg.account_keys[0];
    let mut sol_outflow: u64 = 0;
    for ix in &msg.instructions {
        if ix.program == system_program() {
            if ix.data == [4, 0, 0, 0] {
                continue; // the advance-nonce plumbing, reported via verdict
            }
            if ix.data.len() == 12 && ix.data[..4] == [2, 0, 0, 0] {
                let lamports = u64::from_le_bytes(ix.data[4..12].try_into().expect("8 bytes"));
                let from = msg.account(ix, 0);
                let to = msg.account(ix, 1);
                if from == Some(&fee_payer) {
                    sol_outflow = sol_outflow.saturating_add(lamports);
                }
                actions.push(format!(
                    "Send {} SOL from {} to {}",
                    format_amount(lamports, LAMPORTS_PER_SOL_DECIMALS),
                    from.map(Pubkey::short).unwrap_or_else(|| "?".into()),
                    to.map(Pubkey::short).unwrap_or_else(|| "?".into()),
                ));
                continue;
            }
            warnings.push("unrecognized system-program instruction — do not sign unless you understand it".into());
        } else if ix.program == token_program() || ix.program == token_2022_program() {
            if ix.data.first() == Some(&12) && ix.data.len() >= 10 {
                let amount = u64::from_le_bytes(ix.data[1..9].try_into().expect("8 bytes"));
                let decimals = ix.data[9];
                actions.push(format!(
                    "Send {} of token mint {} from {} to {}",
                    format_amount(amount, decimals),
                    msg.account(ix, 1).map(Pubkey::short).unwrap_or_else(|| "?".into()),
                    msg.account(ix, 0).map(Pubkey::short).unwrap_or_else(|| "?".into()),
                    msg.account(ix, 2).map(Pubkey::short).unwrap_or_else(|| "?".into()),
                ));
                continue;
            }
            warnings.push("unrecognized token-program instruction — do not sign unless you understand it".into());
        } else if ix.program == ata_program() {
            actions.push("Create the recipient's token account if missing (small rent, paid by signer)".into());
        } else if ix.program == memo_program() {
            // The memo is untrusted data. Quote it, cap it, and never let it
            // masquerade as part of the verdict.
            let text: String = String::from_utf8_lossy(&ix.data).chars().take(80).collect();
            actions.push(format!("Attach on-chain memo (inert data): {text:?}"));
        } else {
            warnings.push(format!(
                "instruction for unrecognized program {} — do not sign unless you understand it",
                ix.program.short()
            ));
        }
    }
    sol_outflow
}

pub fn parameters_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "transaction_base64": {
                "type": "string",
                "description": "The pending unsigned transaction to verify, base64-encoded."
            }
        },
        "required": ["transaction_base64"]
    })
}
