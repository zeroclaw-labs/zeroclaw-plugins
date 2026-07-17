//! Pure core of the `spl-transfer-build` tool: parse args, enforce policy,
//! decide which RPC lookups are needed, build the unsigned transaction, and
//! shape the human-readable digest. No wasm, no network — the shim performs
//! the RPC round-trips this module requests via [`Lookups`].
//!
//! Custody: this tool holds no keys, cannot sign, and cannot broadcast. It
//! returns base64 unsigned-transaction bytes plus a digest of exactly what
//! will be signed; a human or the host wallet does the rest.

use std::collections::BTreeMap;

use serde::Deserialize;
use solana_core_wasi::amount::{from_base_units, to_base_units};
use solana_core_wasi::instruction::{
    advance_nonce, ata_create_idempotent, attach_references, memo as memo_ix, spl_transfer_checked,
    system_transfer, Instruction,
};
use solana_core_wasi::message::{compile_legacy, unsigned_transaction_base64};
use solana_core_wasi::nonce::parse_nonce_account;
use solana_core_wasi::policy::{parse_policy, PolicyVerdict, TransferPolicy};
use solana_core_wasi::pubkey::{derive_ata, Pubkey};
use solana_core_wasi::rpc;

/// Tool arguments, exactly as the LLM supplies them. `sender` is the wallet
/// that will sign (and pay fees); the tool never sees its key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Args {
    pub sender: String,
    pub recipient: String,
    /// Decimal user-units amount, e.g. "25" or "0.5".
    pub amount: String,
    /// Base58 SPL mint, or omitted/"SOL" for native SOL.
    #[serde(default)]
    pub mint: Option<String>,
    /// Optional memo for invoice reconciliation.
    #[serde(default)]
    pub memo: Option<String>,
    /// Optional base58 32-byte Solana Pay reference for payment discovery.
    #[serde(default)]
    pub reference: Option<String>,
    /// Host-injected operator config. Callers cannot spoof it: the host
    /// strips any caller-supplied `__config` before injection.
    #[serde(rename = "__config", default)]
    pub config: BTreeMap<String, String>,
}

/// Everything that can go wrong. Every branch fails closed with an
/// operator-actionable message and no transaction bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    BadArgs(String),
    Policy(String),
    Refused { reason: String },
    Rpc(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::BadArgs(e) => write!(f, "bad arguments: {e}"),
            BuildError::Policy(e) => write!(f, "policy config error (transfer denied): {e}"),
            BuildError::Refused { reason } => write!(f, "transfer refused: {reason}"),
            BuildError::Rpc(e) => write!(f, "rpc error: {e}"),
        }
    }
}

/// Network lookups the shim must satisfy. Keeping the trait tiny keeps host
/// tests honest: mock exactly these three calls, nothing else.
pub trait Lookups {
    /// POST the JSON-RPC `body` to the policy's rpc_url, return the raw body.
    fn rpc(&mut self, body: &str) -> Result<String, String>;
}

/// A validated, policy-admitted transfer plan (pre-RPC).
#[derive(Debug)]
pub struct Plan {
    pub policy: TransferPolicy,
    pub sender: Pubkey,
    pub recipient: Pubkey,
    pub mint_key: String,
    pub amount_display: String,
    pub memo: Option<String>,
    pub reference: Option<Pubkey>,
}

/// Parse + policy-check the arguments. Pure; no network.
pub fn plan(args: &Args) -> Result<Plan, BuildError> {
    let policy = parse_policy(&args.config).map_err(|e| BuildError::Policy(e.to_string()))?;
    let sender =
        Pubkey::parse(&args.sender).map_err(|e| BuildError::BadArgs(format!("sender: {e}")))?;
    let recipient = Pubkey::parse(&args.recipient)
        .map_err(|e| BuildError::BadArgs(format!("recipient: {e}")))?;
    let mint_key = match args.mint.as_deref() {
        None | Some("SOL") | Some("sol") => "SOL".to_string(),
        Some(m) => {
            Pubkey::parse(m).map_err(|e| BuildError::BadArgs(format!("mint: {e}")))?;
            m.to_string()
        }
    };
    let reference = match args.reference.as_deref() {
        None => None,
        Some(r) => {
            Some(Pubkey::parse(r).map_err(|e| BuildError::BadArgs(format!("reference: {e}")))?)
        }
    };
    if let Some(m) = &args.memo {
        if m.len() > 256 {
            return Err(BuildError::BadArgs("memo exceeds 256 bytes".into()));
        }
    }

    // Amount validation needs decimals; for SOL that's 9, for SPL mints the
    // cap entry pins them (cap parsing already validated the decimals field).
    // The definitive on-chain decimals check happens at build time.
    let cap_decimals = policy_decimals(&policy, &mint_key).ok_or_else(|| BuildError::Refused {
        reason: format!("mint {mint_key} is not in the operator's cap list"),
    })?;
    let base_units = to_base_units(&args.amount, cap_decimals)
        .map_err(|e| BuildError::BadArgs(format!("amount: {e}")))?;

    match policy.check(&recipient, &mint_key, base_units) {
        PolicyVerdict::Allowed => {}
        PolicyVerdict::RecipientNotAllowed => {
            return Err(BuildError::Refused {
                reason: format!(
                    "recipient {recipient} is not on the operator's allowlist; no transaction was built"
                ),
            })
        }
        PolicyVerdict::MintNotAllowed => {
            return Err(BuildError::Refused {
                reason: format!("mint {mint_key} is not on the operator's cap list; no transaction was built"),
            })
        }
        PolicyVerdict::OverCap { cap_base_units } => {
            return Err(BuildError::Refused {
                reason: format!(
                    "amount {} exceeds the operator's per-transfer cap of {} for {}; no transaction was built",
                    args.amount,
                    from_base_units(cap_base_units, cap_decimals),
                    mint_key
                ),
            })
        }
    }

    Ok(Plan {
        policy,
        sender,
        recipient,
        mint_key,
        amount_display: args.amount.clone(),
        memo: args.memo.clone(),
        reference,
    })
}

/// The decimals the operator's cap entry was written against. The policy
/// stores caps in base units; we recover decimals from the cap config line
/// format at parse time. SOL is always 9.
fn policy_decimals(policy: &TransferPolicy, mint_key: &str) -> Option<u8> {
    // The policy module normalizes decimals into base units; it does not keep
    // decimals. SOL is fixed; for SPL we re-derive from the raw caps entry at
    // plan time via the decimals catalog the operator wrote. To keep the
    // policy surface minimal we conservatively use: SOL = 9, SPL = looked up
    // on-chain at build time, but the CAP was written in base units already —
    // so for validation we only need "some" decimals to parse the user
    // amount. We require the operator's cap entry decimals to equal the
    // mint's real decimals, verified at build time.
    if !policy.mint_caps.contains_key(mint_key) {
        return None;
    }
    if mint_key == "SOL" {
        Some(9)
    } else {
        policy.cap_decimals(mint_key)
    }
}

/// Result of a successful build.
#[derive(Debug)]
pub struct Built {
    pub transaction_base64: String,
    pub digest: String,
    pub used_durable_nonce: bool,
}

/// Execute the RPC lookups and assemble the unsigned transaction.
pub fn build(plan: &Plan, lookups: &mut dyn Lookups) -> Result<Built, BuildError> {
    let mut ixs: Vec<Instruction> = Vec::new();
    let mut used_nonce = false;

    // Durable nonce mode: fetch + parse the nonce account, advance-first.
    let blockhash: [u8; 32] = if let Some(nonce_acct) = plan.policy.nonce_account {
        let raw = lookups
            .rpc(&rpc::get_account_info(&nonce_acct))
            .map_err(BuildError::Rpc)?;
        let (data, _owner) =
            rpc::parse_account_info(&raw).map_err(|e| BuildError::Rpc(e.to_string()))?;
        let state = parse_nonce_account(&data)
            .map_err(|e| BuildError::Rpc(format!("nonce account {nonce_acct}: {e}")))?;
        if state.authority != plan.sender {
            return Err(BuildError::Refused {
                reason: format!(
                    "nonce account authority {} is not the sender {}; refusing to build an unusable transaction",
                    state.authority, plan.sender
                ),
            });
        }
        ixs.push(advance_nonce(&nonce_acct, &plan.sender));
        used_nonce = true;
        state.durable_nonce
    } else {
        // Fresh blockhash: valid ~60-90s. Documented tradeoff; operators who
        // route through approval queues should configure nonce_account.
        let raw = lookups
            .rpc(&rpc::request_body(
                "getLatestBlockhash",
                serde_json::json!([{ "commitment": "confirmed" }]),
            ))
            .map_err(BuildError::Rpc)?;
        parse_blockhash(&raw)?
    };

    let (amount_base, decimals, digest_asset) = if plan.mint_key == "SOL" {
        let base = to_base_units(&plan.amount_display, 9)
            .map_err(|e| BuildError::BadArgs(e.to_string()))?;
        (base, 9u8, "SOL".to_string())
    } else {
        let mint = Pubkey::parse(&plan.mint_key).expect("validated in plan");
        let raw = lookups
            .rpc(&rpc::get_account_info(&mint))
            .map_err(BuildError::Rpc)?;
        let (data, _) =
            rpc::parse_account_info(&raw).map_err(|e| BuildError::Rpc(e.to_string()))?;
        let on_chain_decimals =
            rpc::mint_decimals(&data).map_err(|e| BuildError::Rpc(e.to_string()))?;
        let cap_decimals = plan
            .policy
            .cap_decimals(&plan.mint_key)
            .unwrap_or(on_chain_decimals);
        if cap_decimals != on_chain_decimals {
            return Err(BuildError::Refused {
                reason: format!(
                    "operator cap for {} was written at {} decimals but the mint has {}; fix the cap entry (fail closed)",
                    plan.mint_key, cap_decimals, on_chain_decimals
                ),
            });
        }
        let base = to_base_units(&plan.amount_display, on_chain_decimals)
            .map_err(|e| BuildError::BadArgs(e.to_string()))?;
        (base, on_chain_decimals, format!("mint {}", plan.mint_key))
    };

    if plan.mint_key == "SOL" {
        let mut transfer = system_transfer(&plan.sender, &plan.recipient, amount_base);
        if let Some(m) = &plan.memo {
            ixs.push(memo_ix(m));
        }
        if let Some(r) = &plan.reference {
            attach_references(&mut transfer, &[*r]);
        }
        ixs.push(transfer);
    } else {
        let mint = Pubkey::parse(&plan.mint_key).expect("validated");
        let src_ata = derive_ata(&plan.sender, &mint);
        let dst_ata = derive_ata(&plan.recipient, &mint);
        // Create the destination ATA when missing (idempotent either way, but
        // we check to keep the digest honest about what the tx does).
        let raw = lookups
            .rpc(&rpc::get_account_info(&dst_ata))
            .map_err(BuildError::Rpc)?;
        let dst_exists =
            rpc::parse_account_exists(&raw).map_err(|e| BuildError::Rpc(e.to_string()))?;
        if !dst_exists {
            ixs.push(ata_create_idempotent(
                &plan.sender,
                &dst_ata,
                &plan.recipient,
                &mint,
            ));
        }
        if let Some(m) = &plan.memo {
            ixs.push(memo_ix(m)); // memo second-to-last, per Solana Pay ordering
        }
        let mut transfer = spl_transfer_checked(
            &src_ata,
            &mint,
            &dst_ata,
            &plan.sender,
            amount_base,
            decimals,
        );
        if let Some(r) = &plan.reference {
            attach_references(&mut transfer, &[*r]);
        }
        ixs.push(transfer);
    }

    let msg = compile_legacy(&plan.sender, &ixs, &blockhash);
    let tx_b64 = unsigned_transaction_base64(&msg);

    let mut digest = format!(
        "UNSIGNED transfer: {} {} from {} to {}",
        plan.amount_display, digest_asset, plan.sender, plan.recipient
    );
    if let Some(m) = &plan.memo {
        digest.push_str(&format!(", memo \"{m}\""));
    }
    if plan.reference.is_some() {
        digest.push_str(", with payment reference");
    }
    digest.push_str(if used_nonce {
        ". Durable nonce: valid until the nonce advances — safe to approve later."
    } else {
        ". Fresh blockhash: sign within ~60s or it expires."
    });
    digest.push_str(" This tool holds no keys; nothing moves until the owner signs.");

    Ok(Built {
        transaction_base64: tx_b64,
        digest,
        used_durable_nonce: used_nonce,
    })
}

fn parse_blockhash(raw: &str) -> Result<[u8; 32], BuildError> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| BuildError::Rpc(e.to_string()))?;
    if let Some(err) = v.get("error") {
        return Err(BuildError::Rpc(err.to_string()));
    }
    let bh = v
        .pointer("/result/value/blockhash")
        .and_then(|s| s.as_str())
        .ok_or_else(|| BuildError::Rpc("missing result.value.blockhash".into()))?;
    Pubkey::parse(bh)
        .map(|p| p.0)
        .map_err(|e| BuildError::Rpc(format!("bad blockhash: {e}")))
}

/// Top-level entry the shim calls: parse args JSON, plan, build, shape output.
pub fn run(raw_args: &str, lookups: &mut dyn Lookups) -> Result<String, BuildError> {
    let args: Args =
        serde_json::from_str(raw_args).map_err(|e| BuildError::BadArgs(e.to_string()))?;
    let p = plan(&args)?;
    let built = build(&p, lookups)?;
    Ok(serde_json::json!({
        "summary": built.digest,
        "unsigned_transaction_base64": built.transaction_base64,
        "durable_nonce": built.used_durable_nonce,
    })
    .to_string())
}
