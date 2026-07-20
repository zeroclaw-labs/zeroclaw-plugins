//! Pure transaction-building logic for `durable-tx-build`. No wasm, no HTTP:
//! the network is injected as [`HttpPost`], so everything here runs under a
//! plain host `cargo test`.
//!
//! Safety model, enforced here and not in the prompt:
//! - the recipient must be a valid base58 pubkey (never free text),
//! - the mint must be on the operator's allowlist,
//! - the amount must clear the operator's per-transaction cap,
//! - the sender is always the nonce authority — the human wallet — so the
//!   plugin cannot be steered into spending from anything else,
//! - the output is an *unsigned* transaction; this component has no key
//!   material at any point.

use std::collections::HashMap;

use aval_core::amount::{format_amount, parse_amount, LAMPORTS_PER_SOL_DECIMALS};
use aval_core::codec::b64_encode;
use aval_core::instruction::{
    advance_nonce_account, create_ata_idempotent, memo, spl_transfer_checked, system_transfer,
    Instruction,
};
use aval_core::message::{compile_message, serialize_unsigned_transaction};
use aval_core::nonce::parse_nonce_account;
use aval_core::pubkey::{derive_ata, system_program, token_program, Pubkey};
use aval_core::rpc::{parse_mint_decimals, parse_token_account_amount, HttpPost, Rpc};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
/// Refuse to build without an explicit operator cap. A missing cap is a
/// configuration error, not permission to spend freely.
pub const CAP_REQUIRED_MSG: &str =
    "refusing to build: no per-transaction cap configured. Set max_amount_ui in this plugin's config section.";

// deny_unknown_fields closes the argument surface: a prompt-injected model
// cannot smuggle override flags this plugin never defined.
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct BuildArgs {
    /// Base58 recipient wallet address. Never an alias or free text.
    pub recipient: String,
    /// Decimal amount in UI units, as a string ("12.5").
    pub amount: String,
    /// SPL mint address, or omitted/"SOL" for native SOL.
    #[serde(default)]
    pub mint: Option<String>,
    /// Optional memo for reconciliation (invoice ids and the like).
    #[serde(default)]
    pub memo: Option<String>,
    /// Durable nonce account created by nonce-vault-init.
    pub nonce_account: String,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

pub struct Config {
    pub rpc_url: String,
    /// Mints the operator allows, as base58 strings. "SOL" allows native SOL.
    pub allowed_mints: Vec<String>,
    /// Per-transaction cap in UI units, per mint symbol/address; "*" applies
    /// to everything without a specific entry.
    pub max_amount_ui: HashMap<String, String>,
}

impl Config {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let rpc_url = section
            .get("rpc_url")
            .cloned()
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        let allowed_mints = section
            .get("allowed_mints")
            .map(|s| {
                s.split(',')
                    .map(|m| m.trim().to_string())
                    .filter(|m| !m.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        // max_amount_ui accepts either a bare number ("100") applied to all
        // mints, or "MINT:limit,MINT:limit" pairs.
        let mut max_amount_ui = HashMap::new();
        if let Some(raw) = section.get("max_amount_ui") {
            for part in raw.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                match part.rsplit_once(':') {
                    Some((mint, limit)) => {
                        max_amount_ui.insert(mint.trim().to_string(), limit.trim().to_string());
                    }
                    None => {
                        max_amount_ui.insert("*".to_string(), part.to_string());
                    }
                }
            }
        }
        Config {
            rpc_url,
            allowed_mints,
            max_amount_ui,
        }
    }

    fn cap_for(&self, mint_label: &str) -> Option<&String> {
        self.max_amount_ui
            .get(mint_label)
            .or_else(|| self.max_amount_ui.get("*"))
    }
}

#[derive(Debug)]
pub struct BuiltTransfer {
    /// Base64 unsigned transaction, ready for any offline signer.
    pub transaction_base64: String,
    /// Short human summary for the approval prompt.
    pub summary: String,
}

pub fn build_transfer<H: HttpPost>(http: &H, args: &BuildArgs) -> Result<BuiltTransfer, String> {
    let cfg = Config::from_section(&args.config);
    let rpc = Rpc::new(http, &cfg.rpc_url);

    let recipient = Pubkey::from_base58(args.recipient.trim())
        .map_err(|e| format!("recipient rejected: {e}"))?;
    let nonce_account = Pubkey::from_base58(args.nonce_account.trim())
        .map_err(|e| format!("nonce_account rejected: {e}"))?;

    let mint_label = match args.mint.as_deref().map(str::trim) {
        None | Some("") | Some("SOL") | Some("sol") => "SOL".to_string(),
        Some(m) => m.to_string(),
    };

    // Allowlist gate. Fail closed when the list is empty: an operator who
    // configured nothing has authorized nothing.
    if !cfg.allowed_mints.iter().any(|m| m == &mint_label) {
        return Err(format!(
            "refusing to build: mint {mint_label:?} is not on the operator allowlist ({:?})",
            cfg.allowed_mints
        ));
    }

    // Cap gate. For SOL the decimals are fixed, so the amount/cap comparison
    // happens right here — before a single byte of network traffic. For SPL
    // mints the comparison happens the moment decimals are known.
    let cap = cfg.cap_for(&mint_label).ok_or(CAP_REQUIRED_MSG)?.clone();
    let sol_amounts = if mint_label == "SOL" {
        let lamports = parse_amount(&args.amount, LAMPORTS_PER_SOL_DECIMALS)?;
        let cap_lamports = parse_amount(&cap, LAMPORTS_PER_SOL_DECIMALS)
            .map_err(|e| format!("invalid configured cap: {e}"))?;
        if lamports > cap_lamports {
            return Err(format!(
                "refusing to build: {} SOL exceeds the per-transaction cap of {} SOL",
                format_amount(lamports, LAMPORTS_PER_SOL_DECIMALS),
                format_amount(cap_lamports, LAMPORTS_PER_SOL_DECIMALS)
            ));
        }
        Some(lamports)
    } else {
        None
    };

    // Durable nonce: the stored hash is the transaction's recent_blockhash,
    // and the account's authority is the sender and fee payer.
    let nonce_info = rpc
        .get_account(&nonce_account)?
        .ok_or("nonce account does not exist; run nonce-vault-init first")?;
    if nonce_info.owner != system_program() {
        return Err("nonce account is not owned by the system program".into());
    }
    let nonce_state = parse_nonce_account(&nonce_info.data)?;
    let authority = nonce_state.authority;

    // Optional defense-in-depth: an operator who pins `authority` in config
    // refuses any nonce account — however it got into the arguments — whose
    // on-chain authority is a different wallet.
    if let Some(pinned) = args.config.get("authority") {
        let pinned = Pubkey::from_base58(pinned.trim())
            .map_err(|e| format!("configured authority rejected: {e}"))?;
        if pinned != authority {
            return Err(format!(
                "refusing to build: nonce account {} is controlled by {}, not the \
                 configured authority {}",
                nonce_account.short(),
                authority.short(),
                pinned.short()
            ));
        }
    }

    let mut instructions: Vec<Instruction> =
        vec![advance_nonce_account(&nonce_account, &authority)];

    let summary_body: String;
    if let Some(lamports) = sol_amounts {
        let balance = rpc.get_balance(&authority)?;
        if balance < lamports {
            return Err(format!(
                "sender {} holds {} SOL, below the requested {} SOL",
                authority.short(),
                format_amount(balance, LAMPORTS_PER_SOL_DECIMALS),
                format_amount(lamports, LAMPORTS_PER_SOL_DECIMALS)
            ));
        }
        instructions.push(system_transfer(&authority, &recipient, lamports));
        summary_body = format!(
            "{} SOL from {} to {}",
            format_amount(lamports, LAMPORTS_PER_SOL_DECIMALS),
            authority.short(),
            recipient.short()
        );
    } else {
        let mint = Pubkey::from_base58(&mint_label).map_err(|e| format!("mint rejected: {e}"))?;
        let mint_info = rpc
            .get_account(&mint)?
            .ok_or("mint account does not exist on this cluster")?;
        // Token-2022 mints can carry transfer hooks, transfer fees, and
        // permanent delegates that change what a transfer means. Until those
        // extensions are explicitly handled, refuse rather than mislead the
        // approver.
        if mint_info.owner != token_program() {
            return Err(
                "refusing to build: mint is not owned by the SPL Token program. \
                 Token-2022 mints are not supported yet because their extensions \
                 (hooks, fees, permanent delegates) alter transfer semantics."
                    .into(),
            );
        }
        let decimals = parse_mint_decimals(&mint_info.data)?;
        let amount = parse_amount(&args.amount, decimals)?;
        let cap_units =
            parse_amount(&cap, decimals).map_err(|e| format!("invalid configured cap: {e}"))?;
        if amount > cap_units {
            return Err(format!(
                "refusing to build: {} exceeds the per-transaction cap of {} for mint {}",
                format_amount(amount, decimals),
                format_amount(cap_units, decimals),
                mint.short()
            ));
        }

        let source_ata = derive_ata(&authority, &mint, &token_program())?;
        let dest_ata = derive_ata(&recipient, &mint, &token_program())?;

        let source_info = rpc
            .get_account(&source_ata)?
            .ok_or("sender has no token account for this mint")?;
        let source_balance = parse_token_account_amount(&source_info.data)?;
        if source_balance < amount {
            return Err(format!(
                "sender token balance is {}, below the requested {}",
                format_amount(source_balance, decimals),
                format_amount(amount, decimals)
            ));
        }

        // CreateIdempotent keeps the transaction valid whether or not the
        // recipient's ATA exists by the time the human approves.
        instructions.push(create_ata_idempotent(
            &authority,
            &dest_ata,
            &recipient,
            &mint,
            &token_program(),
        ));
        instructions.push(spl_transfer_checked(
            &token_program(),
            &source_ata,
            &mint,
            &dest_ata,
            &authority,
            amount,
            decimals,
        ));
        summary_body = format!(
            "{} of mint {} from {} to {}",
            format_amount(amount, decimals),
            mint.short(),
            authority.short(),
            recipient.short()
        );
    }

    if let Some(m) = args.memo.as_deref().filter(|m| !m.trim().is_empty()) {
        if m.len() > 256 {
            return Err("memo longer than 256 bytes".into());
        }
        instructions.push(memo(m.trim()));
    }

    let message = compile_message(&authority, &instructions, &nonce_state.blockhash);
    let tx = serialize_unsigned_transaction(&message);

    let memo_note = args
        .memo
        .as_deref()
        .filter(|m| !m.trim().is_empty())
        .map(|m| format!(" Memo: {:?}.", m.trim()))
        .unwrap_or_default();

    Ok(BuiltTransfer {
        transaction_base64: b64_encode(&tx),
        summary: format!(
            "Unsigned transfer built: {summary_body}.{memo_note} \
             Anchored to durable nonce {} — it will not expire while awaiting approval. \
             Signature required from {}. Run approval_recheck before signing.",
            nonce_account.short(),
            authority.short()
        ),
    })
}

pub fn parameters_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "recipient": {
                "type": "string",
                "description": "Recipient wallet address, base58. Must be an exact address; aliases and names are rejected."
            },
            "amount": {
                "type": "string",
                "description": "Amount in UI units as a decimal string, e.g. \"12.5\"."
            },
            "mint": {
                "type": "string",
                "description": "SPL mint address, or \"SOL\" (default) for native SOL."
            },
            "memo": {
                "type": "string",
                "description": "Optional memo attached on-chain, e.g. an invoice id."
            },
            "nonce_account": {
                "type": "string",
                "description": "Durable nonce account address created by nonce_vault_init."
            }
        },
        "required": ["recipient", "amount", "nonce_account"]
    })
}
