//! Pure logic for squads-propose. No wasm, no http, no clock: everything
//! flows through the Rpc trait and the injected config, so this file is fully
//! exercised by host tests with a mock.
//!
//! Flow: policy gate first, bytes second.
//!   1. Build Policy from config. Missing or empty policy refuses to run.
//!   2. Resolve mint through the allowlist and recipient through the address
//!      book. Raw base58 recipients are rejected even when valid.
//!   3. Parse the amount with exact integer math and enforce the cap.
//!   4. Read the multisig account, take transaction_index + 1, derive the
//!      transaction, proposal, and vault PDAs.
//!   5. Build the inner message: create recipient ATA idempotently (vault
//!      pays), transfer_checked from the vault ATA, optional sanitized memo.
//!   6. Wrap in vault_transaction_create + proposal_create and compile the
//!      outer legacy transaction with the human creator as fee payer.
//!   7. Return compact JSON: summary receipt + unsigned base64 for signing.
//!
//! The plugin never signs. The unsigned transaction goes to the operator's
//! wallet; quorum and execution happen in the Squads app. A proposal is the
//! durable object, so nothing here can expire in an approval queue.

use quorum_core::message::{compile_legacy_message, unsigned_tx_base64};
use quorum_core::policy::Policy;
use quorum_core::pubkey::Pubkey;
use quorum_core::receipt::Receipt;
use quorum_core::rpc::{get_account_base64, get_latest_blockhash, Rpc};
use quorum_core::spl::{
    create_ata_idempotent_ix, derive_ata, format_base_amount, memo_ix, transfer_checked_ix,
};
use quorum_core::squads::{
    compile_transaction_message, decode_multisig, proposal_create_ix, proposal_pda,
    transaction_pda, vault_pda, vault_transaction_create_ix, PERM_INITIATE,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct ProposeArgs {
    /// Recipient name from the operator's address book. Raw addresses are
    /// rejected by policy.
    pub recipient: String,
    /// Decimal string, for example "150" or "12.5".
    pub amount: String,
    /// Token symbol or mint address; must be on the config allowlist.
    pub token: String,
    /// Optional memo, sanitized and length capped by policy.
    #[serde(default)]
    pub memo: Option<String>,
}

fn cfg_str<'a>(cfg: &'a Value, key: &str) -> Result<&'a str, String> {
    cfg.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("config missing required '{key}'"))
}

pub fn run(rpc: &dyn Rpc, cfg: &Value, args: &ProposeArgs) -> Result<String, String> {
    // 1. Policy gate. Fail closed before any network or byte work.
    let policy = Policy::from_config(cfg)?;
    let rule = policy.resolve_mint(&args.token)?;
    let recipient = policy.resolve_recipient(&args.recipient)?;
    let amount = policy.check_amount(rule, &args.amount)?;
    let memo = policy.sanitize_memo(args.memo.as_deref());

    // 2. Operator identity and target multisig come from config, never from
    // the model.
    let multisig_addr = Pubkey::from_base58(cfg_str(cfg, "multisig")?)
        .map_err(|e| format!("config multisig: {e}"))?;
    let creator = Pubkey::from_base58(cfg_str(cfg, "creator_pubkey")?)
        .map_err(|e| format!("config creator_pubkey: {e}"))?;
    let vault_index = quorum_core::policy::u64_field(cfg, "vault_index")?
        .map(|v| u8::try_from(v).map_err(|_| "config vault_index must fit in u8".to_string()))
        .transpose()?
        .unwrap_or(0);

    // 3. Live multisig state: next index and a membership sanity check.
    let ms_data = get_account_base64(rpc, &multisig_addr.to_base58())?
        .ok_or("multisig account not found on chain")?;
    let ms = decode_multisig(&ms_data)?;
    match ms.members.iter().find(|m| m.key == creator) {
        None => {
            return Err(format!(
                "creator {} is not a member of this multisig",
                creator.short()
            ))
        }
        Some(m) if m.permissions & PERM_INITIATE == 0 => {
            return Err(format!(
                "creator {} lacks the Initiate permission",
                creator.short()
            ))
        }
        Some(_) => {}
    }
    let index = ms
        .transaction_index
        .checked_add(1)
        .ok_or("transaction index overflow")?;

    // 4. PDAs.
    let (transaction, _) = transaction_pda(&multisig_addr, index);
    let (proposal, _) = proposal_pda(&multisig_addr, index);
    let (vault, _) = vault_pda(&multisig_addr, vault_index);

    // 5. Inner message the vault will execute after quorum.
    let token_program = rule.token_program();
    let vault_ata = derive_ata(&vault, &rule.mint, &token_program);
    let recipient_ata = derive_ata(&recipient, &rule.mint, &token_program);
    let mut inner = vec![
        create_ata_idempotent_ix(&vault, &recipient, &rule.mint, &token_program),
        transfer_checked_ix(
            &token_program,
            &vault_ata,
            &rule.mint,
            &recipient_ata,
            &vault,
            amount,
            rule.decimals,
        ),
    ];
    if let Some(m) = &memo {
        inner.push(memo_ix(m));
    }
    let tx_message = compile_transaction_message(&vault, &inner)?;

    // 6. Outer transaction: create the vault transaction and its proposal in
    // one signature from the human creator.
    let outer = vec![
        vault_transaction_create_ix(
            &multisig_addr,
            &transaction,
            &creator,
            &creator,
            vault_index,
            0,
            &tx_message,
            memo.clone(),
        ),
        proposal_create_ix(&multisig_addr, &proposal, &creator, &creator, index, false),
    ];
    let blockhash = get_latest_blockhash(rpc)?;
    let compiled = compile_legacy_message(&creator, &outer, &blockhash)?;
    let unsigned = unsigned_tx_base64(&compiled);

    // 7. Receipt plus payload, compact by construction.
    let mut r = Receipt::new();
    r.line(format!(
        "Proposal #{index} on multisig {}",
        multisig_addr.short()
    ));
    r.line(format!(
        "Pay {} {} to {} ({})",
        format_base_amount(amount, rule.decimals),
        rule.symbol,
        args.recipient.trim(),
        recipient.short()
    ));
    if let Some(m) = &memo {
        r.line(format!("Memo: {m}"));
    }
    r.line(format!(
        "Needs {} of {} approvals; time lock {}s",
        ms.threshold,
        ms.members.len(),
        ms.time_lock
    ));
    r.line("Sign the attached transaction to file this proposal. Funds move only after quorum approves in Squads.");

    Ok(json!({
        "summary": r.render(),
        "proposal_index": index,
        "proposal": proposal.to_base58(),
        "transaction": transaction.to_base58(),
        "vault": vault.to_base58(),
        "unsigned_tx_base64": unsigned,
    })
    .to_string())
}
