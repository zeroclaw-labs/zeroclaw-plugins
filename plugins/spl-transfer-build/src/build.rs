//! The pure builder. No wit-bindgen, no wasm dependency, no live network: it
//! takes an [`RpcClient`] over any [`Transport`], so `cargo test` drives the
//! exact code path the component runs inside wasmtime.
//!
//! Two outcomes are normal and both are deterministic: a built transaction, or
//! a [`Refusal`]. An `Err` means the node failed, not that the request was
//! rejected — the distinction matters, because a model must never be able to
//! read "the RPC timed out" as "the policy allowed it".

use std::collections::HashMap;

use solana_wasi::nonce::NonceState;
use solana_wasi::prelude::*;
use solana_wasi::shape::{clip, parse_amount, ui_amount};
use solana_wasi::token::{MintState, TokenAccount, TokenProgram};
use solana_wasi::tx::blockhash_from_base58;

/// Native SOL has nine decimals and no mint account to read them from.
pub const SOL_DECIMALS: u8 = 9;

/// The most memo text that will ever reach the ledger.
pub const MAX_MEMO_CHARS: usize = 120;

/// What the agent asked for. Every field here is model-controlled and is
/// treated as such.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
    /// The recipient's **wallet**, not their token account.
    pub recipient: Pubkey,
    /// A plain decimal string, in whole tokens.
    pub amount: String,
    /// `None` means native SOL.
    pub mint: Option<Pubkey>,
    /// Optional memo, for reconciling an invoice out of the ledger later.
    pub memo: Option<String>,
}

/// A policy decision. Deterministic, testable, and never influenced by
/// anything the model said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Stable identifier for the rule that fired.
    pub code: &'static str,
    /// One sentence, for the human and the model.
    pub reason: String,
}

impl Refusal {
    fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Refusal {
            code,
            reason: reason.into(),
        }
    }
}

/// A transaction nobody has signed yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltTransfer {
    /// Base64, ready for `simulateTransaction` or an approval gate.
    pub transaction_base64: String,
    /// SHA-256 of the message, hex. The human compares this with their wallet.
    pub digest: String,
    /// The rendered, human-readable summary.
    pub summary: String,
    /// True when the transaction is anchored to a durable nonce rather than a
    /// blockhash, and therefore does not expire while it waits for approval.
    pub durable: bool,
}

/// What the outcome actually was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Built. Hand it to a human or a multisig.
    Built(Box<BuiltTransfer>),
    /// Refused by policy. Nothing was built.
    Refused(Refusal),
}

/// Operator policy, read from the plugin's own config section.
///
/// This is the security boundary. Everything that can stop a transfer lives
/// here, in `config.toml`, where the agent cannot reach it. The tool arguments
/// can choose a recipient and an amount; they cannot raise a cap, add a mint,
/// change the sender, or turn a check off.
#[derive(Debug, Clone, PartialEq)]
pub struct TransferConfig {
    /// JSON-RPC endpoint. May contain an API key; never rendered.
    pub rpc_url: String,
    /// The wallet that will sign. A public key — this plugin holds no secret.
    pub sender: Option<Pubkey>,
    /// Per-transaction ceilings, in whole tokens, keyed by mint.
    ///
    /// This doubles as the allowlist: a mint with no entry cannot be sent at
    /// all. Default-deny falls out of the data structure rather than out of a
    /// separate flag someone can forget to set.
    pub caps: Vec<(Option<Pubkey>, String)>,
    /// A durable nonce account, so an approval queue cannot outlive the
    /// transaction.
    pub nonce_account: Option<Pubkey>,
    /// The key that advances the nonce. Defaults to the sender.
    pub nonce_authority: Option<Pubkey>,
    /// Priority fee bid, in micro-lamports per compute unit.
    pub priority_fee: Option<u64>,
    /// Refuse a transfer whose fee exceeds this, in basis points.
    pub max_transfer_fee_bps: u16,
    /// Simulate before returning. On by default: a transaction a human is
    /// about to approve should be known to land.
    pub simulate: bool,
}

impl Default for TransferConfig {
    fn default() -> Self {
        TransferConfig {
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
            sender: None,
            caps: Vec::new(),
            nonce_account: None,
            nonce_authority: None,
            priority_fee: None,
            max_transfer_fee_bps: 100,
            simulate: true,
        }
    }
}

impl TransferConfig {
    /// Build from the flat `string -> string` section the host injects.
    ///
    /// Unparseable values are dropped, never defaulted to something permissive:
    /// a typo in a cap must not become an unlimited cap, and a typo in a mint
    /// must not become an allowlisted mint.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let mut cfg = TransferConfig::default();

        if let Some(url) = section.get("rpc_url").filter(|v| !v.trim().is_empty()) {
            cfg.rpc_url = url.trim().to_string();
        }
        cfg.sender = section.get("sender").and_then(|s| Pubkey::from_base58(s.trim()).ok());
        cfg.nonce_account = section
            .get("nonce_account")
            .and_then(|s| Pubkey::from_base58(s.trim()).ok());
        cfg.nonce_authority = section
            .get("nonce_authority")
            .and_then(|s| Pubkey::from_base58(s.trim()).ok());
        cfg.priority_fee = section
            .get("priority_fee_micro_lamports")
            .and_then(|v| v.trim().parse::<u64>().ok());
        if let Some(v) = section
            .get("max_transfer_fee_bps")
            .and_then(|v| v.trim().parse::<u16>().ok())
        {
            cfg.max_transfer_fee_bps = v.min(10_000);
        }
        if let Some(v) = section.get("simulate") {
            cfg.simulate = !v.eq_ignore_ascii_case("false");
        }
        if let Some(raw) = section.get("spend_caps") {
            cfg.caps = parse_caps(raw);
        }
        cfg
    }

    /// The cap for a mint, or `None` when it is not allowlisted at all.
    pub fn cap_for(&self, mint: Option<Pubkey>) -> Option<&str> {
        self.caps
            .iter()
            .find(|(m, _)| *m == mint)
            .map(|(_, cap)| cap.as_str())
    }
}

/// `"SOL:0.5, EPjFW…:250"` — the token cap for native SOL uses the literal
/// `SOL`, everything else is a mint address.
fn parse_caps(raw: &str) -> Vec<(Option<Pubkey>, String)> {
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((key, amount)) = entry.rsplit_once(':') else {
            continue;
        };
        let (key, amount) = (key.trim(), amount.trim());
        // Reject the cap rather than the digit: "100abc" must not become 100.
        if amount.is_empty() || !amount.chars().all(|c| c.is_ascii_digit() || c == '.') {
            continue;
        }
        let mint = if key.eq_ignore_ascii_case("SOL") {
            None
        } else {
            match Pubkey::from_base58(key) {
                Ok(m) => Some(m),
                Err(_) => continue,
            }
        };
        out.push((mint, amount.to_string()));
    }
    out
}

/// Build an unsigned transfer, or refuse.
///
/// At most three RPC round trips: one batched account read, one blockhash (only
/// when no durable nonce is configured), and one simulation.
pub fn build<T: Transport>(
    rpc: &RpcClient<T>,
    request: &TransferRequest,
    cfg: &TransferConfig,
) -> Result<Outcome> {
    macro_rules! refuse {
        ($code:expr, $($arg:tt)*) => {
            return Ok(Outcome::Refused(Refusal::new($code, format!($($arg)*))))
        };
    }

    let Some(sender) = cfg.sender else {
        refuse!(
            "no_sender",
            "the operator has not configured a sender wallet; set `sender` in this plugin's config"
        )
    };

    // --- policy, before anything is spent on the network -------------------

    if request.recipient == sender {
        refuse!("self_transfer", "the recipient is the sender's own wallet")
    }
    if request.recipient.is_zeroed() {
        refuse!("recipient_is_system_program", "the recipient is the system program")
    }

    let Some(cap) = cfg.cap_for(request.mint) else {
        refuse!(
            "mint_not_allowlisted",
            "{} is not in this agent's spend caps, so it cannot be sent. \
             Spend caps live in the operator's config and cannot be changed from a conversation.",
            request
                .mint
                .map(|m| m.abbreviated())
                .unwrap_or_else(|| "native SOL".into())
        )
    };

    let memo = match sanitize_memo(request.memo.as_deref()) {
        Ok(m) => m,
        Err(reason) => refuse!("bad_memo", "{reason}"),
    };

    // --- read the chain ----------------------------------------------------

    let (program, decimals, mint_state) = match request.mint {
        None => (TokenProgram::Legacy, SOL_DECIMALS, None),
        Some(mint) => {
            let account = match rpc.get_account(&mint)? {
                Some(a) => a,
                None => refuse!("mint_missing", "{} does not exist", mint.abbreviated()),
            };
            let state = match MintState::parse(mint, &account) {
                Ok(s) => s,
                Err(e) => refuse!("not_a_mint", "{e}"),
            };
            if let Some(refusal) = hostile_mint(&state, cfg) {
                return Ok(Outcome::Refused(refusal));
            }
            (state.program, state.mint.decimals, Some(state))
        }
    };

    let amount = match parse_amount(&request.amount, decimals) {
        Ok(a) => a,
        Err(e) => refuse!("bad_amount", "{e}"),
    };
    if amount == 0 {
        refuse!("zero_amount", "the amount is zero")
    }
    let cap_units = parse_amount(cap, decimals).unwrap_or(0);
    if amount > cap_units {
        refuse!(
            "over_cap",
            "{} exceeds this agent's per-transfer cap of {}. The cap is set in the \
             operator's config file and cannot be raised from a conversation.",
            ui_amount(amount, decimals),
            cap
        )
    }
    let Ok(amount_u64) = u64::try_from(amount) else {
        refuse!("amount_too_large", "the amount does not fit in a u64")
    };

    // One batched read for everything else the build needs.
    let mut wanted = vec![request.recipient];
    let (source_ata, dest_ata) = match request.mint {
        Some(mint) => {
            let source = associated_token_address(&sender, &mint, program)?;
            let dest = associated_token_address(&request.recipient, &mint, program)?;
            wanted.push(source);
            wanted.push(dest);
            (Some(source), Some(dest))
        }
        None => (None, None),
    };
    if let Some(nonce) = cfg.nonce_account {
        wanted.push(nonce);
    }
    let fetched = rpc.get_multiple_accounts(&wanted)?;

    // The classic, unrecoverable mistake: paying a token account, or a mint,
    // instead of a wallet. An agent that read an address out of a chat message
    // gets this wrong far more often than a person does. Both are owned by a
    // token program, and the length tells them apart — worth distinguishing,
    // because "that is the token's mint address" and "that is somebody's token
    // account" are different mistakes to go and fix.
    if let Some(account) = fetched.first().and_then(Clone::clone) {
        if TokenProgram::from_owner(&account.owner).is_some() {
            let what = if account.data.len() == solana_wasi::token::MINT_LEN {
                "a token mint"
            } else {
                "a token account"
            };
            refuse!(
                "recipient_is_not_a_wallet",
                "{} is {what}, not a wallet. Send to the owner's wallet address instead; \
                 the transfer would otherwise be unrecoverable.",
                request.recipient.abbreviated()
            )
        }
    }

    let mut instructions = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // --- durable nonce, or an expiring blockhash ---------------------------

    let (recent_blockhash, durable) = match cfg.nonce_account {
        Some(nonce_account) => {
            let index = wanted.len() - 1;
            let Some(account) = fetched.get(index).and_then(Clone::clone) else {
                refuse!("nonce_missing", "the configured nonce account does not exist")
            };
            let state = match NonceState::parse(&account) {
                Ok(s) => s,
                Err(e) => refuse!("nonce_invalid", "{e}"),
            };
            let authority = cfg.nonce_authority.unwrap_or(sender);
            if state.authority != authority {
                refuse!(
                    "nonce_authority_mismatch",
                    "the nonce account's authority is {}, not the configured {}",
                    state.authority.abbreviated(),
                    authority.abbreviated()
                )
            }
            instructions.push(instructions::advance_nonce_account(
                &nonce_account,
                &authority,
            ));
            (state.durable_nonce, true)
        }
        None => {
            let latest = rpc.get_latest_blockhash()?;
            notes.push(
                "expires in about a minute: no durable nonce is configured, so this must be \
                 signed promptly"
                    .to_string(),
            );
            (blockhash_from_base58(&latest.blockhash)?, false)
        }
    };

    if let Some(price) = cfg.priority_fee {
        instructions.push(instructions::set_compute_unit_price(price));
    }

    // --- the transfer itself ------------------------------------------------

    match (request.mint, source_ata, dest_ata) {
        (None, _, _) => {
            instructions.push(instructions::transfer_sol(
                &sender,
                &request.recipient,
                amount_u64,
            ));
        }
        (Some(mint), Some(source), Some(dest)) => {
            match fetched.get(1).and_then(Clone::clone) {
                Some(account) => {
                    let token_account = match TokenAccount::unpack(&account.data) {
                        Ok(t) => t,
                        Err(e) => refuse!("source_unreadable", "{e}"),
                    };
                    if token_account.is_frozen() {
                        refuse!("source_frozen", "the sender's token account is frozen")
                    }
                    if token_account.amount < amount_u64 {
                        refuse!(
                            "insufficient_balance",
                            "the sender holds {}, which is less than {}",
                            ui_amount(token_account.amount as u128, decimals),
                            ui_amount(amount, decimals)
                        )
                    }
                }
                None => refuse!(
                    "source_missing",
                    "the sender has no {} account, so there is nothing to send",
                    mint.abbreviated()
                ),
            }

            // Idempotent on purpose: between building this and a human tapping
            // approve, somebody else may have created the recipient's account.
            if fetched.get(2).and_then(Clone::clone).is_none() {
                instructions.push(instructions::create_associated_token_account_idempotent(
                    &sender,
                    &dest,
                    &request.recipient,
                    &mint,
                    program,
                ));
                notes.push(
                    "creates the recipient's token account, about 0.00204 SOL of rent paid \
                     by the sender"
                        .to_string(),
                );
            }

            instructions.push(instructions::transfer_checked(
                program,
                &source,
                &mint,
                &dest,
                &sender,
                amount_u64,
                decimals,
            ));
        }
        _ => refuse!("internal", "token accounts were not derived"),
    }

    if let Some(text) = &memo {
        instructions.push(instructions::memo(text, &[sender]));
    }

    // --- compile ------------------------------------------------------------

    let message = Message::compile(&sender, &instructions, recent_blockhash)?;
    let digest = message.digest();
    let transaction = UnsignedTransaction::new(message);
    let transaction_base64 = match transaction.to_base64() {
        Ok(b) => b,
        Err(e) => refuse!("too_large", "{e}"),
    };

    // A transaction a human is about to approve should be known to land.
    let mut simulation = None;
    if cfg.simulate {
        match rpc.simulate_unsigned(&transaction_base64) {
            Ok(outcome) => match outcome.err {
                Some(err) => refuse!(
                    "simulation_failed",
                    "the transaction would fail on-chain: {}",
                    clip(&err, 120)
                ),
                None => simulation = outcome.units_consumed,
            },
            // A node that will not simulate must not silently become an
            // approval. Say so in the summary instead.
            Err(_) => notes.push("not simulated: the node declined the request".to_string()),
        }
    }

    if let Some(state) = &mint_state {
        if let Some(bps) = state.transfer_fee_bps().filter(|b| *b > 0) {
            let fee = amount * bps as u128 / 10_000;
            notes.push(format!(
                "the recipient receives {} after a {bps} bps transfer fee",
                ui_amount(amount.saturating_sub(fee), decimals)
            ));
        }
        if state.mint.freeze_authority.is_some() {
            notes.push("this token's issuer can freeze the recipient's account".to_string());
        }
        if let Some(delegate) = state.permanent_delegate() {
            notes.push(format!(
                "{} can move these tokens out of the recipient's account at any time",
                delegate.abbreviated()
            ));
        }
    }

    let summary = render_summary(
        request,
        &sender,
        amount,
        decimals,
        &memo,
        &digest,
        durable,
        simulation,
        &notes,
    );

    Ok(Outcome::Built(Box::new(BuiltTransfer {
        transaction_base64,
        digest,
        summary,
        durable,
    })))
}

/// Refuse the mints where a `TransferChecked` cannot honestly succeed, or where
/// what arrives is not what the summary promised.
///
/// Deliberately narrow. A permanent delegate or a freeze authority is a custody
/// risk and shows up as a warning in the summary — but the operator allowlisted
/// this mint, and refusing to move an allowlisted token would just move the
/// payment somewhere with no guardrails at all.
fn hostile_mint(state: &MintState, cfg: &TransferConfig) -> Option<Refusal> {
    if state.is_non_transferable() {
        return Some(Refusal::new(
            "non_transferable",
            "this token cannot be transferred at all",
        ));
    }
    if state.is_paused() {
        return Some(Refusal::new(
            "paused",
            "all transfers of this token are paused right now",
        ));
    }
    if state.defaults_to_frozen() {
        return Some(Refusal::new(
            "default_frozen",
            "new accounts for this token are created frozen, so the recipient could not \
             spend what you send",
        ));
    }
    // An armed hook needs its extra accounts resolved and passed. This builder
    // does not resolve them, so the transaction would fail on-chain. Saying
    // which limitation applies beats a generic failure at signing time.
    if let Some(program) = state.transfer_hook_program() {
        return Some(Refusal::new(
            "transfer_hook_armed",
            format!(
                "this token runs a transfer hook ({}); this builder does not resolve the \
                 hook's extra accounts, so the transfer would fail",
                program.abbreviated()
            ),
        ));
    }
    if let Some(bps) = state.transfer_fee_bps() {
        if bps > cfg.max_transfer_fee_bps {
            return Some(Refusal::new(
                "transfer_fee_too_high",
                format!(
                    "this token withholds {bps} bps on transfer, over the operator's \
                     {} bps limit",
                    cfg.max_transfer_fee_bps
                ),
            ));
        }
    }
    None
}

/// A memo is model-controlled text that becomes permanent, public, on-chain
/// data. Bound it and flatten it; refuse it if the model tried to hide
/// something in it.
fn sanitize_memo(memo: Option<&str>) -> core::result::Result<Option<String>, String> {
    let Some(raw) = memo.map(str::trim).filter(|m| !m.is_empty()) else {
        return Ok(None);
    };
    let clean = untrusted_text(raw, MAX_MEMO_CHARS);
    if clean.suspicious {
        return Err(
            "the memo contains control characters or text aimed at a language model; \
             it would be written permanently to a public ledger"
                .to_string(),
        );
    }
    Ok(Some(clean.text))
}

#[allow(clippy::too_many_arguments)]
fn render_summary(
    request: &TransferRequest,
    sender: &Pubkey,
    amount: u128,
    decimals: u8,
    memo: &Option<String>,
    digest: &str,
    durable: bool,
    units: Option<u64>,
    notes: &[String],
) -> String {
    let mut budget = Budget::new(1_200);
    let asset = request
        .mint
        .map(|m| m.abbreviated())
        .unwrap_or_else(|| "SOL".into());

    budget.push_always("UNSIGNED TRANSFER — nothing has been signed or sent");
    budget.push_always(format!("send {} {asset}", ui_amount(amount, decimals)));
    budget.push_always(format!("from {}", sender.abbreviated()));
    budget.push_always(format!("to   {}", request.recipient.abbreviated()));
    if let Some(text) = memo {
        budget.push(format!("memo \"{text}\""));
    }
    budget.push(if durable {
        "validity: anchored to a durable nonce, does not expire while it waits".to_string()
    } else {
        "validity: a recent blockhash".to_string()
    });
    for note in notes {
        budget.push(format!("note: {note}"));
    }
    if let Some(units) = units {
        budget.push(format!("simulated on-chain: succeeds, {units} compute units"));
    }
    budget.push_always(format!("digest {digest}"));
    budget.push_always("^ your wallet must show this same digest before you approve");
    budget.render()
}
