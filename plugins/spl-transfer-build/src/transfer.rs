//! Pure unsigned-transfer builder. No wasm and no sockets: all chain access
//! goes through [`HttpTransport`], which host tests implement with a mock.
//!
//! Custody tier T1: this code constructs a transaction and *stops*. It holds
//! no key material, and the signer address it builds for comes exclusively
//! from operator config — tool arguments cannot choose who signs or who pays
//! fees. Guardrails enforced here, below the LLM:
//!
//! 1. **Token allowlist** — only operator-listed mints move.
//! 2. **Per-transfer cap** — in token units, compared in base units after the
//!    mint's on-chain decimals are known (never floats).
//! 3. **Recipient allowlist** (optional) — when set, only listed addresses.
//! 4. **Token-2022 hygiene** — non-transferable, permanent-delegate, and
//!    transfer-hook mints are refused; transfer fees are surfaced.
//! 5. **Durable nonce** — optional; verified to belong to the configured
//!    owner, so an approval can wait hours without the blockhash dying.

use std::collections::HashMap;

use zeroclaw_solana_core::amount::{format_base_units, parse_decimal_amount};
use zeroclaw_solana_core::encoding::to_base64;
use zeroclaw_solana_core::links::explorer_inspector_url;
use zeroclaw_solana_core::instruction::{
    advance_nonce, create_ata_idempotent, memo as memo_ix, system_transfer, transfer_checked,
    Instruction,
};
use zeroclaw_solana_core::message::{compile_v0_message, MAX_TRANSACTION_BYTES};
use zeroclaw_solana_core::nonce::parse_nonce_account;
use zeroclaw_solana_core::pubkey::{
    derive_ata, token_2022_program, token_program, Pubkey, SYSTEM_PROGRAM,
};
use zeroclaw_solana_core::rpc::{get_account, get_latest_blockhash, HttpTransport};
use zeroclaw_solana_core::token::{parse_mint, Extension};

/// USDC on mainnet-beta, the default allowlisted token.
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const NATIVE_SOL: &str = "native";
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const DEFAULT_MAX_AMOUNT: &str = "100";
const SOL_DECIMALS: u8 = 9;

#[derive(Debug)]
pub struct TransferConfig {
    pub rpc_url: String,
    /// The wallet that owns the funds, pays fees, and signs — config-only.
    pub owner: Pubkey,
    /// symbol (upper-case) → mint base58, or `native` for SOL.
    pub tokens: Vec<(String, String)>,
    /// Per-transfer cap in token units (decimal string), used for any token
    /// without a per-symbol override.
    pub max_amount: String,
    /// Per-symbol cap overrides (`max_amounts = "SOL:0.5,USDC:200"`), so a
    /// shared numeric cap never conflates tokens of very different value.
    pub max_amounts: Vec<(String, String)>,
    /// When non-empty, the only addresses that may receive.
    pub allowed_recipients: Vec<Pubkey>,
    /// Optional durable nonce account owned by `owner`.
    pub nonce_account: Option<Pubkey>,
}

impl TransferConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let owner = section
            .get("owner")
            .filter(|v| !v.is_empty())
            .ok_or("config error: set `owner` to the signing wallet's address (the plugin never sees its key)")?;
        let owner = Pubkey::parse(owner).map_err(|e| format!("config error: bad owner: {e}"))?;

        let tokens = match section.get("tokens").filter(|v| !v.is_empty()) {
            Some(spec) => parse_token_list(spec)?,
            None => vec![
                ("USDC".to_string(), USDC_MINT.to_string()),
                ("SOL".to_string(), NATIVE_SOL.to_string()),
            ],
        };

        let max_amount = section
            .get("max_amount")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_MAX_AMOUNT.to_string());

        let max_amounts = section
            .get("max_amounts")
            .map(String::as_str)
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|entry| {
                entry
                    .split_once(':')
                    .map(|(sym, cap)| (sym.trim().to_ascii_uppercase(), cap.trim().to_string()))
                    .ok_or_else(|| {
                        format!("config error: max_amounts entry {entry:?} is not SYMBOL:cap")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let allowed_recipients = section
            .get("allowed_recipients")
            .map(String::as_str)
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Pubkey::parse(s).map_err(|e| format!("config error: allowed_recipients: {e}")))
            .collect::<Result<Vec<_>, _>>()?;

        let nonce_account = match section.get("nonce_account").filter(|v| !v.is_empty()) {
            Some(addr) => Some(
                Pubkey::parse(addr).map_err(|e| format!("config error: bad nonce_account: {e}"))?,
            ),
            None => None,
        };

        Ok(Self {
            rpc_url: section
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string()),
            owner,
            tokens,
            max_amount,
            max_amounts,
            allowed_recipients,
            nonce_account,
        })
    }
}

fn parse_token_list(spec: &str) -> Result<Vec<(String, String)>, String> {
    let mut tokens = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (symbol, mint) = entry
            .split_once(':')
            .ok_or_else(|| format!("config error: token entry {entry:?} is not SYMBOL:mint"))?;
        let mint = mint.trim();
        if mint != NATIVE_SOL {
            Pubkey::parse(mint).map_err(|e| format!("config error: token {symbol:?}: {e}"))?;
        }
        tokens.push((symbol.trim().to_ascii_uppercase(), mint.to_string()));
    }
    if tokens.is_empty() {
        return Err("config error: `tokens` is set but empty".to_string());
    }
    Ok(tokens)
}

pub struct TransferArgs {
    pub recipient: String,
    pub amount: String,
    pub token: Option<String>,
    pub memo: Option<String>,
}

#[derive(Debug)]
pub struct BuiltTransfer {
    pub transaction_base64: String,
    /// Read-only Solana Explorer inspector link for this exact transaction — the
    /// human taps it to review the decoded instructions/accounts (and simulate)
    /// before signing. A transaction cannot be *signed* from a link or QR; this
    /// is review only, then they sign in their wallet / Squads / CLI.
    pub review_url: String,
    pub summary: String,
}

/// Build an unsigned transfer under the configured policy. Guardrail
/// violations return `Err` — the tool refuses rather than adjusts.
pub fn build_transfer<T: HttpTransport>(
    transport: &T,
    args: &TransferArgs,
    cfg: &TransferConfig,
) -> Result<BuiltTransfer, String> {
    // Bound caller-supplied strings before any of them can be echoed into an
    // error (context-flood guard). Amount is bounded in parse_decimal_amount,
    // recipient in Pubkey::parse; token and memo are echoed/embedded here.
    if args.token.as_deref().is_some_and(|t| t.len() > 32) {
        return Err("refused: token symbol is too long".to_string());
    }
    if args.memo.as_deref().is_some_and(|m| m.len() > 512) {
        return Err("refused: memo is too long".to_string());
    }

    let recipient = Pubkey::parse(&args.recipient)?;
    if !cfg.allowed_recipients.is_empty() && !cfg.allowed_recipients.contains(&recipient) {
        return Err(format!(
            "refused: {} is not in the operator's allowed_recipients list",
            recipient.to_base58()
        ));
    }
    if recipient == cfg.owner {
        return Err("refused: recipient is the owner wallet itself".to_string());
    }

    let symbol = args
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_ascii_uppercase)
        .unwrap_or_else(|| cfg.tokens[0].0.clone());
    let mint_spec = cfg
        .tokens
        .iter()
        .find(|(sym, _)| *sym == symbol)
        .map(|(_, mint)| mint.clone())
        .ok_or_else(|| {
            format!(
                "refused: token {symbol:?} is not in the operator allowlist ({})",
                cfg.tokens
                    .iter()
                    .map(|(s, _)| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    let mut instructions: Vec<Instruction> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // Durable nonce first: it must lead the instruction list, and its
    // authority must be the configured owner — a foreign nonce account would
    // let someone else control the transaction's lifetime.
    let blockhash_source = match &cfg.nonce_account {
        Some(nonce_addr) => {
            let account = get_account(transport, &cfg.rpc_url, nonce_addr)?
                .ok_or_else(|| format!("nonce account {nonce_addr} does not exist"))?;
            if account.owner != SYSTEM_PROGRAM {
                return Err(format!(
                    "{nonce_addr} is not a system-program nonce account"
                ));
            }
            let state = parse_nonce_account(&account.data)?;
            if state.authority != cfg.owner {
                return Err(format!(
                    "refused: nonce account {nonce_addr} is authorized by {}, not the configured owner",
                    state.authority
                ));
            }
            instructions.push(advance_nonce(nonce_addr, &cfg.owner));
            notes.push("durable nonce: no blockhash expiry, sign whenever ready".to_string());
            state.durable_nonce
        }
        None => {
            let (hash, last_valid) = get_latest_blockhash(transport, &cfg.rpc_url)?;
            notes.push(format!(
                "recent blockhash: sign and submit before block height {last_valid} (~1 minute)"
            ));
            hash
        }
    };

    let cap = cfg
        .max_amounts
        .iter()
        .find(|(sym, _)| *sym == symbol)
        .map(|(_, cap)| cap.as_str())
        .unwrap_or(&cfg.max_amount);

    let (amount_base, decimals, transfer_desc) = if mint_spec == NATIVE_SOL {
        let amount_base = checked_amount(&args.amount, SOL_DECIMALS, cap)?;
        instructions.push(system_transfer(&cfg.owner, &recipient, amount_base));
        (amount_base, SOL_DECIMALS, "SOL (native)".to_string())
    } else {
        let mint = Pubkey::parse(&mint_spec)?;
        let mint_account = get_account(transport, &cfg.rpc_url, &mint)?
            .ok_or_else(|| format!("mint {mint} does not exist on this cluster"))?;
        let token_prog = if mint_account.owner == token_program() {
            token_program()
        } else if mint_account.owner == token_2022_program() {
            token_2022_program()
        } else {
            return Err(format!("{mint} is not owned by a token program"));
        };
        let info = parse_mint(&mint_account.data)?;
        // An oversized / duplicate-padded extension list means the mint
        // account is malformed or the RPC is hostile. We are about to move
        // money against it — refuse rather than transfer on bad data.
        if info.extensions_truncated {
            return Err("refused: mint has a malformed or oversized extension list \
                 (possible hostile RPC); not building a transfer against it"
                .to_string());
        }
        screen_extensions(&info.extensions, &mut notes)?;

        let amount_base = checked_amount(&args.amount, info.decimals, cap)?;

        let source = derive_ata(&cfg.owner, &mint, &token_prog)?;
        let dest = derive_ata(&recipient, &mint, &token_prog)?;
        if get_account(transport, &cfg.rpc_url, &dest)?.is_none() {
            instructions.push(create_ata_idempotent(
                &cfg.owner,
                &dest,
                &recipient,
                &mint,
                &token_prog,
            ));
            notes.push("creates the recipient's token account (~0.002 SOL rent)".to_string());
        }
        instructions.push(transfer_checked(
            &token_prog,
            &source,
            &mint,
            &dest,
            &cfg.owner,
            amount_base,
            info.decimals,
        ));
        (amount_base, info.decimals, symbol.clone())
    };

    if let Some(text) = args
        .memo
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
    {
        instructions.push(memo_ix(&cfg.owner, text));
    }

    let compiled = compile_v0_message(&cfg.owner, &instructions, &blockhash_source)?;
    let wire_len = compiled.unsigned_transaction_bytes().len();
    if wire_len > MAX_TRANSACTION_BYTES {
        return Err(format!(
            "refused: transaction serializes to {wire_len} bytes, over Solana's \
             {MAX_TRANSACTION_BYTES}-byte limit — shorten the memo"
        ));
    }
    // Defense-in-depth cue: with no recipient allowlist configured, the only
    // guards left are the amount cap and the human signer — so flag the
    // destination for that signer to eyeball before approving.
    if cfg.allowed_recipients.is_empty() {
        notes.push(
            "recipient is not on a config allowlist — confirm the destination before signing"
                .to_string(),
        );
    }

    let summary = format!(
        "UNSIGNED transfer of {} {} from {} to {}.{} Verify the recipient, then sign with the owner wallet.",
        format_base_units(amount_base, decimals),
        transfer_desc,
        abbreviate(&cfg.owner.to_base58()),
        recipient.to_base58(),
        notes
            .iter()
            .map(|n| format!(" Note: {n}."))
            .collect::<String>(),
    );

    // Review link carries the MESSAGE bytes (not the full wire tx, whose
    // leading signature-count byte would make the inspector misparse it).
    let review_url = explorer_inspector_url(&to_base64(compiled.message_bytes()));

    Ok(BuiltTransfer {
        transaction_base64: compiled.unsigned_transaction_base64(),
        review_url,
        summary,
    })
}

/// Parse the requested amount and enforce the cap, both in base units.
fn checked_amount(amount: &str, decimals: u8, max_amount: &str) -> Result<u64, String> {
    let amount_base = parse_decimal_amount(amount, decimals)?;
    if amount_base == 0 {
        return Err("refused: amount is zero".to_string());
    }
    let cap_base = parse_decimal_amount(max_amount, decimals)
        .map_err(|e| format!("config error: max_amount: {e}"))?;
    if amount_base > cap_base {
        return Err(format!(
            "refused: {} exceeds the operator-configured cap of {} per transfer",
            amount.trim(),
            max_amount
        ));
    }
    Ok(amount_base)
}

/// Refuse mints whose Token-2022 extensions can strand or confiscate the
/// transfer; surface the ones that merely tax it.
fn screen_extensions(extensions: &[Extension], notes: &mut Vec<String>) -> Result<(), String> {
    for ext in extensions {
        match ext {
            Extension::NonTransferable => {
                return Err("refused: this mint is non-transferable (Token-2022)".to_string())
            }
            Extension::PermanentDelegate { delegate } => {
                return Err(format!(
                    "refused: this mint has a permanent delegate ({}) that can seize tokens; \
                     not sending without explicit operator allowlisting of a safer token",
                    abbreviate(&delegate.to_base58())
                ))
            }
            // Refused even when the hook program is currently unset: the
            // authority can point it at arbitrary code later, and risk-check
            // rates the bare extension RED — the two tools must agree.
            Extension::TransferHook { program_id } => {
                let which = match program_id {
                    Some(hook) => format!("hook program {}", abbreviate(&hook.to_base58())),
                    None => "a transfer-hook extension (program currently unset)".to_string(),
                };
                return Err(format!(
                    "refused: this mint routes transfers through {which}; \
                     unvetted hooks can block or tax transfers"
                ));
            }
            Extension::TransferFee { basis_points, .. } if *basis_points > 0 => {
                notes.push(format!(
                    "this token charges a {}bps transfer fee; the recipient receives less",
                    basis_points
                ));
            }
            Extension::DefaultAccountState { frozen: true } => {
                return Err(
                    "refused: new accounts of this mint start frozen; the recipient could not \
                     use the tokens"
                        .to_string(),
                )
            }
            _ => {}
        }
    }
    Ok(())
}

fn abbreviate(addr: &str) -> String {
    if addr.len() <= 12 {
        return addr.to_string();
    }
    format!("{}…{}", &addr[..4], &addr[addr.len() - 4..])
}
