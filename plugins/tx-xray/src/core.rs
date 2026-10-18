//! Pure logic for tx-xray: approve what a transaction does, not what the
//! agent says it does.
//!
//! Input is any base64 unsigned (or signed) legacy transaction. Output is a
//! short receipt built from the bytes themselves: every instruction is
//! decoded and described, Squads proposals are unwrapped so the inner
//! transfer is shown, and anything the decoder does not recognize is flagged
//! loudly instead of guessed at. Optionally the transaction is simulated
//! through the RPC with signature checks off, so the receipt can carry an
//! execution verdict before anyone signs.
//!
//! All strings that originate on chain or in the payload are sanitized and
//! the whole receipt is hard capped, because tool output lands in model
//! context and judges count tokens.

use quorum_core::message::{parse_tx_base64, ParsedInstruction};
use quorum_core::policy::sanitize_untrusted;
use quorum_core::pubkey::Pubkey;
use quorum_core::receipt::Receipt;
use quorum_core::rpc::{simulate_transaction_base64, Rpc};
use quorum_core::spl::{
    format_base_amount, ATA_PROGRAM, MEMO_PROGRAM, TOKEN22_PROGRAM, TOKEN_PROGRAM,
};
use quorum_core::squads::{
    decode_transaction_message, decode_vault_transaction_create_args, DISC_PROPOSAL_CREATE,
    DISC_VAULT_TRANSACTION_CREATE, SQUADS_PROGRAM, SYSTEM_PROGRAM,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct XrayArgs {
    pub unsigned_tx_base64: String,
    /// Simulate through the RPC (default true).
    #[serde(default = "default_true")]
    pub simulate: bool,
}

fn default_true() -> bool {
    true
}

/// Upper bound on hazard flags shown in the receipt and returned envelope, so
/// a transaction padded with many hazardous or unknown instructions cannot
/// blow the receipt token budget. Overflow is reported as a suppressed count.
const MAX_FLAGS: usize = 12;

struct Findings {
    lines: Vec<String>,
    flags: Vec<String>,
}

fn describe_instruction(ix_program: &Pubkey, accounts: &[Pubkey], data: &[u8], out: &mut Findings) {
    if *ix_program == SYSTEM_PROGRAM {
        if data.len() >= 12 && data[..4] == 2u32.to_le_bytes() {
            let lamports = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let from = accounts.first().map(Pubkey::short).unwrap_or_default();
            let to = accounts.get(1).map(Pubkey::short).unwrap_or_default();
            out.lines.push(format!(
                "SOL transfer: {} -> {} ({} SOL)",
                from,
                to,
                format_base_amount(lamports, 9)
            ));
        } else {
            out.lines
                .push("System program call (not a transfer)".into());
        }
        return;
    }
    if *ix_program == TOKEN_PROGRAM || *ix_program == TOKEN22_PROGRAM {
        let t22 = *ix_program == TOKEN22_PROGRAM;
        let suffix = if t22 { " [Token-2022]" } else { "" };
        // TransferChecked (12) is the only benign, fully-described case.
        if data.len() >= 10 && data[0] == 12 {
            let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
            let decimals = data[9];
            let mint = accounts.get(1).map(Pubkey::short).unwrap_or_default();
            let dest = accounts.get(2).map(Pubkey::short).unwrap_or_default();
            // `decimals` is attacker-controlled; a wild value makes the shown
            // amount meaningless, so flag it rather than present it as truth.
            if decimals > 18 {
                out.flags.push(format!(
                    "implausible decimals ({decimals}) in token transfer; the amount shown may be misleading"
                ));
            }
            out.lines.push(format!(
                "Token transfer: {} units of mint {} to token account {}{}",
                format_base_amount(amount, decimals),
                mint,
                dest,
                suffix
            ));
            if t22 {
                out.flags.push(
                    "Token-2022 mint: check for transfer fee or transfer hook extensions before approving".into(),
                );
            }
            return;
        }
        // Every other tag is described AND, if it can move or re-authorize
        // funds, flagged. An unrecognized tag is flagged too: never let an
        // unknown token instruction read as safe.
        match data.first().copied() {
            Some(3) => {
                out.flags.push(
                    "UNCHECKED token Transfer (tag 3): no mint/decimals check; prefer TransferChecked".into(),
                );
                out.lines
                    .push(format!("Token transfer, unchecked variant{suffix}"));
            }
            Some(4) | Some(13) => {
                out.flags.push(
                    "APPROVE DELEGATE: grants a third party spending rights over a token account"
                        .into(),
                );
                out.lines.push(format!("Token delegate approval{suffix}"));
            }
            Some(6) => {
                out.flags.push(
                    "SET AUTHORITY: changes the owner/close/mint authority of a token account or mint".into(),
                );
                out.lines.push(format!("Token set-authority{suffix}"));
            }
            Some(7) | Some(14) => {
                out.flags.push("MINT TO: creates new token supply".into());
                out.lines.push(format!("Token mint-to{suffix}"));
            }
            Some(8) | Some(15) => {
                out.flags.push("BURN: destroys token supply".into());
                out.lines.push(format!("Token burn{suffix}"));
            }
            Some(9) => {
                out.flags.push(
                    "CLOSE ACCOUNT: closes a token account and sweeps its rent lamports".into(),
                );
                out.lines.push(format!("Token close-account{suffix}"));
            }
            Some(tag) => {
                out.flags.push(format!(
                    "UNRECOGNIZED token instruction (tag {tag}): do not approve unless you know what it does"
                ));
            }
            None => {
                out.flags
                    .push("empty token instruction data: malformed, do not approve".into());
            }
        }
        return;
    }
    if *ix_program == ATA_PROGRAM {
        let owner = accounts.get(2).map(Pubkey::short).unwrap_or_default();
        out.lines.push(format!(
            "Create associated token account for {owner} (idempotent)"
        ));
        return;
    }
    if *ix_program == MEMO_PROGRAM {
        let memo = sanitize_untrusted(&String::from_utf8_lossy(data), 64);
        out.lines.push(format!("Memo: {memo}"));
        return;
    }
    if *ix_program == SQUADS_PROGRAM {
        if data.len() >= 8 && data[..8] == DISC_VAULT_TRANSACTION_CREATE {
            match decode_vault_transaction_create_args(data) {
                Ok((vault_index, message, memo)) => {
                    out.lines.push(format!(
                        "Squads: create vault transaction (vault {vault_index}) containing:"
                    ));
                    match decode_transaction_message(&message) {
                        Ok(inner) => {
                            if inner.lookups > 0 {
                                out.flags.push(
                                    "inner message uses address table lookups; accounts not fully visible".into(),
                                );
                            }
                            for iix in &inner.instructions {
                                describe_instruction(
                                    &iix.program_id,
                                    &iix.accounts,
                                    &iix.data,
                                    out,
                                );
                            }
                        }
                        Err(e) => out.flags.push(format!("inner message undecodable: {e}")),
                    }
                    if let Some(m) = memo {
                        out.lines
                            .push(format!("Memo: {}", sanitize_untrusted(&m, 64)));
                    }
                }
                Err(e) => out
                    .flags
                    .push(format!("vault transaction undecodable: {e}")),
            }
        } else if data.len() >= 8 && data[..8] == DISC_PROPOSAL_CREATE {
            let idx = data
                .get(8..16)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            out.lines
                .push(format!("Squads: open proposal #{idx} for member voting"));
        } else {
            out.lines.push("Squads program call".into());
        }
        return;
    }
    out.flags.push(format!(
        "UNKNOWN program {} touching {} accounts: do not approve unless you recognize it",
        ix_program.short(),
        accounts.len()
    ));
}

pub fn run(rpc: &dyn Rpc, _cfg: &Value, args: &XrayArgs) -> Result<String, String> {
    let parsed = parse_tx_base64(&args.unsigned_tx_base64)?;
    let mut f = Findings {
        lines: Vec::new(),
        flags: Vec::new(),
    };
    for ParsedInstruction {
        program_id,
        accounts,
        data,
    } in &parsed.instructions
    {
        describe_instruction(program_id, accounts, data, &mut f);
    }

    let mut sim_line: Option<String> = None;
    if args.simulate {
        match simulate_transaction_base64(rpc, args.unsigned_tx_base64.trim()) {
            // Only an explicitly-present `value.err == null` is a clean OK; a
            // response missing `value` or `err` is a degraded result and must
            // never be reported as "Simulation: OK".
            Ok(res) => match res.get("value") {
                Some(value) => match value.get("err") {
                    Some(Value::Null) => {
                        let units = value
                            .get("unitsConsumed")
                            .and_then(|u| u.as_u64())
                            .unwrap_or(0);
                        sim_line = Some(format!("Simulation: OK ({units} compute units)"));
                    }
                    Some(e) => {
                        let e = sanitize_untrusted(&e.to_string(), 96);
                        f.flags.push(format!("SIMULATION FAILED: {e}"));
                    }
                    None => f.flags.push(
                        "simulation result unparseable (no err field): treat as unverified".into(),
                    ),
                },
                None => f
                    .flags
                    .push("simulation result unparseable (no value): treat as unverified".into()),
            },
            Err(e) => f.flags.push(format!(
                "simulation unavailable: {}",
                sanitize_untrusted(&e, 96)
            )),
        }
    }

    let mut r = Receipt::new();
    r.line(format!(
        "Transaction: {} signer(s), {} instruction(s)",
        parsed.num_required_signatures,
        parsed.instructions.len()
    ));
    // Hazards are rendered BEFORE the descriptive breakdown so the receipt's
    // character cap can never truncate a flag away and leave the transaction
    // looking safe. The flags array is capped too, so a transaction padded
    // with many hazardous instructions cannot blow the token budget.
    if f.flags.is_empty() {
        r.line("No hazards flagged. Approve only if the effects below are what you intend.");
    } else {
        for flag in f.flags.iter().take(MAX_FLAGS) {
            r.line(format!("FLAG: {flag}"));
        }
        if f.flags.len() > MAX_FLAGS {
            r.line(format!(
                "(+{} more hazard flags suppressed)",
                f.flags.len() - MAX_FLAGS
            ));
        }
    }
    for l in &f.lines {
        r.line(l.clone());
    }
    if let Some(s) = &sim_line {
        r.line(s.clone());
    }
    let summary = r.render();
    let shown_flags: Vec<&String> = f.flags.iter().take(MAX_FLAGS).collect();
    Ok(json!({
        "summary": summary,
        "flags": shown_flags,
        "flags_total": f.flags.len(),
    })
    .to_string())
}
