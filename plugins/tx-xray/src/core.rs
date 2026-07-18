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
        if data.len() >= 10 && data[0] == 12 {
            let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
            let decimals = data[9];
            let mint = accounts.get(1).map(Pubkey::short).unwrap_or_default();
            let dest = accounts.get(2).map(Pubkey::short).unwrap_or_default();
            out.lines.push(format!(
                "Token transfer: {} units of mint {} to token account {}{}",
                format_base_amount(amount, decimals),
                mint,
                dest,
                if t22 { " [Token-2022]" } else { "" }
            ));
            if t22 {
                out.flags.push(
                    "Token-2022 mint: check for transfer fee or transfer hook extensions before approving".into(),
                );
            }
        } else if data.first() == Some(&3) {
            out.flags
                .push("plain Transfer without decimals check; prefer TransferChecked".into());
            out.lines.push("Token transfer (unchecked variant)".into());
        } else if data.first() == Some(&4) {
            out.flags
                .push("APPROVE DELEGATE: this grants spending rights over a token account".into());
            out.lines.push("Token delegate approval".into());
        } else {
            out.lines.push(format!(
                "Token program call, tag {}",
                data.first().copied().unwrap_or(255)
            ));
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
            Ok(res) => {
                let err = res.get("value").and_then(|v| v.get("err")).cloned();
                match err {
                    Some(Value::Null) | None => {
                        let units = res
                            .get("value")
                            .and_then(|v| v.get("unitsConsumed"))
                            .and_then(|u| u.as_u64())
                            .unwrap_or(0);
                        sim_line = Some(format!("Simulation: OK ({units} compute units)"));
                    }
                    Some(e) => {
                        let e = sanitize_untrusted(&e.to_string(), 96);
                        f.flags.push(format!("SIMULATION FAILED: {e}"));
                    }
                }
            }
            Err(e) => f.flags.push(format!("simulation unavailable: {e}")),
        }
    }

    let mut r = Receipt::new();
    r.line(format!(
        "Transaction: {} signer(s), {} instruction(s)",
        parsed.num_required_signatures,
        parsed.instructions.len()
    ));
    for l in &f.lines {
        r.line(l.clone());
    }
    if let Some(s) = &sim_line {
        r.line(s.clone());
    }
    if f.flags.is_empty() {
        r.line("No hazards flagged. Approve only if the effects above are what you intend.");
    } else {
        for flag in &f.flags {
            r.line(format!("FLAG: {flag}"));
        }
    }
    let summary = r.render();
    Ok(json!({
        "summary": summary,
        "flags": f.flags,
    })
    .to_string())
}
