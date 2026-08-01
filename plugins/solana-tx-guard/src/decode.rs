//! Pure Solana transaction decoding + danger classification — no wasm, no network.
//!
//! Answers the question the whole field skips: *before* a wallet signs, what does
//! this transaction actually DO? It parses the wire format (legacy and, safely,
//! versioned) and flags the instructions that can cost you control or funds:
//! authority changes, delegate approvals, account closes, owner reassignments.
//! Host-tested against hand-built and real transactions.

// ── known program ids ───────────────────────────────────────────────────────
pub const SYSTEM: &str = "11111111111111111111111111111111";
pub const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub ix_index: usize,
    pub program: String,
    pub program_name: String,
    pub instruction: String,
    pub severity: Severity,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct DecodedTx {
    pub version: &'static str, // "legacy" | "v0"
    pub num_required_signatures: u8,
    pub account_keys: Vec<String>,
    pub num_instructions: usize,
    pub findings: Vec<Finding>,
    /// Programs invoked that are not on the known-safe list.
    pub unknown_programs: Vec<String>,
    pub notes: Vec<String>,
}

// ── shortvec (compact-u16) ──────────────────────────────────────────────────
fn read_shortvec_len(b: &[u8], pos: &mut usize) -> Option<usize> {
    let mut len = 0usize;
    let mut shift = 0;
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        len |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 21 {
            return None;
        }
    }
    Some(len)
}

fn program_name(id: &str) -> &'static str {
    match id {
        SYSTEM => "System",
        TOKEN => "SPL-Token",
        TOKEN_2022 => "Token-2022",
        ATA => "AssociatedTokenAccount",
        COMPUTE_BUDGET => "ComputeBudget",
        _ => "Unknown",
    }
}

/// Decode a base64-decoded transaction (signatures + message) and classify it.
pub fn decode_tx(raw: &[u8]) -> Result<DecodedTx, String> {
    let mut pos = 0usize;
    // signatures: shortvec of 64-byte blobs — skip them, we only read the message.
    let num_sigs = read_shortvec_len(raw, &mut pos).ok_or("truncated: signature count")?;
    pos = pos
        .checked_add(num_sigs.checked_mul(64).ok_or("signature overflow")?)
        .ok_or("signature overflow")?;
    if pos > raw.len() {
        return Err("truncated: signatures".into());
    }

    // message: detect versioned (high bit of first byte set)
    let first = *raw.get(pos).ok_or("truncated: message header")?;
    let versioned = first & 0x80 != 0;
    let version = if versioned { "v0" } else { "legacy" };
    if versioned {
        pos += 1; // consume the version byte; the rest of a v0 header follows
    }

    let num_required_signatures = *raw.get(pos).ok_or("truncated: header")?;
    let _num_readonly_signed = *raw.get(pos + 1).ok_or("truncated: header")?;
    let _num_readonly_unsigned = *raw.get(pos + 2).ok_or("truncated: header")?;
    pos += 3;

    // account keys
    let num_keys = read_shortvec_len(raw, &mut pos).ok_or("truncated: account key count")?;
    let mut account_keys = Vec::with_capacity(num_keys);
    for _ in 0..num_keys {
        let key = raw.get(pos..pos + 32).ok_or("truncated: account key")?;
        account_keys.push(bs58::encode(key).into_string());
        pos += 32;
    }
    // recent blockhash
    pos = pos.checked_add(32).ok_or("overflow")?;
    if pos > raw.len() {
        return Err("truncated: blockhash".into());
    }

    // instructions
    let num_instructions = read_shortvec_len(raw, &mut pos).ok_or("truncated: instruction count")?;
    let mut findings = Vec::new();
    let mut unknown = Vec::new();
    let mut notes = Vec::new();

    for i in 0..num_instructions {
        let program_id_index = *raw.get(pos).ok_or("truncated: program index")? as usize;
        pos += 1;
        let n_accts = read_shortvec_len(raw, &mut pos).ok_or("truncated: ix account count")?;
        let acct_indices: Vec<u8> = raw
            .get(pos..pos + n_accts)
            .ok_or("truncated: ix accounts")?
            .to_vec();
        pos += n_accts;
        let data_len = read_shortvec_len(raw, &mut pos).ok_or("truncated: ix data len")?;
        let data = raw.get(pos..pos + data_len).ok_or("truncated: ix data")?.to_vec();
        pos += data_len;

        let program = account_keys
            .get(program_id_index)
            .cloned()
            .unwrap_or_else(|| "<index out of range>".to_string());
        let pname = program_name(&program);
        if pname == "Unknown" && !unknown.contains(&program) {
            unknown.push(program.clone());
        }
        classify(i, &program, pname, &data, &acct_indices, &account_keys, &mut findings);
    }

    if versioned {
        notes.push(
            "Versioned (v0) transaction: address-lookup-table accounts are resolved on-chain and are not visible in the static decode — lean on the live simulation for the full effect."
                .into(),
        );
    }
    if account_keys.is_empty() {
        return Err("no account keys — not a decodable transaction".into());
    }

    Ok(DecodedTx {
        version,
        num_required_signatures,
        account_keys,
        num_instructions,
        findings,
        unknown_programs: unknown,
        notes,
    })
}

fn push(
    findings: &mut Vec<Finding>,
    ix: usize,
    program: &str,
    pname: &str,
    instruction: &str,
    severity: Severity,
    detail: String,
) {
    findings.push(Finding {
        ix_index: ix,
        program: program.to_string(),
        program_name: pname.to_string(),
        instruction: instruction.to_string(),
        severity,
        detail,
    });
}

fn le_u64(d: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(off..off + 8)?.try_into().ok()?))
}

/// Classify one instruction's danger from its program + data + accounts.
fn classify(
    ix: usize,
    program: &str,
    pname: &str,
    data: &[u8],
    accts: &[u8],
    keys: &[String],
    findings: &mut Vec<Finding>,
) {
    let key_of = |slot: usize| -> String {
        accts
            .get(slot)
            .and_then(|&i| keys.get(i as usize))
            .cloned()
            .unwrap_or_default()
    };
    match pname {
        "SPL-Token" | "Token-2022" => {
            let tag = data.first().copied().unwrap_or(255);
            match tag {
                6 => push(findings, ix, program, pname, "SetAuthority", Severity::Critical,
                    "hands control of a mint or token account to another key — the classic way authority is silently transferred.".into()),
                4 => {
                    let amt = le_u64(data, 1);
                    push(findings, ix, program, pname, "Approve", Severity::High,
                        format!("grants a delegate the right to spend your tokens{}. Revoke-able, but active until you do.",
                            amt.map(|a| format!(" (up to {a})")).unwrap_or_default()));
                }
                12 => {
                    // ApproveChecked
                    push(findings, ix, program, pname, "ApproveChecked", Severity::High,
                        "grants a delegate spending rights over your token account.".into());
                }
                9 => push(findings, ix, program, pname, "CloseAccount", Severity::High,
                    format!("closes a token account and sends its rent lamports to {}.", key_of(2).chars().take(8).collect::<String>())),
                8 => push(findings, ix, program, pname, "Burn", Severity::Medium,
                    "permanently destroys tokens from an account.".into()),
                7 => push(findings, ix, program, pname, "MintTo", Severity::Low,
                    "mints new tokens (only works if you hold the mint authority).".into()),
                3 => {
                    let amt = le_u64(data, 1);
                    push(findings, ix, program, pname, "Transfer", Severity::Info,
                        format!("moves {} token base units to {}.",
                            amt.map(|a| a.to_string()).unwrap_or("?".into()), key_of(1).chars().take(8).collect::<String>()));
                }
                _ => {}
            }
        }
        "System" => {
            let tag = data.get(0..4).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes).unwrap_or(u32::MAX);
            match tag {
                1 => push(findings, ix, program, pname, "Assign", Severity::Critical,
                    "reassigns an account's owner program — after this a different program controls it.".into()),
                2 => {
                    let lamports = le_u64(data, 4);
                    push(findings, ix, program, pname, "Transfer", Severity::Info,
                        format!("transfers {} lamports to {}.",
                            lamports.map(|l| l.to_string()).unwrap_or("?".into()), key_of(1).chars().take(8).collect::<String>()));
                }
                8 => push(findings, ix, program, pname, "Allocate", Severity::Low, "allocates space in an account.".into()),
                _ => {}
            }
        }
        "ComputeBudget" | "AssociatedTokenAccount" => { /* benign by design */ }
        _ => push(findings, ix, program, pname, "unknown-program-call", Severity::Medium,
            "calls a program that is not on the known-safe list — verify what it does before signing.".into()),
    }
}

/// Overall verdict from the static findings alone (the live sim refines it).
pub fn static_verdict(tx: &DecodedTx) -> (&'static str, u32) {
    let max = tx.findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Info);
    let score: u32 = tx
        .findings
        .iter()
        .map(|f| match f.severity {
            Severity::Critical => 40,
            Severity::High => 25,
            Severity::Medium => 12,
            Severity::Low => 4,
            Severity::Info => 0,
        })
        .sum::<u32>()
        .min(100);
    let band = match max {
        Severity::Critical | Severity::High => "DANGEROUS",
        Severity::Medium => "REVIEW",
        _ if !tx.unknown_programs.is_empty() => "REVIEW",
        _ => "SAFE",
    };
    (band, score)
}
