//! Pure build core: verify that every requested token account is empty and
//! owner-closeable, then assemble an unsigned close transaction. No wasm
//! dependency — host-testable with plain `cargo test`; RPC is a trait.
//!
//! Fail-closed policy: verification is all-or-nothing. If any account fails
//! any invariant, no transaction is produced and the error names the account
//! and the invariant. The rent destination is not an input anywhere in this
//! crate — it is always the owner, by construction (see `tx.rs`).

use crate::tx::{build_close_tx, decode_key, CloseTarget, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use serde_json::{json, Value};

/// Hard cap on closes per transaction (packet-size and review-ergonomics).
pub const MAX_CLOSES_PER_TX: usize = 12;
pub const DEFAULT_MAX_CLOSES: usize = 8;

pub trait Rpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, String>;
}

#[derive(Debug, Clone)]
pub struct BuildRequest {
    pub owner: String,
    /// Explicit token accounts to close. When `None`, the plugin scans and
    /// picks up to `max_accounts` empty accounts itself.
    pub accounts: Option<Vec<String>>,
    pub max_accounts: usize,
    pub priority_fee_micro_lamports: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ClosedAccount {
    pub pubkey: String,
    pub lamports: u64,
}

#[derive(Debug, Clone)]
pub struct BuildOutput {
    pub tx_base64: String,
    pub closed: Vec<ClosedAccount>,
    pub reclaim_lamports: u64,
    pub blockhash: String,
    pub last_valid_block_height: Option<u64>,
}

fn short(addr: &str) -> String {
    if addr.len() > 12 {
        format!("{}..{}", &addr[..6], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}

fn lamports_to_sol(lamports: u64) -> String {
    format!("{:.9}", lamports as f64 / 1e9)
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

/// One fully validated closeable account.
struct Verified {
    pubkey: String,
    lamports: u64,
    token_program: String,
}

/// Check one `jsonParsed` token-account value against every close invariant.
/// Returns the reason string on failure — used verbatim in the fail-closed
/// error so the human sees exactly why nothing was built.
fn check_invariants(pubkey: &str, account: &Value, owner: &str) -> Result<Verified, String> {
    let program = match account.get("owner").and_then(Value::as_str) {
        Some(p) if p == TOKEN_PROGRAM || p == TOKEN_2022_PROGRAM => p.to_string(),
        Some(_) => return Err(format!("{}: not a token account", short(pubkey))),
        None => return Err(format!("{}: account not found", short(pubkey))),
    };
    let lamports = account
        .get("lamports")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{}: malformed account data", short(pubkey)))?;
    let info = &account["data"]["parsed"]["info"];
    if info.get("owner").and_then(Value::as_str) != Some(owner) {
        return Err(format!(
            "{}: owned by a different wallet — refusing",
            short(pubkey)
        ));
    }
    if info["tokenAmount"].get("amount").and_then(Value::as_str) != Some("0") {
        return Err(format!(
            "{}: balance is not zero — closing would require burning tokens; refusing",
            short(pubkey)
        ));
    }
    if info.get("state").and_then(Value::as_str) != Some("initialized") {
        return Err(format!(
            "{}: account is frozen — cannot close",
            short(pubkey)
        ));
    }
    if let Some(ca) = info.get("closeAuthority").and_then(Value::as_str) {
        if ca != owner {
            return Err(format!(
                "{}: close authority is a different key — refusing",
                short(pubkey)
            ));
        }
    }
    Ok(Verified {
        pubkey: pubkey.to_string(),
        lamports,
        token_program: program,
    })
}

/// Verify an explicit account list via `getMultipleAccounts`. All-or-nothing.
fn verify_explicit(
    rpc: &dyn Rpc,
    owner: &str,
    accounts: &[String],
) -> Result<Vec<Verified>, String> {
    for a in accounts {
        decode_key(a).map_err(|_| format!("invalid account address: {}", short(a)))?;
    }
    let result = rpc.call(
        "getMultipleAccounts",
        json!([accounts, { "encoding": "jsonParsed", "commitment": "confirmed" }]),
    )?;
    let values = result["value"]
        .as_array()
        .ok_or_else(|| "malformed RPC response: missing value array".to_string())?;
    if values.len() != accounts.len() {
        return Err("malformed RPC response: length mismatch".to_string());
    }
    let mut verified = Vec::new();
    let mut violations = Vec::new();
    for (pubkey, value) in accounts.iter().zip(values) {
        if value.is_null() {
            violations.push(format!("{}: account not found", short(pubkey)));
            continue;
        }
        match check_invariants(pubkey, value, owner) {
            Ok(v) => verified.push(v),
            Err(reason) => violations.push(reason),
        }
    }
    if !violations.is_empty() {
        return Err(format!(
            "refusing to build: {} of {} accounts failed verification. {}",
            violations.len(),
            accounts.len(),
            violations.join("; ")
        ));
    }
    Ok(verified)
}

/// No explicit list: scan both token programs and pick the top `max` empty
/// closeable accounts by rent.
fn pick_by_scan(rpc: &dyn Rpc, owner: &str, max: usize) -> Result<Vec<Verified>, String> {
    let mut found = Vec::new();
    for program in [TOKEN_PROGRAM, TOKEN_2022_PROGRAM] {
        let result = rpc.call(
            "getTokenAccountsByOwner",
            json!([
                owner,
                { "programId": program },
                { "encoding": "jsonParsed", "commitment": "confirmed" }
            ]),
        )?;
        let entries = result["value"]
            .as_array()
            .ok_or_else(|| "malformed RPC response: missing value array".to_string())?;
        for entry in entries {
            let pubkey = match entry.get("pubkey").and_then(Value::as_str) {
                Some(p) if decode_key(p).is_ok() => p,
                _ => continue, // fail closed: skip anything unparseable
            };
            if let Ok(v) = check_invariants(pubkey, &entry["account"], owner) {
                found.push(v);
            }
        }
    }
    found.sort_by(|a, b| b.lamports.cmp(&a.lamports).then(a.pubkey.cmp(&b.pubkey)));
    found.truncate(max);
    Ok(found)
}

/// Build the unsigned close transaction.
pub fn build(rpc: &dyn Rpc, req: &BuildRequest) -> Result<BuildOutput, String> {
    let owner_bytes = decode_key(&req.owner)
        .map_err(|_| "invalid owner address (must be base58, 32 bytes)".to_string())?;
    let max = req.max_accounts.clamp(1, MAX_CLOSES_PER_TX);

    let verified = match &req.accounts {
        Some(list) => {
            if list.is_empty() {
                return Err("accounts list is empty".to_string());
            }
            if list.len() > MAX_CLOSES_PER_TX {
                return Err(format!(
                    "refusing: {} accounts exceeds the per-transaction cap of {}",
                    list.len(),
                    MAX_CLOSES_PER_TX
                ));
            }
            verify_explicit(rpc, &req.owner, list)?
        }
        None => pick_by_scan(rpc, &req.owner, max)?,
    };
    if verified.is_empty() {
        return Err("no empty closeable token accounts found".to_string());
    }

    let bh_result = rpc.call("getLatestBlockhash", json!([{ "commitment": "confirmed" }]))?;
    let blockhash_str = bh_result["value"]["blockhash"]
        .as_str()
        .ok_or_else(|| "malformed RPC response: missing blockhash".to_string())?
        .to_string();
    let blockhash = decode_key(&blockhash_str)
        .map_err(|_| "malformed RPC response: invalid blockhash".to_string())?;
    let last_valid_block_height = bh_result["value"]["lastValidBlockHeight"].as_u64();

    let targets: Vec<CloseTarget> = verified
        .iter()
        .map(|v| {
            Ok(CloseTarget {
                pubkey: decode_key(&v.pubkey)?,
                token_program: decode_key(&v.token_program)?,
            })
        })
        .collect::<Result<_, String>>()?;

    let tx = build_close_tx(
        owner_bytes,
        &targets,
        blockhash,
        req.priority_fee_micro_lamports,
    )?;

    Ok(BuildOutput {
        tx_base64: base64_encode(&tx),
        reclaim_lamports: verified.iter().map(|v| v.lamports).sum(),
        closed: verified
            .into_iter()
            .map(|v| ClosedAccount {
                pubkey: v.pubkey,
                lamports: v.lamports,
            })
            .collect(),
        blockhash: blockhash_str,
        last_valid_block_height,
    })
}

/// Human-readable summary for the approval gate, plus the base64 payload.
pub fn render(out: &BuildOutput, owner: &str) -> String {
    let mut s = format!(
        "Unsigned transaction: close {} empty token account(s) owned by {}.\n\
         Reclaims ~{} SOL ({} lamports) — rent always returns to the owner; \
         this tool has no destination parameter.\n",
        out.closed.len(),
        short(owner),
        lamports_to_sol(out.reclaim_lamports),
        out.reclaim_lamports,
    );
    for (i, c) in out.closed.iter().enumerate() {
        s.push_str(&format!(
            "  {}. {}  {} SOL\n",
            i + 1,
            c.pubkey,
            lamports_to_sol(c.lamports)
        ));
    }
    s.push_str(&format!(
        "Blockhash {} — expires around block height {}; sign promptly or re-run to refresh.\n\
         unsigned_tx_base64:\n{}\n",
        short(&out.blockhash),
        out.last_valid_block_height
            .map(|h| h.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        out.tx_base64,
    ));
    s
}

/// Tiny base64 (standard alphabet, padded) — avoids another dependency.
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
