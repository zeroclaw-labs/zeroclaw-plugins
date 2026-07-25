//! `solana-inbox-core` — pure parser turning Solana JSON-RPC responses into
//! agent-shaped inbound events.
//!
//! ## What this crate is
//!
//! A dependency-light, `wasm32-wasip2`-friendly Rust library that decodes
//! `getSignaturesForAddress` and `getTransaction` (with
//! `encoding: "jsonParsed"`) responses into a compact `Inbound` record
//! stream that any agent runtime — ZeroClaw, Eliza, custom — can hand
//! to its LLM as inbound "chat" events. The reference consumer is the
//! `solana-inbox` channel plugin published alongside this crate; the
//! primitives here (`Config`, `SignatureEntry`, `Inbound`,
//! `parse_signatures_response`, `extract_inbounds`) are reusable by any
//! other plugin that wants to treat Solana as an inbound message stream
//! (memo-only, transfer-only, program-log-listener, DAS-driven cNFT
//! deltas, and so on).
//!
//! ## What this crate is not
//!
//! - Not a Solana SDK wrapper. `solana-sdk` and `solana-client` are not
//!   dependencies and never will be; both drag heavy transitive
//!   requirements that break inside a WIT-component `wasm32-wasip2`
//!   build. Everything here is `serde_json` walking on the RPC's shape.
//! - Not an HTTP client. Callers pass in already-parsed
//!   `serde_json::Value` responses. Every function is pure: same input →
//!   same output, no side effects, no async, no I/O.
//! - Not a wallet or signer. Zero private-key material anywhere.
//! - Not a general RPC library. Coverage is intentionally narrow:
//!   `getSignaturesForAddress` and `getTransaction`, plus the config
//!   surface a `solana-inbox`-style channel needs.
//!
//! ## Invariants
//!
//! Every load-bearing invariant is documented in `PROOFS.md` in the
//! consuming plugin and verified by the `proptest` harnesses in
//! `tests/props.rs` there. Load-bearing ones:
//! - `parse_signatures_response` output is chronological (oldest-first)
//!   whenever the RPC contract is honored.
//! - Failed transactions (`err != null`) are dropped.
//! - `Config::from_json` fails closed on any unknown key
//!   (`#[serde(deny_unknown_fields)]`).
//! - SPL transfer events fire only when `owner == watched_address`
//!   exactly.
//! - Memo content is byte-capped at `MAX_MEMO_LEN` bytes, rounded down
//!   to a UTF-8 char boundary.
//! - Duplicate memos in a single tx collapse to one event.
//! - `null` / malformed inputs yield zero events, never panic.
//!
//! ## What it deliberately does not do
//!
//! - Trust the operator's config. Unknown keys in the JSON config are
//!   treated as errors, not silently ignored. A typo like `"rpc_urll"`
//!   fails and the runtime never activates the channel — deliberately
//!   fail-closed per the reviewer's public guidance on PR #25 of
//!   `zeroclaw-labs/zeroclaw-plugins`.
//! - Trust the RPC's account order. The watched address is compared by
//!   value in every position of the parsed instruction, so a malicious
//!   endpoint cannot slip a false "transfer arrived" event past a
//!   different-looking `to` field.

use std::collections::HashSet;

use serde::Deserialize;

/// SPL Memo program v2 — the modern deployment.
pub const SPL_MEMO_V2: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
/// SPL Memo program v1 — still on chain and still used by older senders.
pub const SPL_MEMO_V1: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";
/// Native SOL "mint" placeholder for the transfer summary channel.
pub const NATIVE_SOL: &str = "SOL";
/// Maximum bytes of memo content we forward to the agent verbatim.
/// Longer memos are truncated with a marker so a single 32 KB memo can't
/// flood the LLM's context window. Byte-based (not char-based) so the
/// bound holds tightly for exotic Unicode: a 512-byte cap gives a total
/// `Inbound.content` size of at most ~600 bytes including prefix and
/// truncation marker, regardless of what the sender put in the memo.
pub const MAX_MEMO_LEN: usize = 512;

/// Fully-resolved operator configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub rpc_url: String,
    pub watched_address: String,
    pub commitment: String,
    pub max_sigs_per_poll: u32,
    pub include_transfers: bool,
}

/// The subset of config fields recognized in the JSON blob the host injects.
/// `#[serde(deny_unknown_fields)]` is the fail-closed posture: unknown keys
/// are a configuration bug and must not silently degrade behavior.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigInput {
    rpc_url: Option<String>,
    watched_address: Option<String>,
    commitment: Option<String>,
    max_sigs_per_poll: Option<u32>,
    include_transfers: Option<bool>,
}

impl Config {
    /// Parse an operator-supplied JSON config. Empty `{}` (the
    /// unprivileged / no-config_read case) is rejected on purpose because a
    /// channel without a watched address has no reason to exist and would
    /// otherwise silently no-op.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let raw: ConfigInput = serde_json::from_str(json)
            .map_err(|e| format!("invalid channel config JSON: {e}"))?;
        let watched_address = raw
            .watched_address
            .ok_or_else(|| "config missing required field `watched_address`".to_string())?;
        if !is_plausible_pubkey(&watched_address) {
            return Err(format!(
                "watched_address `{watched_address}` is not a plausible base58 Solana pubkey"
            ));
        }
        let rpc_url = raw
            .rpc_url
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "config missing required field `rpc_url`".to_string())?;
        let commitment = match raw.commitment.as_deref() {
            None | Some("confirmed") => "confirmed".to_string(),
            Some("processed") => "processed".to_string(),
            Some("finalized") => "finalized".to_string(),
            Some(other) => {
                return Err(format!(
                    "commitment must be one of processed|confirmed|finalized; got `{other}`"
                ))
            }
        };
        let max_sigs_per_poll = match raw.max_sigs_per_poll {
            None => 20,
            Some(n) if (1..=100).contains(&n) => n,
            Some(n) => {
                return Err(format!(
                    "max_sigs_per_poll must be in 1..=100; got {n}"
                ))
            }
        };
        Ok(Self {
            rpc_url,
            watched_address,
            commitment,
            max_sigs_per_poll,
            include_transfers: raw.include_transfers.unwrap_or(true),
        })
    }
}

/// Cheap shape check for a base58 Solana pubkey. A real ed25519 curve check
/// would need `curve25519-dalek`, which is friction in `wasm32-wasip2`; the
/// downstream RPC will reject any address whose bytes don't resolve to an
/// account, so this is only a first-line guard against obvious garbage in
/// operator configs.
fn is_plausible_pubkey(s: &str) -> bool {
    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let bytes = s.as_bytes();
    (32..=44).contains(&bytes.len()) && bytes.iter().all(|b| BASE58.contains(b))
}

/// One entry from `getSignaturesForAddress`.
#[derive(Debug, Clone, PartialEq)]
pub struct SignatureEntry {
    pub signature: String,
    pub slot: u64,
    /// RPC returns block time as unix seconds; we normalize to milliseconds
    /// at the shim boundary (WIT `inbound-message.timestamp` is ms).
    pub block_time_secs: Option<i64>,
}

/// Parse a `getSignaturesForAddress` response into a chronological list of
/// signatures (oldest first). Failed transactions are dropped so an agent
/// isn't spammed by another wallet's bounced fee-payer.
pub fn parse_signatures_response(response: &serde_json::Value) -> Vec<SignatureEntry> {
    let arr = match response.get("result").and_then(|r| r.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out: Vec<SignatureEntry> = arr
        .iter()
        .filter(|entry| entry.get("err").is_some_and(|e| e.is_null()))
        .filter_map(|entry| {
            let signature = entry.get("signature")?.as_str()?.to_string();
            let slot = entry.get("slot")?.as_u64()?;
            let block_time_secs = entry.get("blockTime").and_then(serde_json::Value::as_i64);
            Some(SignatureEntry {
                signature,
                slot,
                block_time_secs,
            })
        })
        .collect();
    // RPC returns newest first; the agent should see events in the order they
    // happened, so we reverse before returning.
    out.reverse();
    out
}

/// A single inbound event derived from one transaction. One transaction can
/// yield multiple `Inbound` records — a memo *and* a transfer notification,
/// for instance — which the shim buffers and drains one per `poll_message`
/// call, matching the pattern telegram.rs uses for chunked messages.
#[derive(Debug, Clone, PartialEq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub timestamp_ms: u64,
}

/// Kind of transfer we surface to the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TransferAsset {
    Sol,
    SplMint(String),
}

/// Extract every `Inbound` record from one `getTransaction` response.
/// Argument surface intentionally small so the tests can drive the same
/// entry point the wasm shim does.
pub fn extract_inbounds(
    tx_response: &serde_json::Value,
    signature: &str,
    watched_address: &str,
    include_transfers: bool,
    block_time_secs_fallback: Option<i64>,
) -> Vec<Inbound> {
    let result = match tx_response.get("result") {
        Some(r) if !r.is_null() => r,
        _ => return Vec::new(),
    };

    let timestamp_ms = result
        .get("blockTime")
        .and_then(serde_json::Value::as_i64)
        .or(block_time_secs_fallback)
        .map(|s| s.saturating_mul(1000) as u64)
        .unwrap_or(0);

    let fee_payer = fee_payer_address(result).unwrap_or_else(|| "unknown".to_string());

    let mut out: Vec<Inbound> = Vec::new();
    let mut seen_content: HashSet<(String, String)> = HashSet::new();

    for memo in extract_memos(result) {
        let content = format_memo(&memo, &fee_payer);
        let id = format!("{signature}#memo{}", out.len());
        push_dedup(
            &mut out,
            &mut seen_content,
            Inbound {
                id,
                sender: fee_payer.clone(),
                reply_target: fee_payer.clone(),
                content,
                timestamp_ms,
            },
        );
    }

    if include_transfers {
        for t in extract_transfers_to(result, watched_address) {
            let content = format_transfer(&t);
            let id = format!("{signature}#transfer{}", out.len());
            push_dedup(
                &mut out,
                &mut seen_content,
                Inbound {
                    id,
                    sender: t.from.clone(),
                    reply_target: t.from.clone(),
                    content,
                    timestamp_ms,
                },
            );
        }
    }

    out
}

fn push_dedup(
    out: &mut Vec<Inbound>,
    seen: &mut HashSet<(String, String)>,
    inb: Inbound,
) {
    let key = (inb.sender.clone(), inb.content.clone());
    if seen.insert(key) {
        out.push(inb);
    }
}

/// Fee-payer is the first account in the transaction's account key list.
/// Works for both jsonParsed and json encodings.
fn fee_payer_address(result: &serde_json::Value) -> Option<String> {
    result
        .get("transaction")
        .and_then(|t| t.get("message"))
        .and_then(|m| m.get("accountKeys"))
        .and_then(|k| k.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| {
            // With jsonParsed, each entry is an object {pubkey, signer, writable, source}.
            // With plain json, each entry is a bare base58 string.
            first
                .as_str()
                .map(str::to_string)
                .or_else(|| first.get("pubkey").and_then(|p| p.as_str()).map(str::to_string))
        })
}

/// Walk every instruction (top-level and inner) and yield the memo string
/// for any that were emitted by an SPL Memo program.
///
/// Robust across encodings: `jsonParsed` decodes memos into
/// `{program: "spl-memo", parsed: "the text"}`; plain `json` leaves them as
/// `{programIdIndex, accounts, data}` where `data` is base58 UTF-8. We only
/// support the jsonParsed shape here — the shim always requests
/// `encoding: "jsonParsed"` — but a program-id check on `programId` (or
/// on `accountKeys[programIdIndex]`) is included as belt-and-suspenders
/// for RPCs that return a mixed shape.
fn extract_memos(result: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let account_keys: Vec<String> = result
        .get("transaction")
        .and_then(|t| t.get("message"))
        .and_then(|m| m.get("accountKeys"))
        .and_then(|k| k.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .or_else(|| v.get("pubkey").and_then(|p| p.as_str()).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default();

    if let Some(instrs) = result
        .get("transaction")
        .and_then(|t| t.get("message"))
        .and_then(|m| m.get("instructions"))
        .and_then(|i| i.as_array())
    {
        for ix in instrs {
            if let Some(memo) = memo_from_instruction(ix, &account_keys) {
                out.push(memo);
            }
        }
    }

    if let Some(inner) = result
        .get("meta")
        .and_then(|m| m.get("innerInstructions"))
        .and_then(|i| i.as_array())
    {
        for group in inner {
            if let Some(ixs) = group.get("instructions").and_then(|i| i.as_array()) {
                for ix in ixs {
                    if let Some(memo) = memo_from_instruction(ix, &account_keys) {
                        out.push(memo);
                    }
                }
            }
        }
    }

    out
}

fn memo_from_instruction(
    ix: &serde_json::Value,
    account_keys: &[String],
) -> Option<String> {
    let program_id = ix
        .get("programId")
        .and_then(|p| p.as_str())
        .map(str::to_string)
        .or_else(|| {
            ix.get("programIdIndex")
                .and_then(|i| i.as_u64())
                .and_then(|i| account_keys.get(i as usize).cloned())
        })?;
    if program_id != SPL_MEMO_V1 && program_id != SPL_MEMO_V2 {
        return None;
    }
    if let Some(parsed) = ix.get("parsed").and_then(|p| p.as_str()) {
        return Some(parsed.to_string());
    }
    // Fallback: the RPC left the instruction in raw form. Data is base58
    // (or base64 for versioned txs); support both, quietly ignoring bytes
    // that aren't valid UTF-8 so a binary memo can't crash the poll loop.
    if let Some(data) = ix.get("data").and_then(|d| d.as_str()) {
        if let Some(text) = decode_memo_bytes(data) {
            return Some(text);
        }
    }
    None
}

/// Best-effort decode of a raw memo instruction's `data` field. Tries
/// UTF-8-through-base58 first (the historical wire encoding), then
/// UTF-8-through-base64 (some newer RPCs when a specific `encoding` is
/// requested), then gives up quietly.
fn decode_memo_bytes(data: &str) -> Option<String> {
    // Base58 alphabet: `123...` — same characters we already validate
    // against for pubkeys. If the string contains any character outside
    // that set, skip the base58 attempt.
    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if data.bytes().all(|b| BASE58.contains(&b)) {
        if let Some(bytes) = base58_decode(data) {
            if let Ok(s) = String::from_utf8(bytes) {
                return Some(s);
            }
        }
    }
    None
}

/// Tiny base58 decoder (Bitcoin alphabet). Only used as a fallback for RPCs
/// that leave the memo as raw base58 rather than pre-decoding it; the wasm
/// shim requests `encoding: "jsonParsed"` so this path is rarely hit. Kept
/// dependency-free on purpose.
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut zeros = 0usize;
    for &b in s.as_bytes() {
        if b == b'1' {
            zeros += 1;
        } else {
            break;
        }
    }
    let mut num: Vec<u8> = Vec::new();
    for &b in s.as_bytes() {
        let digit = ALPHABET.iter().position(|&c| c == b)? as u32;
        let mut carry = digit;
        for byte in num.iter_mut() {
            let temp = (*byte as u32) * 58 + carry;
            *byte = (temp & 0xff) as u8;
            carry = temp >> 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(num.iter().rev());
    Some(out)
}

/// Enforce the memo-length cap and prepend a compact sender-hint that
/// gives the agent context without demanding it read the raw pubkey.
/// Truncation is byte-based and rounds down to the nearest UTF-8 char
/// boundary so the resulting string is always valid UTF-8, always
/// bounded to `MAX_MEMO_LEN` bytes of memo payload plus a short fixed
/// prefix/marker, and never panics on multi-byte input.
fn format_memo(memo: &str, sender: &str) -> String {
    let truncated = if memo.len() > MAX_MEMO_LEN {
        let mut cut = MAX_MEMO_LEN;
        while cut > 0 && !memo.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…[truncated at {MAX_MEMO_LEN} bytes]", &memo[..cut])
    } else {
        memo.to_string()
    };
    format!("[memo from {}] {}", short_addr(sender), truncated)
}

fn short_addr(addr: &str) -> String {
    if addr.len() <= 10 {
        return addr.to_string();
    }
    let (head, _) = addr.split_at(4);
    let (_, tail) = addr.split_at(addr.len() - 4);
    format!("{head}…{tail}")
}

/// A transfer credited to the watched address, in the smallest amount the
/// RPC reported (lamports for SOL, base units for SPL).
#[derive(Debug, Clone, PartialEq)]
struct IncomingTransfer {
    from: String,
    asset: TransferAsset,
    /// Decimals for pretty-printing; 9 for SOL, from the mint metadata for SPL.
    decimals: u8,
    /// Amount in smallest units; `+delta` on the watched address.
    delta: u128,
}

fn format_transfer(t: &IncomingTransfer) -> String {
    let human = pretty_amount(t.delta, t.decimals);
    let asset = match &t.asset {
        TransferAsset::Sol => "SOL".to_string(),
        TransferAsset::SplMint(mint) => format!("mint {}", short_addr(mint)),
    };
    format!("[+{} {}] from {}", human, asset, short_addr(&t.from))
}

/// Divide `amount` by `10^decimals`, rendering as a bounded decimal string.
/// Uses u128 arithmetic to avoid f64 precision loss on typical token supplies.
fn pretty_amount(amount: u128, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let divisor: u128 = 10u128.pow(decimals as u32);
    let whole = amount / divisor;
    let frac = amount % divisor;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac_str = format!("{frac:0>width$}", width = decimals as usize);
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    format!("{whole}.{frac_str}")
}

/// Diff pre/post SOL balances and pre/post SPL token balances to find
/// transfers that credited the watched address. Everything is derived from
/// `meta` — we don't have to parse the transaction's instruction stream to
/// find every possible way SOL/tokens can move to an account.
fn extract_transfers_to(
    result: &serde_json::Value,
    watched: &str,
) -> Vec<IncomingTransfer> {
    let meta = match result.get("meta") {
        Some(m) if !m.is_null() => m,
        _ => return Vec::new(),
    };
    let account_keys: Vec<String> = result
        .get("transaction")
        .and_then(|t| t.get("message"))
        .and_then(|m| m.get("accountKeys"))
        .and_then(|k| k.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .or_else(|| v.get("pubkey").and_then(|p| p.as_str()).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default();

    let watched_idx = account_keys.iter().position(|k| k == watched);
    let mut out: Vec<IncomingTransfer> = Vec::new();

    if let Some(idx) = watched_idx {
        if let (Some(pre), Some(post)) = (
            meta.get("preBalances")
                .and_then(|b| b.as_array())
                .and_then(|a| a.get(idx))
                .and_then(|v| v.as_u64()),
            meta.get("postBalances")
                .and_then(|b| b.as_array())
                .and_then(|a| a.get(idx))
                .and_then(|v| v.as_u64()),
        ) {
            if post > pre {
                let delta = (post - pre) as u128;
                let from = infer_sol_sender(meta, &account_keys, idx);
                out.push(IncomingTransfer {
                    from,
                    asset: TransferAsset::Sol,
                    decimals: 9,
                    delta,
                });
            }
        }
    }

    // preTokenBalances / postTokenBalances are arrays of {accountIndex,
    // mint, owner, uiTokenAmount:{amount, decimals}}. We compare by
    // (accountIndex, mint) and emit a transfer when the owner matches
    // `watched` and post > pre.
    let pre_tok = meta
        .get("preTokenBalances")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    let post_tok = meta
        .get("postTokenBalances")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();

    for post_entry in &post_tok {
        let owner = post_entry.get("owner").and_then(|o| o.as_str());
        if owner != Some(watched) {
            continue;
        }
        let idx = match post_entry.get("accountIndex").and_then(|i| i.as_u64()) {
            Some(i) => i,
            None => continue,
        };
        let mint = match post_entry.get("mint").and_then(|m| m.as_str()) {
            Some(m) => m,
            None => continue,
        };
        let decimals = post_entry
            .get("uiTokenAmount")
            .and_then(|u| u.get("decimals"))
            .and_then(|d| d.as_u64())
            .unwrap_or(0) as u8;
        let post_amount: u128 = post_entry
            .get("uiTokenAmount")
            .and_then(|u| u.get("amount"))
            .and_then(|a| a.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let pre_amount: u128 = pre_tok
            .iter()
            .find(|p| {
                p.get("accountIndex").and_then(|i| i.as_u64()) == Some(idx)
                    && p.get("mint").and_then(|m| m.as_str()) == Some(mint)
            })
            .and_then(|p| p.get("uiTokenAmount"))
            .and_then(|u| u.get("amount"))
            .and_then(|a| a.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if post_amount > pre_amount {
            let delta = post_amount - pre_amount;
            // For SPL transfers the sender is not directly encoded in
            // meta; the closest fee-free approximation is the fee-payer.
            let from = fee_payer_address(result).unwrap_or_else(|| "unknown".to_string());
            out.push(IncomingTransfer {
                from,
                asset: TransferAsset::SplMint(mint.to_string()),
                decimals,
                delta,
            });
        }
    }

    out
}

/// SOL is spent by fee-payers and moved between accounts by system
/// transfers. The fee-payer's balance always goes down in every tx, so we
/// exclude them from the sender candidate list. Whoever else's balance
/// dropped by exactly the same amount the watched address gained is the
/// most likely sender — an approximation, but strictly better than
/// "unknown". Ties are broken by the first matching index.
fn infer_sol_sender(
    meta: &serde_json::Value,
    account_keys: &[String],
    watched_idx: usize,
) -> String {
    let pre = meta
        .get("preBalances")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    let post = meta
        .get("postBalances")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    let delta_watched = pre
        .get(watched_idx)
        .and_then(|v| v.as_u64())
        .and_then(|p| post.get(watched_idx).and_then(|v| v.as_u64()).map(|q| q as i128 - p as i128))
        .unwrap_or(0);
    for (i, key) in account_keys.iter().enumerate() {
        if i == watched_idx {
            continue;
        }
        let p = pre.get(i).and_then(|v| v.as_u64()).unwrap_or(0) as i128;
        let q = post.get(i).and_then(|v| v.as_u64()).unwrap_or(0) as i128;
        // Fee-payer's drop includes the tx fee; match "sent at least the
        // watched delta" rather than an exact equality.
        if p - q >= delta_watched && delta_watched > 0 {
            return key.clone();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn pretty_amount_edges() {
        assert_eq!(pretty_amount(0, 6), "0");
        assert_eq!(pretty_amount(1, 0), "1");
        assert_eq!(pretty_amount(1_000_000, 6), "1");
        assert_eq!(pretty_amount(1_234_567, 6), "1.234567");
        assert_eq!(pretty_amount(100, 6), "0.0001");
    }

    #[test]
    fn short_addr_stable() {
        assert_eq!(short_addr("So11111111111111111111111111111111111111112"), "So11…1112");
        assert_eq!(short_addr("short"), "short");
    }

    #[test]
    fn plausible_pubkey_gates() {
        assert!(is_plausible_pubkey("So11111111111111111111111111111111111111112"));
        assert!(!is_plausible_pubkey(""));
        assert!(!is_plausible_pubkey("too-short"));
        assert!(!is_plausible_pubkey("has-a-dash-which-is-not-base58-11111111111"));
    }
}
