//! Pure core of the `payment-watch` tool: given a Solana Pay reference key
//! (and optionally the expected amount/mint/recipient), decide whether the
//! payment landed. Read-only: two bounded RPC calls, no keys, no state.
//!
//! How it works: Solana Pay attaches the reference as a read-only non-signer
//! account on the transfer instruction, so validators index the transaction
//! under it. `getSignaturesForAddress(reference)` finds candidate signatures;
//! `getTransaction` confirms success and extracts who paid what. The output
//! is one short line, not the RPC's 40KB.

use std::collections::BTreeMap;

use serde::Deserialize;
use solana_core_wasi::amount::{from_base_units, to_base_units};
use solana_core_wasi::pubkey::Pubkey;
use solana_core_wasi::rpc;

/// Tool arguments. The reference is the only required field; expectations
/// tighten the verdict when supplied.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Args {
    /// Base58 32-byte Solana Pay reference key to look up.
    pub reference: String,
    /// Expected decimal amount (user units). When set with `mint`, the
    /// verdict is PAID only if a matching transfer of at least this amount
    /// confirmed.
    #[serde(default)]
    pub expected_amount: Option<String>,
    /// Base58 mint the payment should arrive in ("SOL" not supported here:
    /// reference-tagged native transfers are rare; SPL is the terminal flow).
    #[serde(default)]
    pub mint: Option<String>,
    /// Expected recipient wallet (owner of the receiving ATA).
    #[serde(default)]
    pub recipient: Option<String>,
    /// Host-injected operator config (rpc_url). Callers cannot spoof it.
    #[serde(rename = "__config", default)]
    pub config: BTreeMap<String, String>,
}

/// Errors: every branch fails closed to "not confirmed".
#[derive(Debug, PartialEq, Eq)]
pub enum WatchError {
    BadArgs(String),
    Config(String),
    Rpc(String),
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatchError::BadArgs(e) => write!(f, "bad arguments: {e}"),
            WatchError::Config(e) => write!(f, "config error: {e}"),
            WatchError::Rpc(e) => write!(f, "rpc error: {e}"),
        }
    }
}

/// Recognized config keys. Only the transport endpoint lives in config; the
/// tool takes no policy because it moves nothing.
const KNOWN_KEYS: &[&str] = &["rpc_url"];

fn rpc_url(config: &BTreeMap<String, String>) -> Result<String, WatchError> {
    for k in config.keys() {
        if !KNOWN_KEYS.contains(&k.as_str()) {
            return Err(WatchError::Config(format!(
                "unknown config key '{k}' — refusing to guess (fail closed)"
            )));
        }
    }
    let url = config
        .get("rpc_url")
        .ok_or_else(|| WatchError::Config("rpc_url is required".into()))?
        .trim()
        .to_string();
    if !url.starts_with("https://") {
        return Err(WatchError::Config(
            "rpc_url must be an https:// endpoint".into(),
        ));
    }
    Ok(url)
}

/// Network lookups the shim satisfies (same shape as spl-transfer-build).
pub trait Lookups {
    fn rpc(&mut self, body: &str) -> Result<String, String>;
}

/// The verdict, shaped for a chat window.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A confirmed transaction under the reference satisfied expectations.
    Paid { signature: String, summary: String },
    /// Signatures exist but none satisfied the expectations.
    NotSatisfied { reason: String },
    /// No transaction under this reference yet.
    NotSeen,
}

/// Run the watch. Bounded: looks at up to `SIG_LIMIT` newest signatures and
/// inspects at most `TX_INSPECT_LIMIT` successful ones.
pub fn watch(args: &Args, lookups: &mut dyn Lookups) -> Result<Verdict, WatchError> {
    const SIG_LIMIT: u16 = 10;
    const TX_INSPECT_LIMIT: usize = 3;

    let url_check = rpc_url(&args.config)?; // fail closed before any parsing
    let _ = url_check;

    let reference = Pubkey::parse(&args.reference)
        .map_err(|e| WatchError::BadArgs(format!("reference: {e}")))?;

    // Validate expectations before spending RPC calls. Each one is a filter of
    // its own: the reference travels in a public payment request, so anyone can
    // tag a transfer with it, and a caller that names only the mint still needs
    // the mint checked.
    if args.expected_amount.is_some() && args.mint.is_none() {
        return Err(WatchError::BadArgs(
            "expected_amount requires mint (decimals come from the chain)".into(),
        ));
    }
    if let Some(m) = &args.mint {
        Pubkey::parse(m).map_err(|e| WatchError::BadArgs(format!("mint: {e}")))?;
    }
    if let Some(r) = &args.recipient {
        Pubkey::parse(r).map_err(|e| WatchError::BadArgs(format!("recipient: {e}")))?;
    }

    let raw = lookups
        .rpc(&rpc::get_signatures_for_address(
            &reference, SIG_LIMIT, None,
        ))
        .map_err(WatchError::Rpc)?;
    let sigs = rpc::parse_signatures(&raw).map_err(|e| WatchError::Rpc(e.to_string()))?;
    if sigs.is_empty() {
        return Ok(Verdict::NotSeen);
    }

    let mut last_reason = String::new();
    for entry in sigs
        .iter()
        .filter(|s| s.err.is_none())
        .take(TX_INSPECT_LIMIT)
    {
        let raw_tx = lookups
            .rpc(&rpc::get_transaction(&entry.signature))
            .map_err(WatchError::Rpc)?;
        let deltas = match rpc::parse_token_deltas(&raw_tx) {
            Ok(d) => d,
            Err(e) => {
                last_reason = e.to_string();
                continue;
            }
        };
        // Match expectations against positive deltas.
        for d in &deltas {
            if let Some(mint) = &args.mint {
                if &d.mint != mint {
                    last_reason = format!("transfer was in mint {}, expected {}", d.mint, mint);
                    continue;
                }
            }
            if let Some(amt) = &args.expected_amount {
                let want = to_base_units(amt, d.decimals)
                    .map_err(|e| WatchError::BadArgs(format!("expected_amount: {e}")))?;
                if d.received_base_units < want {
                    last_reason = format!(
                        "received {} of mint {}, expected at least {}",
                        from_base_units(d.received_base_units, d.decimals),
                        d.mint,
                        amt
                    );
                    continue;
                }
            }
            if let Some(recip) = &args.recipient {
                if &d.owner != recip {
                    last_reason = format!(
                        "funds landed with {}, expected recipient {}",
                        d.owner, recip
                    );
                    continue;
                }
            }
            let status = entry.confirmation_status.as_deref().unwrap_or("confirmed");
            return Ok(Verdict::Paid {
                signature: entry.signature.clone(),
                summary: format!(
                    "PAID: {} of mint {} to {} — sig {}… slot {} ({})",
                    from_base_units(d.received_base_units, d.decimals),
                    d.mint,
                    d.owner,
                    short(&entry.signature, 12),
                    entry.slot,
                    status
                ),
            });
        }
        if deltas.is_empty() {
            last_reason = "transaction confirmed but carried no token transfer".into();
        }
    }
    Ok(Verdict::NotSatisfied {
        reason: if last_reason.is_empty() {
            "transactions found under the reference, but none confirmed successfully".into()
        } else {
            last_reason
        },
    })
}

/// The first `n` characters of a string the endpoint chose. Slicing by byte
/// index panics when the index lands inside a multi-byte character, and a
/// signature is whatever the response carried, not necessarily base58: one
/// hostile getSignaturesForAddress reply was enough to take the component down.
fn short(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((at, _)) => &s[..at],
        None => s,
    }
}

/// Entry point the shim calls: JSON in, one-line JSON out.
pub fn run(raw_args: &str, lookups: &mut dyn Lookups) -> Result<String, WatchError> {
    let args: Args =
        serde_json::from_str(raw_args).map_err(|e| WatchError::BadArgs(e.to_string()))?;
    let verdict = watch(&args, lookups)?;
    let (paid, line, sig) = match verdict {
        Verdict::Paid { signature, summary } => (true, summary, Some(signature)),
        Verdict::NotSatisfied { reason } => (false, format!("NOT CONFIRMED: {reason}"), None),
        Verdict::NotSeen => (
            false,
            "NOT SEEN: no transaction under this reference yet".to_string(),
            None,
        ),
    };
    Ok(serde_json::json!({ "paid": paid, "summary": line, "signature": sig }).to_string())
}
