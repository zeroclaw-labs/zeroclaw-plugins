//! Pure logic for squads-watch: the treasury heartbeat.
//!
//! Reads the configured multisig, scans proposals since a caller-supplied
//! cursor, and returns compact status lines plus the indices still waiting on
//! votes. Designed to run on a ZeroClaw SOP schedule: the agent keeps the
//! cursor between runs, pings members in the channel when something is
//! pending, and stays silent when nothing changed.
//!
//! Strictly read only: the multisig address comes from config, never from the
//! model, so a watcher can never be pointed at an attacker's treasury by an
//! injected message. The cursor is trusted pagination state the SOP loop
//! persists in durable agent memory; it must not be sourced from message
//! content, since a poisoned cursor could skip a pending proposal. As a
//! backstop the receipt names any range the cursor skipped, so an all-clear is
//! never implicitly claimed over unscanned proposals.

use quorum_core::pubkey::Pubkey;
use quorum_core::receipt::Receipt;
use quorum_core::rpc::{get_account_base64, get_multiple_accounts_base64, Rpc};
use quorum_core::squads::{decode_multisig, decode_proposal, proposal_pda, ProposalStatus};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct WatchArgs {
    /// Last transaction index already reported; scan starts after it.
    #[serde(default)]
    pub cursor: Option<u64>,
    /// Maximum proposals to report in one call (default 10, cap 20).
    #[serde(default)]
    pub limit: Option<u64>,
}

const DEFAULT_LOOKBACK: u64 = 5;

pub fn run(rpc: &dyn Rpc, cfg: &Value, args: &WatchArgs) -> Result<String, String> {
    let multisig_addr = cfg
        .get("multisig")
        .and_then(|v| v.as_str())
        .ok_or("config missing required 'multisig'")
        .and_then(|s| Pubkey::from_base58(s).map_err(|_| "config multisig is not a valid address"))
        .map_err(String::from)?;

    let ms_data = get_account_base64(rpc, &multisig_addr.to_base58())?
        .ok_or("multisig account not found on chain")?;
    let ms = decode_multisig(&ms_data)?;

    let ti = ms.transaction_index;
    let limit = args.limit.unwrap_or(10).clamp(1, 20);
    // The scan start is a caller-supplied cursor. It is trusted pagination
    // state that the SOP loop must persist in durable agent memory, NOT read
    // from message content: a cursor set from an injected message could skip
    // past a pending proposal. Clamp a nonsensical beyond-chain cursor to the
    // current index, and below the receipt states the exact range scanned so a
    // skipped window is visible rather than silently trusted.
    let from = args
        .cursor
        .unwrap_or_else(|| ti.saturating_sub(DEFAULT_LOOKBACK))
        .min(ti);

    let mut r = Receipt::new();
    r.line(format!(
        "Multisig {}: {} proposals total, threshold {}/{}, time lock {}s",
        multisig_addr.short(),
        ti,
        ms.threshold,
        ms.members.len(),
        ms.time_lock
    ));

    if from >= ti {
        r.line("No new activity since last check.");
        return Ok(json!({
            "summary": r.render(),
            "next_cursor": ti,
            "pending": [],
        })
        .to_string());
    }

    let first = from + 1;
    let last = ti.min(from + limit);
    // If the cursor skips over non-stale proposals (index > stale), they could
    // still be pending; name the skipped range so an all-clear is never
    // implicitly claimed over unscanned proposals.
    if from > ms.stale_transaction_index {
        r.line(format!(
            "scanning #{first}..#{last}; proposals #{}..#{from} below the cursor were not checked",
            ms.stale_transaction_index + 1
        ));
    }
    let indices: Vec<u64> = (first..=last).collect();
    let addrs: Vec<String> = indices
        .iter()
        .map(|i| proposal_pda(&multisig_addr, *i).0.to_base58())
        .collect();
    let accounts = get_multiple_accounts_base64(rpc, &addrs)?;

    let mut pending: Vec<u64> = Vec::new();
    for (i, acct) in indices.iter().zip(accounts.iter()) {
        let stale = *i <= ms.stale_transaction_index;
        match acct {
            None => r.line(format!("#{i}: transaction filed, no proposal opened yet")),
            Some(bytes) => match decode_proposal(bytes) {
                Ok(p) => {
                    let mut line = match &p.status {
                        ProposalStatus::Active(_) => {
                            pending.push(*i);
                            format!(
                                "#{i}: Active, {} of {} approvals",
                                p.approved.len(),
                                ms.threshold
                            )
                        }
                        ProposalStatus::Approved(_) => {
                            pending.push(*i);
                            format!("#{i}: Approved, awaiting execution")
                        }
                        s => format!("#{i}: {}", s.label()),
                    };
                    if stale {
                        line.push_str(" (stale)");
                    }
                    r.line(line);
                }
                Err(e) => r.line(format!("#{i}: undecodable proposal ({e})")),
            },
        }
    }
    if last < ti {
        r.line(format!(
            "{} more not shown; call again with cursor={last}",
            ti - last
        ));
    }
    if !pending.is_empty() {
        r.line(format!(
            "Action needed: {} proposal(s) waiting on members",
            pending.len()
        ));
    }

    Ok(json!({
        "summary": r.render(),
        "next_cursor": last,
        "pending": pending,
    })
    .to_string())
}
