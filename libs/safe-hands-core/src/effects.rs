//! What a transaction *does*, as opposed to what its instructions say.
//!
//! # Why syntax is not enough
//!
//! Safe Hands v0.1 authorizes by decoding: it recognizes `SystemProgram::Transfer`
//! and SPL `TransferChecked`, and hard-denies everything else. That is a sound
//! merchant desk and a poor firewall. An agent that wants to swap on a DEX, pay
//! an x402 invoice, stake, or call any program written after this repository
//! gets a flat refusal — not because the action is dangerous, but because the
//! decoder has never heard of it.
//!
//! Extending the decoder does not fix this. There is no finite list of programs,
//! and a decoder that understood all of them today would not understand
//! tomorrow's. Worse, instruction decoding is the *weaker* evidence: a program
//! can move tokens through CPI that its top-level instruction data never
//! mentions. A decoder sees a harmless-looking call; the vault empties anyway.
//!
//! So this module asks a different question. Not *"do I recognize this
//! instruction?"* but *"what does this transaction do to the balances I am
//! protecting?"* — which is answerable for any program, including ones nobody
//! has written yet, and which captures CPI effects that decoding cannot see.
//!
//! # How
//!
//! Fetch the pre-state of every writable account, simulate, read the post-state
//! the simulation reports, and diff them. SOL comes from `lamports`; SPL
//! balances come from the token-account layout, which Token-2022 shares for its
//! first 165 bytes. Movements are aggregated per `(owner, asset)` so a policy
//! can say *"this vault may lose at most 25 USDC"* without naming a single
//! instruction.
//!
//! # The honest limitation
//!
//! **Simulation is not execution.** A program can behave differently when it
//! actually runs — a different slot, a moved price, a front-run, or deliberate
//! detection of the simulation environment. Effect analysis therefore bounds
//! what a transaction *would* do against current state, not what it *will* do.
//!
//! Three things keep that from being a false promise. Simulation freshness is
//! already enforced (`simulation.max_slot_age`), so the observation cannot be
//! stale. The result still goes to a human or a multisig, which is where final
//! authority lives in this design regardless. And crucially, effect analysis
//! never *widens* what a known program may do — it only lets an operator admit
//! specific unfamiliar programs under an explicit spending bound. The worst case
//! of an admitted program behaving differently at execution is the cap the
//! operator wrote down.

use crate::decode::DecodedTx;
use crate::rpc::RpcTransport;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The classic SPL token account layout is 165 bytes. Token-2022 shares it and
/// appends extensions, so the same offsets read both.
const TOKEN_ACCOUNT_LEN: usize = 165;
/// `AccountState::Initialized`.
const TOKEN_STATE_INITIALIZED: u8 = 1;
/// `AccountState::Frozen`. Still a real account with a real balance.
const TOKEN_STATE_FROZEN: u8 = 2;

/// The key used for native SOL in a policy's outflow table.
///
/// Not a valid base58 pubkey, so it can never collide with a mint address.
pub const SOL: &str = "SOL";

/// The most writable accounts this will observe in one transaction.
///
/// A legacy message cannot exceed 256 accounts, and nodes bound the address
/// list `simulateTransaction` accepts. Anything past this is refused rather
/// than silently truncated: a partial view of the effects is worse than none,
/// because it looks complete.
pub const MAX_OBSERVED_ACCOUNTS: usize = 128;

/// One account balance at one point in time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balance {
    /// The account holding the value.
    pub address: String,
    /// `None` for native SOL, otherwise the mint.
    pub mint: Option<String>,
    /// Who the value belongs to: the token account's owner, or the account
    /// itself for a plain SOL balance.
    pub owner: String,
    pub raw: u128,
}

impl Balance {
    /// The policy table key for this balance's asset.
    pub fn asset(&self) -> &str {
        self.mint.as_deref().unwrap_or(SOL)
    }
}

/// A net movement of one asset, for one owner, across a whole transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Movement {
    pub owner: String,
    /// `"SOL"` or a mint address.
    pub asset: String,
    /// How much left, net of anything that arrived. Zero when the owner came
    /// out even or ahead.
    pub out_raw: u128,
    /// How much arrived, net of anything that left.
    pub in_raw: u128,
}

/// Balances before and after, and what that implies.
#[derive(Clone, Debug, Default)]
pub struct Effects {
    pub before: Vec<Balance>,
    pub after: Vec<Balance>,
}

impl Effects {
    /// Net movement per `(owner, asset)`, sorted, with no-op pairs dropped.
    ///
    /// Aggregating by owner rather than by account is what makes this hard to
    /// evade: moving value between two token accounts of the same wallet nets
    /// to zero, and moving it out shows up no matter which of the wallet's
    /// accounts it left from.
    pub fn movements(&self) -> Vec<Movement> {
        // i128 because an owner can both send and receive within one
        // transaction, and the intermediate can go either way.
        let mut totals: BTreeMap<(String, String), i128> = BTreeMap::new();
        for balance in &self.before {
            *totals
                .entry((balance.owner.clone(), balance.asset().to_string()))
                .or_default() -= balance.raw as i128;
        }
        for balance in &self.after {
            *totals
                .entry((balance.owner.clone(), balance.asset().to_string()))
                .or_default() += balance.raw as i128;
        }
        totals
            .into_iter()
            .filter(|(_, delta)| *delta != 0)
            .map(|((owner, asset), delta)| Movement {
                owner,
                asset,
                out_raw: if delta < 0 { (-delta) as u128 } else { 0 },
                in_raw: if delta > 0 { delta as u128 } else { 0 },
            })
            .collect()
    }

    /// Everything that left the given owners, in policy-table terms.
    pub fn outflows(&self, guarded: &BTreeSet<String>) -> Vec<Movement> {
        self.movements()
            .into_iter()
            .filter(|movement| movement.out_raw > 0 && guarded.contains(&movement.owner))
            .collect()
    }
}

/// Read an SPL / Token-2022 account: `(mint, owner, amount)`.
///
/// Returns `None` for anything that is not an initialized token account, so a
/// program-owned account that merely happens to be 165 bytes long is never
/// misread as holding tokens.
fn parse_token_account(data: &[u8]) -> Option<(String, String, u128)> {
    if data.len() < TOKEN_ACCOUNT_LEN {
        return None;
    }
    let state = data[108];
    if state != TOKEN_STATE_INITIALIZED && state != TOKEN_STATE_FROZEN {
        return None;
    }
    let mint = bs58::encode(&data[0..32]).into_string();
    let owner = bs58::encode(&data[32..64]).into_string();
    let amount = u64::from_le_bytes(data[64..72].try_into().ok()?);
    Some((mint, owner, amount as u128))
}

/// Turn one account's RPC representation into the balances it holds.
///
/// A token account yields two: its token balance, and its lamports — attributed
/// to the token account's *owner*, not to itself, so that draining an account's
/// rent shows up against the wallet that would lose it.
fn balances_of(address: &str, account: &Value) -> Vec<Balance> {
    if account.is_null() {
        // The account does not exist at this point in time. Absent is zero;
        // saying nothing would make a closed account look like no change.
        return vec![Balance {
            address: address.to_string(),
            mint: None,
            owner: address.to_string(),
            raw: 0,
        }];
    }
    let lamports = account.get("lamports").and_then(Value::as_u64).unwrap_or(0) as u128;
    let program = account.get("owner").and_then(Value::as_str).unwrap_or("");
    let data = account
        .get("data")
        .and_then(Value::as_array)
        .and_then(|parts| parts.first())
        .and_then(Value::as_str)
        .and_then(|encoded| crate::codec::base64_decode(encoded, 1 << 20).ok())
        .unwrap_or_default();

    let is_token_program =
        program == crate::crypto::TOKEN_PROGRAM || program == crate::crypto::TOKEN_2022_PROGRAM;
    match is_token_program
        .then(|| parse_token_account(&data))
        .flatten()
    {
        Some((mint, owner, amount)) => vec![
            Balance {
                address: address.to_string(),
                mint: Some(mint),
                owner: owner.clone(),
                raw: amount,
            },
            Balance {
                address: address.to_string(),
                mint: None,
                owner,
                raw: lamports,
            },
        ],
        None => vec![Balance {
            address: address.to_string(),
            mint: None,
            owner: address.to_string(),
            raw: lamports,
        }],
    }
}

/// Every account this transaction can write to, deduplicated and sorted.
///
/// Read-only accounts are excluded because the runtime cannot change them, so
/// including them would only add RPC weight. The fee payer is always writable
/// whether or not an instruction names it.
pub fn writable_accounts(tx: &DecodedTx) -> Vec<String> {
    let mut writable: BTreeSet<String> = BTreeSet::new();
    if let Some(payer) = tx.resolved_keys.first() {
        writable.insert(payer.clone());
    }
    for instruction in &tx.raw_instructions {
        for meta in &instruction.accounts {
            if meta.is_writable {
                writable.insert(meta.pubkey.to_string());
            }
        }
    }
    writable.into_iter().collect()
}

/// Observe what this transaction would do, by diffing pre-state against the
/// post-state a simulation reports.
///
/// Fails rather than guesses: if the pre-state cannot be fetched, if the node
/// declines to report post-state, or if the two views do not line up, this
/// returns an error and the caller treats the evidence as missing. A firewall
/// that assumes "probably nothing moved" is not a firewall.
pub fn observe(rpc: &dyn RpcTransport, tx: &DecodedTx) -> Result<Effects, String> {
    let addresses = writable_accounts(tx);
    if addresses.is_empty() {
        return Err("transaction writes to no accounts, which cannot be right".to_string());
    }
    if addresses.len() > MAX_OBSERVED_ACCOUNTS {
        return Err(format!(
            "transaction writes to {} accounts, more than the {MAX_OBSERVED_ACCOUNTS} this can \
             observe — refusing a partial view of the effects",
            addresses.len()
        ));
    }

    let before = fetch_pre_state(rpc, &addresses)?;
    let after = fetch_post_state(rpc, tx, &addresses)?;
    Ok(Effects { before, after })
}

fn fetch_pre_state(rpc: &dyn RpcTransport, addresses: &[String]) -> Result<Vec<Balance>, String> {
    let response = rpc.call(
        "getMultipleAccounts",
        json!([addresses, {"encoding": "base64", "commitment": "confirmed"}]),
    )?;
    let accounts = response
        .pointer("/result/value")
        .and_then(Value::as_array)
        .ok_or("getMultipleAccounts did not return an account array")?;
    if accounts.len() != addresses.len() {
        return Err(format!(
            "getMultipleAccounts returned {} accounts for {} addresses",
            accounts.len(),
            addresses.len()
        ));
    }
    Ok(addresses
        .iter()
        .zip(accounts)
        .flat_map(|(address, account)| balances_of(address, account))
        .collect())
}

fn fetch_post_state(
    rpc: &dyn RpcTransport,
    tx: &DecodedTx,
    addresses: &[String],
) -> Result<Vec<Balance>, String> {
    let transaction =
        crate::codec::unsigned_transaction_base64(&tx.serialized_message, tx.required_signatures)?;
    let response = rpc.call(
        "simulateTransaction",
        json!([transaction, {
            "encoding": "base64",
            "commitment": "confirmed",
            "sigVerify": false,
            "replaceRecentBlockhash": false,
            "accounts": {"encoding": "base64", "addresses": addresses}
        }]),
    )?;
    if let Some(error) = response.get("error").filter(|error| !error.is_null()) {
        return Err(format!("simulateTransaction JSON-RPC error: {error}"));
    }
    let value = response
        .pointer("/result/value")
        .ok_or("simulateTransaction missing result.value")?;
    match value.get("err") {
        Some(error) if !error.is_null() => {
            return Err(format!(
                "the transaction fails in simulation, so it has no effects to observe: {error}"
            ))
        }
        None => return Err("simulateTransaction missing result.value.err".to_string()),
        _ => {}
    }
    let accounts = value
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or("simulateTransaction did not report post-state accounts")?;
    if accounts.len() != addresses.len() {
        return Err(format!(
            "simulateTransaction reported {} accounts for {} addresses",
            accounts.len(),
            addresses.len()
        ));
    }
    Ok(addresses
        .iter()
        .zip(accounts)
        .flat_map(|(address, account)| balances_of(address, account))
        .collect())
}

#[cfg(test)]
mod tests;
