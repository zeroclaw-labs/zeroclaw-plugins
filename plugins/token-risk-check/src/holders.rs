//! Holder-concentration math over `getTokenLargestAccounts`.
//!
//! The RPC returns the 20 largest *token accounts*. Raw token-account numbers
//! overstate concentration whenever one wallet splits balances across
//! accounts, and understate the opposite; so when the RPC allows it we
//! resolve each account to its actual wallet owner (`getMultipleAccounts`)
//! and aggregate per owner before ranking. When owner resolution is
//! unavailable the math falls back to per-token-account shares and the
//! report says which basis was used. Either way pools, exchange vaults and
//! treasuries can still aggregate many users — the report keeps saying that
//! too.

use std::collections::HashMap;

use crate::rpc::LargestAccount;

/// Wallet owners that are well-known AMM vault authorities. A token account
/// owned by one of these is pool liquidity, not a person; counting it as a
/// "whale" is the single biggest false positive in naive concentration
/// checks. Conservative by design: only universally-known constants belong
/// here — an unknown pool simply stays in the whale math, which can only
/// overstate risk, never hide it.
pub const KNOWN_AMM_AUTHORITIES: &[&str] = &[
    // Raydium AMM v4 vault authority — owns the token vaults of the bulk of
    // Raydium liquidity pools.
    "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",
];

#[derive(Debug, Clone)]
pub struct Concentration {
    pub top1_pct: f64,
    pub top5_pct: f64,
    pub top10_pct: f64,
    /// (address, share-of-supply %) for the single largest holder bucket.
    pub largest: Option<(String, f64)>,
    /// True when buckets are aggregated by wallet owner rather than by raw
    /// token account.
    pub owner_resolved: bool,
    /// Share of supply sitting in known DEX pool vaults, excluded from the
    /// whale metrics above. Only detectable on the owner-resolved path.
    pub pool_share_pct: Option<f64>,
}

/// Compute shares of total supply per token account (no owner aggregation).
/// Returns `None` when supply is zero or the account list is empty (both real
/// cases: pre-launch mints, burned supply).
pub fn concentration(accounts: &[LargestAccount], supply: u128) -> Option<Concentration> {
    let buckets: Vec<(String, u128)> = accounts
        .iter()
        .map(|a| (a.address.clone(), a.amount))
        .collect();
    ranked(buckets, supply, false, None)
}

/// Compute shares of total supply aggregated by wallet owner. `owners[i]` is
/// the resolved owner of `accounts[i]`; accounts whose owner could not be
/// resolved stay in their own bucket keyed by token-account address, which
/// can only *understate* aggregation, never inflate a holder.
pub fn concentration_by_owner(
    accounts: &[LargestAccount],
    owners: &[Option<String>],
    supply: u128,
) -> Option<Concentration> {
    if owners.len() != accounts.len() {
        // Malformed pairing: refuse to guess, fall back to account basis.
        return concentration(accounts, supply);
    }
    let mut by_owner: HashMap<String, u128> = HashMap::new();
    for (account, owner) in accounts.iter().zip(owners) {
        let key = owner.clone().unwrap_or_else(|| account.address.clone());
        *by_owner.entry(key).or_insert(0) += account.amount;
    }

    // Split out buckets owned by known AMM vault authorities: pool liquidity
    // is reported separately, not as a whale.
    let mut pool_amount: u128 = 0;
    let mut holders: Vec<(String, u128)> = Vec::new();
    for (owner, amount) in by_owner {
        if KNOWN_AMM_AUTHORITIES.contains(&owner.as_str()) {
            pool_amount += amount;
        } else {
            holders.push((owner, amount));
        }
    }
    let pool_share_pct =
        (supply > 0 && pool_amount > 0).then(|| (pool_amount as f64 / supply as f64) * 100.0);

    if holders.is_empty() {
        // Every sampled account was a pool vault: no whales to rank, but the
        // pool share is still worth reporting.
        return pool_share_pct.map(|p| Concentration {
            top1_pct: 0.0,
            top5_pct: 0.0,
            top10_pct: 0.0,
            largest: None,
            owner_resolved: true,
            pool_share_pct: Some(p),
        });
    }
    ranked(holders, supply, true, pool_share_pct)
}

fn ranked(
    mut buckets: Vec<(String, u128)>,
    supply: u128,
    owner_resolved: bool,
    pool_share_pct: Option<f64>,
) -> Option<Concentration> {
    if supply == 0 || buckets.is_empty() {
        return None;
    }
    buckets.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let pct = |take: usize| -> f64 {
        let sum: u128 = buckets.iter().take(take).map(|(_, amount)| amount).sum();
        // f64 keeps ample precision for a percentage readout.
        (sum as f64 / supply as f64) * 100.0
    };

    let largest = buckets
        .first()
        .map(|(addr, amount)| (addr.clone(), (*amount as f64 / supply as f64) * 100.0));

    Some(Concentration {
        top1_pct: pct(1),
        top5_pct: pct(5),
        top10_pct: pct(10),
        largest,
        owner_resolved,
        pool_share_pct,
    })
}
