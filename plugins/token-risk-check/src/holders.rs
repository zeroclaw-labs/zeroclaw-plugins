//! Holder-concentration math over `getTokenLargestAccounts`.
//!
//! The RPC returns the 20 largest *token accounts*, which may be exchange
//! vaults, LP pools, or treasuries — not necessarily individuals. The report
//! says so explicitly; the numbers are still the fastest honest signal for
//! "one wallet can nuke this market".

use crate::rpc::LargestAccount;

#[derive(Debug, Clone)]
pub struct Concentration {
    pub top1_pct: f64,
    pub top5_pct: f64,
    pub top10_pct: f64,
    /// (address, share-of-supply %) for the single largest account.
    pub largest: Option<(String, f64)>,
}

/// Compute shares of total supply. Returns `None` when supply is zero or the
/// account list is empty (both real cases: pre-launch mints, burned supply).
pub fn concentration(accounts: &[LargestAccount], supply: u128) -> Option<Concentration> {
    if supply == 0 || accounts.is_empty() {
        return None;
    }
    // The RPC already sorts descending, but don't rely on it.
    let mut amounts: Vec<&LargestAccount> = accounts.iter().collect();
    amounts.sort_by_key(|a| std::cmp::Reverse(a.amount));

    let pct = |take: usize| -> f64 {
        let sum: u128 = amounts.iter().take(take).map(|a| a.amount).sum();
        // f64 keeps ample precision for a percentage readout.
        (sum as f64 / supply as f64) * 100.0
    };

    let largest = amounts
        .first()
        .map(|a| (a.address.clone(), (a.amount as f64 / supply as f64) * 100.0));

    Some(Concentration {
        top1_pct: pct(1),
        top5_pct: pct(5),
        top10_pct: pct(10),
        largest,
    })
}
