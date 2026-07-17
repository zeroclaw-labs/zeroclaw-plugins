//! Fail-closed operator policy: the piece the LLM cannot talk its way past.
//!
//! Policy lives in the operator's config section (host-injected under
//! `__config`; the host strips any caller-supplied `__config`, so a prompt
//! cannot spoof it). Parsing is strict: unknown keys are rejected so a
//! misspelled `max_amout` can never silently disable a cap. Empty or missing
//! allowlists DENY everything: the operator must opt each recipient and mint
//! in explicitly.

use std::collections::BTreeMap;

use crate::amount::to_base_units;
use crate::pubkey::Pubkey;

/// A parsed, validated transfer policy.
#[derive(Debug, PartialEq, Eq)]
pub struct TransferPolicy {
    /// Base58 wallet addresses allowed as recipients. Empty = deny all.
    pub recipient_allowlist: Vec<Pubkey>,
    /// Allowed mints with per-transfer caps in base units. Key "SOL" covers
    /// native transfers with the cap in lamports. Empty = deny all.
    pub mint_caps: BTreeMap<String, u64>,
    /// The decimals each cap entry was written at, kept so amount parsing and
    /// the on-chain decimals cross-check can use them.
    cap_decimals: BTreeMap<String, u8>,
    /// RPC endpoint. Operator-controlled; the tool never accepts an RPC URL
    /// as a call argument.
    pub rpc_url: String,
    /// Optional durable nonce account (base58). When set, transactions are
    /// built nonce-first and survive the approval queue.
    pub nonce_account: Option<Pubkey>,
}

impl TransferPolicy {
    /// The decimals the operator's cap entry for `mint_key` was written at.
    pub fn cap_decimals(&self, mint_key: &str) -> Option<u8> {
        self.cap_decimals.get(mint_key).copied()
    }
}

/// Errors from policy parsing. Every branch fails closed: no policy, no
/// transfer.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    UnknownKey(String),
    MissingRpcUrl,
    BadRpcUrl(String),
    BadRecipient(String),
    BadMint(String),
    BadCap(String),
    BadNonceAccount(String),
    EmptyAllowlist,
    EmptyMintCaps,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::UnknownKey(k) => {
                write!(
                    f,
                    "unknown config key '{k}' — refusing to guess (fail closed)"
                )
            }
            PolicyError::MissingRpcUrl => write!(f, "rpc_url is required"),
            PolicyError::BadRpcUrl(u) => write!(f, "rpc_url must be https, got '{u}'"),
            PolicyError::BadRecipient(r) => {
                write!(f, "allow_recipients entry '{r}' is not a valid pubkey")
            }
            PolicyError::BadMint(m) => write!(f, "mint '{m}' is not a valid pubkey"),
            PolicyError::BadCap(c) => write!(f, "cap '{c}' is not a valid amount"),
            PolicyError::BadNonceAccount(n) => {
                write!(f, "nonce_account '{n}' is not a valid pubkey")
            }
            PolicyError::EmptyAllowlist => {
                write!(f, "allow_recipients is empty: all transfers denied until the operator adds recipients")
            }
            PolicyError::EmptyMintCaps => {
                write!(
                    f,
                    "no mint caps configured: all transfers denied until the operator adds caps"
                )
            }
        }
    }
}

/// Recognized config keys. `caps` maps a mint symbol entry
/// `<base58-mint-or-SOL>:<decimal-amount>:<decimals>` per line.
const KNOWN_KEYS: &[&str] = &["rpc_url", "allow_recipients", "caps", "nonce_account"];

/// Parse policy out of the flat string map ZeroClaw injects as `__config`.
///
/// Formats (all comma-separated in single config values, keeping to the
/// flat-string shape the host injects):
/// - `allow_recipients = "addr1,addr2"`
/// - `caps = "SOL:0.1:9,EPjF...t1v:25:6"` (mint : max per-transfer : decimals)
pub fn parse_policy(config: &BTreeMap<String, String>) -> Result<TransferPolicy, PolicyError> {
    for k in config.keys() {
        if !KNOWN_KEYS.contains(&k.as_str()) {
            return Err(PolicyError::UnknownKey(k.clone()));
        }
    }
    let rpc_url = config
        .get("rpc_url")
        .ok_or(PolicyError::MissingRpcUrl)?
        .trim()
        .to_string();
    if !rpc_url.starts_with("https://") {
        return Err(PolicyError::BadRpcUrl(rpc_url));
    }

    let mut recipient_allowlist = Vec::new();
    if let Some(raw) = config.get("allow_recipients") {
        for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            recipient_allowlist
                .push(Pubkey::parse(entry).map_err(|_| PolicyError::BadRecipient(entry.into()))?);
        }
    }
    if recipient_allowlist.is_empty() {
        return Err(PolicyError::EmptyAllowlist);
    }

    let mut mint_caps = BTreeMap::new();
    let mut cap_decimals = BTreeMap::new();
    if let Some(raw) = config.get("caps") {
        for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let parts: Vec<&str> = entry.split(':').collect();
            if parts.len() != 3 {
                return Err(PolicyError::BadCap(entry.into()));
            }
            let (mint, amount, decimals) = (parts[0], parts[1], parts[2]);
            if mint != "SOL" {
                Pubkey::parse(mint).map_err(|_| PolicyError::BadMint(mint.into()))?;
            }
            let decimals: u8 = decimals
                .parse()
                .map_err(|_| PolicyError::BadCap(entry.into()))?;
            if mint == "SOL" && decimals != 9 {
                return Err(PolicyError::BadCap(format!("{entry} (SOL is 9 decimals)")));
            }
            let base =
                to_base_units(amount, decimals).map_err(|_| PolicyError::BadCap(entry.into()))?;
            mint_caps.insert(mint.to_string(), base);
            cap_decimals.insert(mint.to_string(), decimals);
        }
    }
    if mint_caps.is_empty() {
        return Err(PolicyError::EmptyMintCaps);
    }

    let nonce_account = match config
        .get("nonce_account")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(s) => Some(Pubkey::parse(s).map_err(|_| PolicyError::BadNonceAccount(s.into()))?),
        None => None,
    };

    Ok(TransferPolicy {
        recipient_allowlist,
        mint_caps,
        cap_decimals,
        rpc_url,
        nonce_account,
    })
}

/// A transfer the policy either admits or refuses. All checks fail closed.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyVerdict {
    Allowed,
    RecipientNotAllowed,
    MintNotAllowed,
    OverCap { cap_base_units: u64 },
}

impl TransferPolicy {
    /// Check a proposed transfer. `mint_key` is "SOL" or the base58 mint.
    pub fn check(
        &self,
        recipient: &Pubkey,
        mint_key: &str,
        amount_base_units: u64,
    ) -> PolicyVerdict {
        if !self.recipient_allowlist.iter().any(|p| p == recipient) {
            return PolicyVerdict::RecipientNotAllowed;
        }
        match self.mint_caps.get(mint_key) {
            None => PolicyVerdict::MintNotAllowed,
            Some(&cap) if amount_base_units > cap => PolicyVerdict::OverCap {
                cap_base_units: cap,
            },
            Some(_) => PolicyVerdict::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    const RECIP: &str = "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn valid() -> BTreeMap<String, String> {
        cfg(&[
            ("rpc_url", "https://api.devnet.solana.com"),
            ("allow_recipients", RECIP),
            ("caps", "SOL:0.1:9"),
        ])
    }

    #[test]
    fn parses_valid_policy() {
        let p = parse_policy(&valid()).unwrap();
        assert_eq!(p.recipient_allowlist.len(), 1);
        assert_eq!(p.mint_caps["SOL"], 100_000_000);
        assert_eq!(p.nonce_account, None);
    }

    #[test]
    fn unknown_key_fails_closed() {
        let mut c = valid();
        c.insert("max_amout".into(), "999".into()); // the maintainer's own example typo
        assert_eq!(
            parse_policy(&c),
            Err(PolicyError::UnknownKey("max_amout".into()))
        );
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let mut c = valid();
        c.insert("allow_recipients".into(), "".into());
        assert_eq!(parse_policy(&c), Err(PolicyError::EmptyAllowlist));
        c.remove("allow_recipients");
        assert_eq!(parse_policy(&c), Err(PolicyError::EmptyAllowlist));
    }

    #[test]
    fn missing_caps_deny_all() {
        let mut c = valid();
        c.remove("caps");
        assert_eq!(parse_policy(&c), Err(PolicyError::EmptyMintCaps));
    }

    #[test]
    fn rejects_http_rpc() {
        let mut c = valid();
        c.insert("rpc_url".into(), "http://evil.example".into());
        assert!(matches!(parse_policy(&c), Err(PolicyError::BadRpcUrl(_))));
    }

    #[test]
    fn cap_enforcement() {
        let mut c = valid();
        c.insert("caps".into(), format!("{USDC}:25:6"));
        let p = parse_policy(&c).unwrap();
        let recip = Pubkey::parse(RECIP).unwrap();
        assert_eq!(p.check(&recip, USDC, 25_000_000), PolicyVerdict::Allowed);
        assert_eq!(
            p.check(&recip, USDC, 25_000_001),
            PolicyVerdict::OverCap {
                cap_base_units: 25_000_000
            }
        );
        assert_eq!(p.check(&recip, "SOL", 1), PolicyVerdict::MintNotAllowed);
        assert_eq!(
            p.check(&Pubkey([3; 32]), USDC, 1),
            PolicyVerdict::RecipientNotAllowed
        );
    }

    #[test]
    fn bad_entries_reject() {
        for (k, v) in [
            ("allow_recipients", "not-a-key"),
            ("caps", "SOL:abc:9"),
            ("caps", "SOL:1"),
            ("caps", "badmint:1:6"),
            ("nonce_account", "nope"),
        ] {
            let mut c = valid();
            c.insert(k.into(), v.into());
            assert!(parse_policy(&c).is_err(), "{k}={v} must fail closed");
        }
    }
}
