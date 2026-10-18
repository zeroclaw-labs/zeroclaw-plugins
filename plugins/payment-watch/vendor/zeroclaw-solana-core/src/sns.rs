//! Solana Name Service (.sol) domain derivation and record parsing.
//!
//! Forward resolution only (name → account/owner), which is the flow that
//! makes the payment tools safe: a user says "pay lucas.sol" and the agent
//! derives the address deterministically instead of hallucinating one.
//!
//! Derivation follows `@bonfida/spl-name-service` exactly:
//! `hashed = sha256("SPL Name Service" + name)`, then the registry account is
//! `find_program_address([hashed, class(32 zero), parent], NAME_PROGRAM)`.
//! For a `.sol` domain the parent is the SOL TLD authority. The registry
//! account's header is `parent(32) · owner(32) · class(32)`, so the owner
//! (the wallet that controls the domain) sits at offset 32.

use crate::encoding::sha256;
use crate::pubkey::{find_program_address, Pubkey};

const HASH_PREFIX: &str = "SPL Name Service";

/// SPL Name Service program.
pub fn name_program() -> Pubkey {
    Pubkey::parse("namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX").unwrap()
}

/// The `.sol` TLD authority (the parent name of every `*.sol` domain).
pub fn sol_tld_authority() -> Pubkey {
    Pubkey::parse("58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx").unwrap()
}

/// A defensive upper bound on the label length. SNS itself imposes no such
/// limit (the label is hashed to 32 bytes regardless), so this is only a
/// flood/abuse guard set well above any real `.sol` domain — never a protocol
/// maximum.
const MAX_LABEL_LEN: usize = 63;

/// Normalize a user-supplied domain into its labels, sub-label first: trim,
/// lowercase, strip a trailing `.sol`, split on `.`. `bonfida.sol` → `["bonfida"]`;
/// `dev.bonfida.sol` → `["dev", "bonfida"]`. Rejects empty/over-long/invalid
/// labels and more than one level of subdomain (SNS derives one level).
pub fn normalize_domain(input: &str) -> Result<Vec<String>, String> {
    let d = input.trim().trim_start_matches('@').to_ascii_lowercase();
    let d = d.strip_suffix(".sol").unwrap_or(&d);
    if d.is_empty() {
        return Err("empty domain".to_string());
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() > 2 {
        return Err(
            "only one level of subdomain is supported, e.g. \"dev.bonfida.sol\"".to_string(),
        );
    }
    for label in &labels {
        if label.is_empty() {
            return Err("invalid domain: empty label".to_string());
        }
        if label.len() > MAX_LABEL_LEN {
            return Err("domain is too long".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("invalid domain: only letters, digits, and '-' are allowed".to_string());
        }
    }
    Ok(labels.into_iter().map(String::from).collect())
}

/// Derive the registry account key for a name under a given parent.
fn derive_under(hashed_name: &[u8; 32], parent: &Pubkey) -> Result<Pubkey, String> {
    let class = [0u8; 32];
    let (key, _) = find_program_address(&[hashed_name, &class, &parent.0], &name_program())?;
    Ok(key)
}

/// Derive the registry account key for normalized labels (sub-first). A top
/// domain hashes `"SPL Name Service" + label` under the SOL TLD; a subdomain
/// hashes `"SPL Name Service" + "\0" + sub` under the *parent domain's* key —
/// exactly `@bonfida/spl-name-service`'s `getDomainKeySync`.
pub fn derive_domain_key(labels: &[String]) -> Result<Pubkey, String> {
    match labels {
        [label] => {
            let hashed = sha256(&[HASH_PREFIX.as_bytes(), label.as_bytes()]);
            derive_under(&hashed, &sol_tld_authority())
        }
        [sub, parent_label] => {
            let parent_hashed = sha256(&[HASH_PREFIX.as_bytes(), parent_label.as_bytes()]);
            let parent = derive_under(&parent_hashed, &sol_tld_authority())?;
            let sub_hashed = sha256(&[HASH_PREFIX.as_bytes(), &[0u8], sub.as_bytes()]);
            derive_under(&sub_hashed, &parent)
        }
        _ => Err("invalid domain: expected one or two labels".to_string()),
    }
}

/// The registry header: parent(32) · owner(32) · class(32), then record data.
pub const NAME_HEADER_LEN: usize = 96;

/// Extract the domain owner from a name registry account's data. A registered
/// domain always has a non-zero owner; an all-zero owner means the record is
/// closed or malformed and must not be reported as a payable wallet.
pub fn parse_registry_owner(data: &[u8]) -> Result<Pubkey, String> {
    if data.len() < NAME_HEADER_LEN {
        return Err(format!(
            "name registry account is {} bytes, expected at least {NAME_HEADER_LEN}",
            data.len()
        ));
    }
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&data[32..64]);
    if owner == [0u8; 32] {
        return Err("name registry has no owner (closed or malformed)".to_string());
    }
    Ok(Pubkey(owner))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn normalizes_domains() {
        assert_eq!(normalize_domain("lucas.sol").unwrap(), labels(&["lucas"]));
        assert_eq!(
            normalize_domain("  LUCAS.SOL  ").unwrap(),
            labels(&["lucas"])
        );
        assert_eq!(normalize_domain("@bonfida").unwrap(), labels(&["bonfida"]));
        assert_eq!(
            normalize_domain("my-name.sol").unwrap(),
            labels(&["my-name"])
        );
        // one level of subdomain is now supported (sub-first)
        assert_eq!(
            normalize_domain("dev.bonfida.sol").unwrap(),
            labels(&["dev", "bonfida"])
        );
    }

    #[test]
    fn rejects_bad_domains() {
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain(".sol").is_err());
        assert!(normalize_domain("a.b.c.sol").is_err()); // >1 subdomain level
        assert!(normalize_domain("a..sol").is_err()); // empty label
        assert!(normalize_domain("bad name").is_err());
        assert!(normalize_domain("emoji😀.sol").is_err());
        assert!(normalize_domain(&"x".repeat(70)).is_err()); // above the flood guard
        assert!(normalize_domain(&"x".repeat(40)).is_ok()); // long but valid
    }

    #[test]
    fn domain_key_is_deterministic_and_off_curve() {
        let a = derive_domain_key(&labels(&["bonfida"])).unwrap();
        let b = derive_domain_key(&labels(&["bonfida"])).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, derive_domain_key(&labels(&["lucas"])).unwrap());
        // A registry account is a PDA, so it must be off the curve.
        assert!(!a.is_on_curve());
        // A subdomain derives to a different (off-curve) key than its parent.
        let sub = derive_domain_key(&labels(&["dev", "bonfida"])).unwrap();
        assert_ne!(sub, a);
        assert!(!sub.is_on_curve());
    }

    #[test]
    fn parses_registry_owner() {
        let mut data = vec![0u8; NAME_HEADER_LEN];
        data[32..64].copy_from_slice(&[7u8; 32]);
        assert_eq!(parse_registry_owner(&data).unwrap().0, [7u8; 32]);
        assert!(parse_registry_owner(&[0u8; 10]).is_err());
        // All-zero owner (closed/malformed record) is rejected, not reported
        // as the system-program address.
        assert!(parse_registry_owner(&[0u8; NAME_HEADER_LEN]).is_err());
    }

    #[test]
    fn bonfida_derives_to_the_canonical_registry_key() {
        // The registry account for the real, well-known `bonfida.sol` domain.
        // This locks the derivation to the exact `@bonfida/spl-name-service`
        // algorithm (prefix, class, parent, program) — a regression here means
        // the derivation drifted from the on-chain reality.
        assert_eq!(
            derive_domain_key(&labels(&["bonfida"]))
                .unwrap()
                .to_base58(),
            "Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb"
        );
    }
}
