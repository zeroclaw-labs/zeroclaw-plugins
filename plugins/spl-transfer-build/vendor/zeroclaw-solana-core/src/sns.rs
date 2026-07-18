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

/// Normalize a user-supplied domain: trim, lowercase, strip a single trailing
/// `.sol`. Rejects empty, over-long, subdomain (`a.b.sol`), and non-label
/// characters — a `.sol` label is `[a-z0-9-]`.
pub fn normalize_domain(input: &str) -> Result<String, String> {
    let d = input.trim().trim_start_matches('@').to_ascii_lowercase();
    let d = d.strip_suffix(".sol").unwrap_or(&d);
    if d.is_empty() {
        return Err("empty domain".to_string());
    }
    if d.len() > 32 {
        return Err("domain label too long (max 32 chars)".to_string());
    }
    if d.contains('.') {
        return Err("subdomains are not supported; use a bare name like \"lucas.sol\"".to_string());
    }
    if !d.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("invalid domain: only letters, digits, and '-' are allowed".to_string());
    }
    Ok(d.to_string())
}

/// Derive the registry account key for a normalized `.sol` domain label.
pub fn derive_domain_key(label: &str) -> Result<Pubkey, String> {
    let hashed = sha256(&[HASH_PREFIX.as_bytes(), label.as_bytes()]);
    let class = [0u8; 32];
    let parent = sol_tld_authority();
    let (key, _) = find_program_address(&[&hashed, &class, &parent.0], &name_program())?;
    Ok(key)
}

/// The registry header: parent(32) · owner(32) · class(32), then record data.
pub const NAME_HEADER_LEN: usize = 96;

/// Extract the domain owner from a name registry account's data.
pub fn parse_registry_owner(data: &[u8]) -> Result<Pubkey, String> {
    if data.len() < NAME_HEADER_LEN {
        return Err(format!(
            "name registry account is {} bytes, expected at least {NAME_HEADER_LEN}",
            data.len()
        ));
    }
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&data[32..64]);
    Ok(Pubkey(owner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_domains() {
        assert_eq!(normalize_domain("lucas.sol").unwrap(), "lucas");
        assert_eq!(normalize_domain("  LUCAS.SOL  ").unwrap(), "lucas");
        assert_eq!(normalize_domain("@bonfida").unwrap(), "bonfida");
        assert_eq!(normalize_domain("my-name.sol").unwrap(), "my-name");
    }

    #[test]
    fn rejects_bad_domains() {
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain(".sol").is_err());
        assert!(normalize_domain("a.b.sol").is_err());
        assert!(normalize_domain("bad name").is_err());
        assert!(normalize_domain("emoji😀.sol").is_err());
        assert!(normalize_domain(&"x".repeat(40)).is_err());
    }

    #[test]
    fn domain_key_is_deterministic_and_off_curve() {
        let a = derive_domain_key("bonfida").unwrap();
        let b = derive_domain_key("bonfida").unwrap();
        assert_eq!(a, b);
        assert_ne!(
            derive_domain_key("bonfida").unwrap(),
            derive_domain_key("lucas").unwrap()
        );
        // A registry account is a PDA, so it must be off the curve.
        assert!(!a.is_on_curve());
    }

    #[test]
    fn parses_registry_owner() {
        let mut data = vec![0u8; NAME_HEADER_LEN];
        data[32..64].copy_from_slice(&[7u8; 32]);
        assert_eq!(parse_registry_owner(&data).unwrap().0, [7u8; 32]);
        assert!(parse_registry_owner(&[0u8; 10]).is_err());
    }

    #[test]
    fn bonfida_derives_to_the_canonical_registry_key() {
        // The registry account for the real, well-known `bonfida.sol` domain.
        // This locks the derivation to the exact `@bonfida/spl-name-service`
        // algorithm (prefix, class, parent, program) — a regression here means
        // the derivation drifted from the on-chain reality.
        assert_eq!(
            derive_domain_key("bonfida").unwrap().to_base58(),
            "Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb"
        );
    }
}
