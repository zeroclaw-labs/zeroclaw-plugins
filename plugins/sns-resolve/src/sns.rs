//! Pure Solana Name Service (`.sol`) resolution logic — no wasm, no network.
//!
//! Derives a domain's SNS name-account address (a program-derived address over
//! the SPL Name Service program) and extracts the owner from that account's data.
//! Both are host-testable with `cargo test`; the derivation is checked against a
//! golden vector verified live on mainnet (`bonfida.sol`).
//!
//! Algorithm (matches `@bonfida/spl-name-service` `getDomainKeySync`):
//!   hashed = sha256("SPL Name Service" ++ label)
//!   name_account = find_program_address([hashed, 0u8;32, ROOT_DOMAIN], NAME_PROGRAM)
//!   owner = name_account_data[32..64]

use sha2::{Digest, Sha256};

const HASH_PREFIX: &str = "SPL Name Service";
/// SPL Name Service program.
pub const NAME_PROGRAM: &str = "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX";
/// The `.sol` TLD root domain account (parent of every top-level `.sol` name).
pub const ROOT_DOMAIN: &str = "58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx";

fn b58_32(s: &str) -> Result<[u8; 32], String> {
    let v = bs58::decode(s)
        .into_vec()
        .map_err(|_| format!("invalid base58: {s}"))?;
    v.try_into().map_err(|_| format!("`{s}` is not 32 bytes"))
}

/// Strip an optional `.sol`/`@` and reject subdomains — returns the bare label.
pub fn normalize(domain: &str) -> Result<String, String> {
    let d = domain.trim().trim_start_matches('@');
    let label = d.strip_suffix(".sol").unwrap_or(d);
    if label.is_empty() {
        return Err("domain is empty".into());
    }
    if label.contains('.') {
        return Err("subdomains are not supported yet; pass a top-level <name>.sol".into());
    }
    Ok(label.to_string())
}

fn hashed_name(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HASH_PREFIX.as_bytes());
    h.update(label.as_bytes());
    h.finalize().into()
}

/// True if the 32 bytes decompress to a valid Ed25519 point (i.e. ON the curve).
/// A program-derived address must be OFF the curve.
fn on_curve(bytes: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
        .decompress()
        .is_some()
}

fn create_program_address(seeds: &[&[u8]], program: &[u8; 32]) -> Option<[u8; 32]> {
    let mut h = Sha256::new();
    for s in seeds {
        h.update(s);
    }
    h.update(program);
    h.update(b"ProgramDerivedAddress");
    let hash: [u8; 32] = h.finalize().into();
    if on_curve(&hash) {
        None
    } else {
        Some(hash)
    }
}

fn find_program_address(seeds: &[&[u8]], program: &[u8; 32]) -> Option<([u8; 32], u8)> {
    let mut bump = 255u8;
    loop {
        let bump_seed = [bump];
        let mut full: Vec<&[u8]> = seeds.to_vec();
        full.push(&bump_seed);
        if let Some(pda) = create_program_address(&full, program) {
            return Some((pda, bump));
        }
        if bump == 0 {
            return None;
        }
        bump -= 1;
    }
}

/// Derive the SNS name-account address for a top-level `.sol` label.
pub fn domain_account(label: &str) -> Result<String, String> {
    let program = b58_32(NAME_PROGRAM)?;
    let parent = b58_32(ROOT_DOMAIN)?;
    let hashed = hashed_name(label);
    let class = [0u8; 32];
    let (pda, _bump) = find_program_address(&[&hashed, &class, &parent], &program)
        .ok_or("could not derive a name account")?;
    Ok(bs58::encode(pda).into_string())
}

/// Extract the owner (bytes 32..64 of the NameRegistryState header) from a
/// name-account's raw data. Fails closed if the buffer is too short.
pub fn owner_from_data(data: &[u8]) -> Result<String, String> {
    if data.len() < 64 {
        return Err("name account data too short to contain an owner".into());
    }
    Ok(bs58::encode(&data[32..64]).into_string())
}
