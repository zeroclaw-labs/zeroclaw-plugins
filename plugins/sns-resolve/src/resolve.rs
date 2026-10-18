//! Pure core: Solana address / SNS domain resolution — no WASM dependency.
//!
//! Handles three input types:
//! 1. Raw base58 pubkey → validated and returned as-is
//! 2. `.sol` domain → hashed for SNS registry lookup (shim does RPC)
//! 3. `.abc` domain → hashed for ANS registry lookup (shim does RPC)

use serde::Serialize;
use sha2::{Sha256, Digest};

// Inline base58 (zero extra deps)
mod base58 {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    static REVERSE: [u8; 128] = {
        let mut table = [0xFFu8; 128];
        let mut i = 0;
        while i < 58 { table[ALPHABET[i] as usize] = i as u8; i += 1; }
        table
    };

    pub fn encode(bytes: &[u8]) -> String {
        let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
        let mut buf = vec![0u8; (bytes.len() * 138 / 100) + 2];
        let mut buf_len = 0;
        for &byte in bytes.iter().skip(leading_zeros) {
            let mut carry = byte as u32;
            for idx in 0.. {
                if idx >= buf_len { buf_len = idx + 1; while buf.len() <= idx { buf.push(0); } }
                carry += (buf[idx] as u32) << 8;
                buf[idx] = (carry % 58) as u8;
                carry /= 58;
                if carry == 0 && idx + 1 >= buf_len { break; }
            }
        }
        let mut result = String::with_capacity(leading_zeros + buf_len);
        for _ in 0..leading_zeros { result.push('1'); }
        for &digit in buf[..buf_len].iter().rev() { result.push(ALPHABET[digit as usize] as char); }
        result
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let bytes = s.as_bytes();
        let leading_ones = bytes.iter().take_while(|&&b| b == b'1').count();
        let mut buf = vec![0u8; (bytes.len() * 733 / 1000) + 2];
        let mut buf_len = 0;
        for &ch in bytes.iter().skip(leading_ones) {
            if ch > 127 { return None; }
            let digit = REVERSE[ch as usize];
            if digit == 0xFF { return None; }
            let mut carry = digit as u32;
            for idx in 0.. {
                if idx >= buf_len { buf_len = idx + 1; while buf.len() <= idx { buf.push(0); } }
                carry += (buf[idx] as u32) * 58;
                buf[idx] = (carry % 256) as u8;
                carry /= 256;
                if carry == 0 && idx + 1 >= buf_len { break; }
            }
        }
        let mut result = vec![0u8; leading_ones];
        for &byte in buf[..buf_len].iter().rev() { result.push(byte); }
        Some(result)
    }

    pub fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
        let vec = decode(s)?;
        (vec.len() == N).then(|| { let mut arr = [0u8; N]; arr.copy_from_slice(&vec); arr })
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ResolveResult {
    pub address: String,
    pub input_type: InputType,
    pub input: String,
    pub domain: Option<String>,
    pub is_raw: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InputType {
    Pubkey,
    SolDomain,
    AnsDomain,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DomainQuery {
    pub domain: String,
    pub tld: String,
    pub program_id: [u8; 32],
    pub hashed_name: [u8; 32],
    pub parent_name: [u8; 32],
}

/// SNS program ID.
pub const SNS_PROGRAM_ID: [u8; 32] = [
    13, 238, 92, 55, 159, 142, 155, 54, 228, 237, 92, 78, 33, 23, 173, 29,
    252, 242, 172, 194, 52, 237, 152, 81, 53, 164, 128, 17, 129, 159, 10, 58,
];

/// ANS program ID (All Domains).
pub const ANS_PROGRAM_ID: [u8; 32] = [
    242, 34, 133, 105, 74, 142, 112, 231, 169, 136, 74, 247, 165, 56, 52, 90,
    187, 38, 13, 234, 1, 74, 14, 44, 214, 34, 96, 120, 19, 85, 244, 155,
];

/// Root parent name for `.sol` TLD.
pub const SOL_ROOT_PARENT: [u8; 32] = [
    187, 168, 246, 209, 170, 182, 45, 83, 170, 120, 226, 8, 114, 197, 73, 188,
    194, 232, 57, 116, 37, 150, 167, 32, 78, 143, 19, 116, 47, 84, 101, 244,
];

// ---------------------------------------------------------------------------
// Domain detection & query building
// ---------------------------------------------------------------------------

pub fn detect(input: &str) -> InputType {
    let trimmed = input.trim();
    if trimmed.ends_with(".sol") { InputType::SolDomain }
    else if trimmed.ends_with(".abc") { InputType::AnsDomain }
    else if is_likely_pubkey(trimmed) { InputType::Pubkey }
    else { InputType::Unknown }
}

fn is_likely_pubkey(s: &str) -> bool {
    (32..=48).contains(&s.len()) && base58::decode(s).map(|v| v.len() == 32).unwrap_or(false)
}

pub fn build_query(domain: &str) -> Result<DomainQuery, String> {
    let input_type = detect(domain);
    let (tld, program_id, parent_name) = match input_type {
        InputType::SolDomain => (".sol", SNS_PROGRAM_ID, SOL_ROOT_PARENT),
        InputType::AnsDomain => (".abc", ANS_PROGRAM_ID, [0u8; 32]),
        _ => return Err(format!("not a recognized domain: {domain}")),
    };
    let name = domain.trim().trim_end_matches(tld).trim_end_matches('.').to_lowercase();
    if name.is_empty() || name.len() > 64 {
        return Err(format!("invalid domain name: {domain}"));
    }
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let hash = hasher.finalize();
    let mut hashed_name = [0u8; 32];
    hashed_name.copy_from_slice(&hash);
    Ok(DomainQuery { domain: domain.trim().to_string(), tld: tld.to_string(), program_id, hashed_name, parent_name })
}

/// Compute the PDA for a name registry account.
pub fn find_name_pda(query: &DomainQuery) -> ([u8; 32], u8) {
    let seeds: &[&[u8]] = &[&query.hashed_name, &[0u8; 32], &query.parent_name];
    let pda_marker = b"ProgramDerivedAddress";
    for bump in (0..=255).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds { hasher.update(seed); }
        hasher.update(&[bump]);
        hasher.update(&query.program_id);
        hasher.update(pda_marker);
        let hash: [u8; 32] = hasher.finalize().into();
        if !is_on_curve(&hash) { return (hash, bump); }
    }
    (Sha256::digest(&seeds.concat()).into(), 255)
}

fn is_on_curve(bytes: &[u8; 32]) -> bool {
    bytes[31] & 0x80 != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_pubkey() {
        assert_eq!(detect("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), InputType::Pubkey);
    }

    #[test]
    fn detect_sol() { assert_eq!(detect("bonfida.sol"), InputType::SolDomain); }

    #[test]
    fn detect_abc() { assert_eq!(detect("jorch.abc"), InputType::AnsDomain); }

    #[test]
    fn detect_unknown() { assert_eq!(detect("not-a-domain-or-key"), InputType::Unknown); }

    #[test]
    fn build_query_works() {
        let q = build_query("bonfida.sol").unwrap();
        assert_eq!(q.tld, ".sol");
        assert!(q.hashed_name != [0u8; 32]);
    }

    #[test]
    fn pda_deterministic() {
        let q = build_query("test.sol").unwrap();
        let (p1, b1) = find_name_pda(&q);
        let (p2, b2) = find_name_pda(&q);
        assert_eq!(p1, p2);
        assert_eq!(b1, b2);
    }
}
