//! Metaplex Token Metadata: derive the metadata PDA for a mint and read whether
//! the metadata is MUTABLE. Mutable metadata means the update authority can change
//! the token's name, symbol, and image after you buy — a common bait-and-switch.
//!
//! Pure + deterministic: PDA derivation and the Borsh field walk are host-tested.
//! Only the getAccountInfo(base64) fetch is done by the caller.

use sha2::{Digest, Sha256};

/// Metaplex Token Metadata program id.
pub const METADATA_PROGRAM: &str = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataInfo {
    pub is_mutable: bool,
    pub update_authority: String,
}

/// Derive the Metaplex metadata PDA for `mint`: find_program_address(
/// ["metadata", metadata_program, mint], metadata_program).
pub fn metadata_pda(mint_b58: &str) -> Option<String> {
    let prog = bs58::decode(METADATA_PROGRAM).into_vec().ok()?;
    let mint = bs58::decode(mint_b58).into_vec().ok()?;
    if mint.len() != 32 || prog.len() != 32 {
        return None;
    }
    let seeds: [&[u8]; 3] = [b"metadata", &prog, &mint];
    // find_program_address: highest bump first, take the first off-curve result.
    for bump in (0u8..=255).rev() {
        let mut h = Sha256::new();
        for s in &seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(&prog);
        h.update(PDA_MARKER);
        let arr: [u8; 32] = h.finalize().into();
        // A valid PDA is OFF the ed25519 curve.
        if curve25519_dalek::edwards::CompressedEdwardsY(arr)
            .decompress()
            .is_none()
        {
            return Some(bs58::encode(arr).into_string());
        }
    }
    None
}

/// Parse a Metaplex Metadata account (Borsh) far enough to read `update_authority`
/// and `is_mutable`. Layout: key(1) · update_authority(32) · mint(32) · name(str)
/// · symbol(str) · uri(str) · seller_fee(u16) · creators(Option<Vec<Creator>>)
/// · primary_sale_happened(bool) · is_mutable(bool). Borsh strings are u32-LE len
/// + bytes; a Creator is 34 bytes (pubkey 32 + verified 1 + share 1).
pub fn parse_metadata(data: &[u8]) -> Option<MetadataInfo> {
    let mut o = 0usize;
    let _key = *data.get(o)?;
    o += 1;
    let ua = data.get(o..o + 32)?;
    let update_authority = bs58::encode(ua).into_string();
    o += 32; // update_authority
    o += 32; // mint

    // name, symbol, uri (three borsh strings)
    for _ in 0..3 {
        let len = u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?) as usize;
        o += 4;
        o = o.checked_add(len)?;
        if o > data.len() {
            return None;
        }
    }
    o += 2; // seller_fee_basis_points (u16)

    // creators: Option<Vec<Creator>>
    let has_creators = *data.get(o)?;
    o += 1;
    if has_creators == 1 {
        let n = u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?) as usize;
        o += 4;
        o = o.checked_add(n.checked_mul(34)?)?;
        if o > data.len() {
            return None;
        }
    }
    o += 1; // primary_sale_happened (bool)
    let is_mutable = *data.get(o)? != 0;
    Some(MetadataInfo { is_mutable, update_authority })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid Metadata blob with the given is_mutable byte.
    fn blob(is_mutable: u8, has_creators: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(4); // key
        b.extend_from_slice(&[1u8; 32]); // update_authority
        b.extend_from_slice(&[2u8; 32]); // mint
        for s in ["NAME", "SYM", "https://u"] {
            b.extend_from_slice(&(s.len() as u32).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
        }
        b.extend_from_slice(&500u16.to_le_bytes()); // seller_fee
        if has_creators {
            b.push(1); // Some
            b.extend_from_slice(&1u32.to_le_bytes()); // 1 creator
            b.extend_from_slice(&[7u8; 32]); // creator pubkey
            b.push(1); // verified
            b.push(100); // share
        } else {
            b.push(0); // None
        }
        b.push(0); // primary_sale_happened
        b.push(is_mutable); // is_mutable
        b
    }

    #[test]
    fn parse_mutable_and_immutable() {
        let m = parse_metadata(&blob(1, true)).unwrap();
        assert!(m.is_mutable);
        assert_eq!(m.update_authority, bs58::encode([1u8; 32]).into_string());

        let im = parse_metadata(&blob(0, false)).unwrap();
        assert!(!im.is_mutable);
    }

    #[test]
    fn parse_truncated_is_none_not_panic() {
        assert!(parse_metadata(&[4, 0, 0]).is_none());
        assert!(parse_metadata(&[]).is_none());
    }

    #[test]
    fn pda_is_deterministic_and_off_curve() {
        // Same input -> same PDA; the result decodes to 32 bytes.
        let a = metadata_pda("So11111111111111111111111111111111111111112").unwrap();
        let b = metadata_pda("So11111111111111111111111111111111111111112").unwrap();
        assert_eq!(a, b);
        assert_eq!(bs58::decode(&a).into_vec().unwrap().len(), 32);
    }

    #[test]
    fn pda_rejects_bad_mint() {
        assert!(metadata_pda("not-a-mint").is_none());
    }
}
