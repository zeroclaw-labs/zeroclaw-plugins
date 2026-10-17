//! 32-byte public keys, well-known program addresses, and the two address
//! derivations this suite needs: `create_with_seed` (durable nonce accounts
//! without a second keypair) and `find_program_address` (associated token
//! accounts).

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

use crate::core::codec::{b58_decode, b58_encode};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn from_base58(s: &str) -> Result<Self, String> {
        let bytes = b58_decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("address {s:?} does not decode to 32 bytes"))?;
        Ok(Pubkey(arr))
    }

    pub fn to_base58(&self) -> String {
        b58_encode(&self.0)
    }

    /// Abbreviated form for human-facing summaries: first and last 4 chars.
    pub fn short(&self) -> String {
        let s = self.to_base58();
        if s.len() <= 8 {
            return s;
        }
        format!("{}..{}", &s[..4], &s[s.len() - 4..])
    }
}

fn known(s: &str) -> Pubkey {
    Pubkey::from_base58(s).expect("well-known address must decode")
}

/// `11111111111111111111111111111111` — the system program is 32 zero bytes.
pub fn system_program() -> Pubkey {
    Pubkey([0u8; 32])
}

pub fn token_program() -> Pubkey {
    known("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

pub fn token_2022_program() -> Pubkey {
    known("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
}

pub fn ata_program() -> Pubkey {
    known("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}

pub fn memo_program() -> Pubkey {
    known("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
}

pub fn sysvar_recent_blockhashes() -> Pubkey {
    known("SysvarRecentB1ockHashes11111111111111111111")
}

pub fn sysvar_rent() -> Pubkey {
    known("SysvarRent111111111111111111111111111111111")
}

/// True when the bytes decompress to a valid ed25519 point. Roughly half of
/// all 32-byte strings do; PDA search rejects candidates until one does not.
pub fn is_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

pub const MAX_SEED_LEN: usize = 32;

/// `SystemProgram::createAccountWithSeed` address derivation:
/// `sha256(base || seed || owner)`. This is how the suite gets deterministic
/// nonce-account addresses that only the human authority can sign for —
/// no second keypair, no secrets in the agent.
pub fn create_with_seed(base: &Pubkey, seed: &str, owner: &Pubkey) -> Result<Pubkey, String> {
    if seed.len() > MAX_SEED_LEN {
        return Err(format!("seed longer than {MAX_SEED_LEN} bytes"));
    }
    let mut h = Sha256::new();
    h.update(base.0);
    h.update(seed.as_bytes());
    h.update(owner.0);
    Ok(Pubkey(h.finalize().into()))
}

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// Standard PDA search: highest bump whose hash lands off-curve.
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Result<(Pubkey, u8), String> {
    for bump in (0u8..=255).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program_id.0);
        h.update(PDA_MARKER);
        let candidate: [u8; 32] = h.finalize().into();
        if !is_on_curve(&candidate) {
            return Ok((Pubkey(candidate), bump));
        }
    }
    Err("no viable program-derived address bump".into())
}

/// Associated token account for `wallet` and `mint` under `token_program`.
pub fn derive_ata(wallet: &Pubkey, mint: &Pubkey, token_prog: &Pubkey) -> Result<Pubkey, String> {
    find_program_address(&[&wallet.0, &token_prog.0, &mint.0], &ata_program()).map(|(pk, _)| pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_addresses_roundtrip() {
        for s in [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
            "SysvarRecentB1ockHashes11111111111111111111",
            "SysvarRent111111111111111111111111111111111",
        ] {
            assert_eq!(Pubkey::from_base58(s).unwrap().to_base58(), s);
        }
        assert_eq!(system_program().to_base58(), "1".repeat(32));
    }

    #[test]
    fn rejects_wrong_length_and_garbage() {
        assert!(Pubkey::from_base58("abc").is_err());
        assert!(Pubkey::from_base58("O0Il").is_err());
        assert!(Pubkey::from_base58("").is_err());
    }

    #[test]
    fn keypair_addresses_are_on_curve() {
        // Program ids generated from real keypairs must decompress.
        assert!(is_on_curve(&token_program().0));
        assert!(is_on_curve(&ata_program().0));
    }

    #[test]
    fn derived_pdas_are_off_curve_and_deterministic() {
        let wallet = token_program(); // any valid pubkey works as input
        let mint = ata_program();
        let (a1, bump1) =
            find_program_address(&[&wallet.0, &token_program().0, &mint.0], &ata_program())
                .unwrap();
        let (a2, bump2) =
            find_program_address(&[&wallet.0, &token_program().0, &mint.0], &ata_program())
                .unwrap();
        assert_eq!(a1, a2);
        assert_eq!(bump1, bump2);
        assert!(!is_on_curve(&a1.0));
    }

    #[test]
    fn create_with_seed_is_deterministic_and_seed_sensitive() {
        let base = token_program();
        let a = create_with_seed(&base, "aval-0", &system_program()).unwrap();
        let b = create_with_seed(&base, "aval-0", &system_program()).unwrap();
        let c = create_with_seed(&base, "aval-1", &system_program()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(create_with_seed(&base, &"x".repeat(33), &system_program()).is_err());
    }

    #[test]
    fn short_form() {
        let pk = token_program();
        let s = pk.short();
        assert!(s.starts_with("Toke"));
        assert!(s.contains(".."));
    }
}
