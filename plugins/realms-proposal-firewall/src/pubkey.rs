use std::{error::Error, fmt, str::FromStr};

use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const PUBKEY_BYTES: usize = 32;
pub const MAX_SEEDS: usize = 16;
pub const MAX_SEED_LEN: usize = 32;
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

pub const SPL_GOVERNANCE_PROGRAM_ID: &str = "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw";
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const BPF_UPGRADEABLE_LOADER_ID: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pubkey([u8; PUBKEY_BYTES]);

impl Pubkey {
    pub const fn new(bytes: [u8; PUBKEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; PUBKEY_BYTES] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; PUBKEY_BYTES] {
        &self.0
    }

    pub fn is_on_curve(&self) -> bool {
        CompressedEdwardsY(self.0).decompress().is_some()
    }
}

impl AsRef<[u8]> for Pubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

impl FromStr for Pubkey {
    type Err = PubkeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.len() > 44 {
            return Err(PubkeyError::InvalidBase58);
        }
        let bytes = bs58::decode(value)
            .into_vec()
            .map_err(|_| PubkeyError::InvalidBase58)?;
        let bytes: [u8; PUBKEY_BYTES] = bytes.try_into().map_err(|_| PubkeyError::InvalidLength)?;
        Ok(Self(bytes))
    }
}

impl Serialize for Pubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Pubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = <&str>::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubkeyError {
    InvalidBase58,
    InvalidLength,
    TooManySeeds,
    SeedTooLong,
    InvalidSeeds,
    NoViableBumpSeed,
}

impl fmt::Display for PubkeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBase58 => "invalid base58 public key",
            Self::InvalidLength => "public key must decode to exactly 32 bytes",
            Self::TooManySeeds => "too many PDA seeds",
            Self::SeedTooLong => "PDA seed exceeds 32 bytes",
            Self::InvalidSeeds => "PDA seeds produce an on-curve address",
            Self::NoViableBumpSeed => "no viable PDA bump seed",
        })
    }
}

impl Error for PubkeyError {}

pub fn create_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Result<Pubkey, PubkeyError> {
    validate_seeds(seeds)?;

    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(program_id.as_ref());
    hasher.update(PDA_MARKER);
    let address = Pubkey::new(hasher.finalize().into());
    if address.is_on_curve() {
        return Err(PubkeyError::InvalidSeeds);
    }
    Ok(address)
}

pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: &Pubkey,
) -> Result<(Pubkey, u8), PubkeyError> {
    if seeds.len() >= MAX_SEEDS {
        return Err(PubkeyError::TooManySeeds);
    }
    validate_seeds(seeds)?;

    for bump in (0..=u8::MAX).rev() {
        let bump_seed = [bump];
        let mut bumped = Vec::with_capacity(seeds.len() + 1);
        bumped.extend_from_slice(seeds);
        bumped.push(&bump_seed);
        match create_program_address(&bumped, program_id) {
            Ok(address) => return Ok((address, bump)),
            Err(PubkeyError::InvalidSeeds) => {}
            Err(error) => return Err(error),
        }
    }
    Err(PubkeyError::NoViableBumpSeed)
}

fn validate_seeds(seeds: &[&[u8]]) -> Result<(), PubkeyError> {
    if seeds.len() > MAX_SEEDS {
        return Err(PubkeyError::TooManySeeds);
    }
    if seeds.iter().any(|seed| seed.len() > MAX_SEED_LEN) {
        return Err(PubkeyError::SeedTooLong);
    }
    Ok(())
}

pub fn proposal_transaction_address(
    governance_program_id: &Pubkey,
    proposal: &Pubkey,
    option_index: u8,
    transaction_index: u16,
) -> Result<(Pubkey, u8), PubkeyError> {
    find_program_address(
        &[
            b"governance",
            proposal.as_ref(),
            &[option_index],
            &transaction_index.to_le_bytes(),
        ],
        governance_program_id,
    )
}

pub fn realm_config_address(
    governance_program_id: &Pubkey,
    realm: &Pubkey,
) -> Result<(Pubkey, u8), PubkeyError> {
    find_program_address(&[b"realm-config", realm.as_ref()], governance_program_id)
}

pub fn native_treasury_address(
    governance_program_id: &Pubkey,
    governance: &Pubkey,
) -> Result<(Pubkey, u8), PubkeyError> {
    find_program_address(
        &[b"native-treasury", governance.as_ref()],
        governance_program_id,
    )
}

pub fn associated_token_address(
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<(Pubkey, u8), PubkeyError> {
    associated_token_address_with_program_id(owner, mint, &spl_token_program_id())
}

pub fn associated_token_address_with_program_id(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program_id: &Pubkey,
) -> Result<(Pubkey, u8), PubkeyError> {
    find_program_address(
        &[owner.as_ref(), token_program_id.as_ref(), mint.as_ref()],
        &associated_token_program_id(),
    )
}

pub fn spl_governance_program_id() -> Pubkey {
    Pubkey::new([
        234, 228, 53, 189, 238, 117, 183, 52, 205, 89, 62, 207, 154, 48, 75, 128, 36, 186, 40, 152,
        103, 183, 105, 177, 249, 60, 167, 187, 184, 142, 70, 254,
    ])
}

pub fn system_program_id() -> Pubkey {
    Pubkey::new([0; 32])
}

pub fn spl_token_program_id() -> Pubkey {
    Pubkey::new([
        6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133,
        237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
    ])
}

pub fn token_2022_program_id() -> Pubkey {
    Pubkey::new([
        6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252,
        77, 131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
    ])
}

pub fn associated_token_program_id() -> Pubkey {
    Pubkey::new([
        140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153,
        218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
    ])
}

pub fn bpf_upgradeable_loader_id() -> Pubkey {
    Pubkey::new([
        2, 168, 246, 145, 78, 136, 161, 176, 226, 16, 21, 62, 247, 99, 174, 43, 0, 194, 185, 61,
        22, 193, 36, 210, 192, 83, 122, 16, 4, 128, 0, 0,
    ])
}
