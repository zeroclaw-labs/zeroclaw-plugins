//! Pure SPL / Token-2022 mint-account parsing. No wasm, no I/O, no deps beyond
//! the standard library — everything here is testable on the host.
//!
//! Layout sources (verify against upstream before release):
//! - SPL Token `Mint`: 82 bytes — mint_authority `COption<Pubkey>` (4+32),
//!   supply u64, decimals u8, is_initialized u8, freeze_authority (4+32).
//! - Token-2022 mints with extensions: base 82 bytes, zero-padded to 165, one
//!   account-type byte (1 = Mint) at offset 165, then TLV entries from 166:
//!   u16 LE extension type, u16 LE value length, value bytes.
//! - Inside TLV values, optional pubkeys are "Pod" options: 32 bytes where
//!   all-zero means None (NOT the 4-byte COption used in the base layout).

/// SPL Token program id (mainnet).
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Token-2022 (Token Extensions) program id (mainnet).
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

const BASE_MINT_LEN: usize = 82;
const ACCOUNT_TYPE_OFFSET: usize = 165;
const TLV_START: usize = 166;
const ACCOUNT_TYPE_MINT: u8 = 1;

/// A parsed Token-2022 extension, reduced to what risk analysis needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// Transfer fee in basis points (the newer of the two epoch configs).
    TransferFee { basis_points: u16 },
    MintCloseAuthority,
    ConfidentialTransfers,
    /// `state`: 1 = initialized, 2 = frozen. Frozen-by-default is the trap.
    DefaultAccountState { frozen: bool },
    NonTransferable,
    InterestBearing,
    /// Permanent delegate that can move/burn ANY holder's tokens.
    PermanentDelegate { delegate: [u8; 32] },
    /// Transfer-hook program invoked on every transfer.
    TransferHook { program_id: Option<[u8; 32]> },
    MetadataPointer,
    TokenMetadata,
    GroupPointer,
    GroupMemberPointer,
    /// Extension type we don't model; carried so the report can say so.
    Unknown(u16),
}

/// Facts pulled from a mint account, program-agnostic.
#[derive(Debug, Clone)]
pub struct MintInfo {
    pub mint_authority: Option<[u8; 32]>,
    pub supply: u64,
    pub decimals: u8,
    pub freeze_authority: Option<[u8; 32]>,
    pub extensions: Vec<Extension>,
}

fn read_u16_le(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn read_u64_le(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8)
        .map(|s| u64::from_le_bytes(s.try_into().expect("slice len 8")))
}

fn read_pubkey(b: &[u8], at: usize) -> Option<[u8; 32]> {
    b.get(at..at + 32).map(|s| s.try_into().expect("slice len 32"))
}

/// 4-byte COption tag + pubkey, as used in the base mint layout.
fn read_coption_pubkey(b: &[u8], at: usize) -> Result<Option<[u8; 32]>, String> {
    let tag = b
        .get(at..at + 4)
        .map(|s| u32::from_le_bytes(s.try_into().expect("slice len 4")))
        .ok_or("mint data truncated at COption tag")?;
    match tag {
        0 => Ok(None),
        1 => read_pubkey(b, at + 4)
            .map(Some)
            .ok_or_else(|| "mint data truncated at COption pubkey".into()),
        n => Err(format!("invalid COption tag {n}")),
    }
}

/// 32-byte Pod option: all-zero means None.
fn pod_pubkey(b: &[u8], at: usize) -> Option<[u8; 32]> {
    read_pubkey(b, at).filter(|pk| pk.iter().any(|&x| x != 0))
}

/// Parse a mint account's raw data. `data` is the full account data; callers
/// have already checked the owner program. Fails closed: any structural
/// surprise is an `Err`, never a guess.
pub fn parse_mint(data: &[u8]) -> Result<MintInfo, String> {
    if data.len() < BASE_MINT_LEN {
        return Err(format!(
            "account data too short for a mint: {} bytes (need {BASE_MINT_LEN})",
            data.len()
        ));
    }
    let mint_authority = read_coption_pubkey(data, 0)?;
    let supply = read_u64_le(data, 36).ok_or("mint data truncated at supply")?;
    let decimals = data[44];
    let is_initialized = data[45];
    if is_initialized != 1 {
        return Err("mint account is not initialized".into());
    }
    let freeze_authority = read_coption_pubkey(data, 46)?;

    let mut extensions = Vec::new();
    if data.len() > BASE_MINT_LEN {
        if data.len() < TLV_START {
            return Err(format!(
                "extended mint data has invalid length {}",
                data.len()
            ));
        }
        if data[ACCOUNT_TYPE_OFFSET] != ACCOUNT_TYPE_MINT {
            return Err(format!(
                "extended account type is {} (expected mint = 1)",
                data[ACCOUNT_TYPE_OFFSET]
            ));
        }
        extensions = parse_tlv(&data[TLV_START..])?;
    }

    Ok(MintInfo {
        mint_authority,
        supply,
        decimals,
        freeze_authority,
        extensions,
    })
}

/// Walk the TLV region. Zero-type entries terminate (uninitialized tail).
fn parse_tlv(mut b: &[u8]) -> Result<Vec<Extension>, String> {
    let mut out = Vec::new();
    loop {
        if b.len() < 4 {
            break; // trailing padding
        }
        let ty = read_u16_le(b, 0).expect("checked len");
        let len = read_u16_le(b, 2).expect("checked len") as usize;
        if ty == 0 {
            break; // Uninitialized terminator
        }
        let val = b
            .get(4..4 + len)
            .ok_or_else(|| format!("TLV entry type {ty} overruns account data"))?;
        out.push(decode_extension(ty, val));
        b = &b[4 + len..];
    }
    Ok(out)
}

/// Token-2022 `ExtensionType` discriminants we recognize.
/// NOTE: verify this table against spl-token-2022 source before release.
fn decode_extension(ty: u16, val: &[u8]) -> Extension {
    match ty {
        1 => Extension::TransferFee {
            // TransferFeeConfig: authority(32) + withdraw_authority(32) +
            // withheld u64 + older(epoch u64, max u64, bps u16) +
            // newer(epoch u64, max u64, bps u16) = 108 bytes.
            // The newer config's bps sit at the last two bytes.
            basis_points: read_u16_le(val, 106).unwrap_or(u16::MAX),
        },
        3 => Extension::MintCloseAuthority,
        // 4 = ConfidentialTransferMint, 16 = ConfidentialTransferFeeConfig;
        // both reduce to "confidential transfers configured" for risk purposes.
        4 | 16 => Extension::ConfidentialTransfers,
        6 => Extension::DefaultAccountState {
            frozen: val.first().copied() == Some(2),
        },
        9 => Extension::NonTransferable,
        10 => Extension::InterestBearing,
        12 => Extension::PermanentDelegate {
            delegate: pod_pubkey(val, 0).unwrap_or([0u8; 32]),
        },
        14 => Extension::TransferHook {
            // TransferHook: authority(32) + program_id(32); zero = unset.
            program_id: pod_pubkey(val, 32),
        },
        18 => Extension::MetadataPointer,
        19 => Extension::TokenMetadata,
        20 => Extension::GroupPointer,
        22 => Extension::GroupMemberPointer,
        other => Extension::Unknown(other),
    }
}
