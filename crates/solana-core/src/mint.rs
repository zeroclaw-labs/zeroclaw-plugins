//! SPL Token and Token-2022 **mint** account decoding.
//!
//! The base mint is the classic 82-byte `spl-token` `Pack` layout. A Token-2022
//! mint carries the same 82 bytes, is padded to the 165-byte account length, and
//! then appends a one-byte account-type discriminator followed by TLV-encoded
//! extensions. This module decodes the base fields and walks the extensions that
//! matter for token risk (permanent delegate, transfer hook, transfer fee,
//! default-frozen state, mint-close authority, non-transferable), all with
//! bounds checks so malformed data returns `Err` instead of panicking.

use crate::{Pubkey, DEFAULT_PUBKEY};

/// Length of the packed base mint (`spl_token::state::Mint::LEN`).
pub const MINT_LEN: usize = 82;
/// Base account length Token-2022 pads to before the account-type byte
/// (`spl_token::state::Account::LEN`).
pub const BASE_ACCOUNT_LEN: usize = 165;
/// Account-type discriminator value for a mint in Token-2022.
pub const ACCOUNT_TYPE_MINT: u8 = 1;

/// Decoded base fields of an SPL / Token-2022 mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mint {
    /// The authority allowed to mint new supply, or `None` if renounced.
    pub mint_authority: Option<Pubkey>,
    /// Total minted supply, in base units (pre-decimals).
    pub supply: u64,
    /// Number of decimals.
    pub decimals: u8,
    /// Whether the mint is initialized.
    pub is_initialized: bool,
    /// The authority allowed to freeze token accounts, or `None`.
    pub freeze_authority: Option<Pubkey>,
}

/// A Token-2022 mint extension relevant to risk assessment. Unrecognized
/// extensions are preserved as [`MintExtension::Other`] so callers can still see
/// that *something* extra is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintExtension {
    /// Mint can be closed (and rent reclaimed) by this authority.
    MintCloseAuthority(Option<Pubkey>),
    /// A fee is withheld on every transfer, in basis points (current epoch).
    TransferFee { basis_points: u16, maximum_fee: u64 },
    /// New token accounts are created frozen by default (holders cannot transfer
    /// until an authority thaws them).
    DefaultAccountStateFrozen,
    /// A default account state other than frozen (e.g. initialized).
    DefaultAccountState(u8),
    /// An address that may transfer or burn tokens from *any* account without
    /// the owner's consent.
    PermanentDelegate(Option<Pubkey>),
    /// Every transfer invokes this program, which can tax or block it.
    TransferHook(Option<Pubkey>),
    /// The token cannot be transferred at all (soul-bound).
    NonTransferable,
    /// Balance accrues interest at this many basis points (informational).
    InterestBearing { current_rate_bps: i16 },
    /// A recognized-but-not-risk-relevant or unrecognized extension type id.
    Other(u16),
}

/// Extension type discriminants from `spl_token_2022::extension::ExtensionType`.
mod ext_type {
    pub const TRANSFER_FEE_CONFIG: u16 = 1;
    pub const MINT_CLOSE_AUTHORITY: u16 = 3;
    pub const DEFAULT_ACCOUNT_STATE: u16 = 6;
    pub const NON_TRANSFERABLE: u16 = 9;
    pub const INTEREST_BEARING_CONFIG: u16 = 10;
    pub const PERMANENT_DELEGATE: u16 = 12;
    pub const TRANSFER_HOOK: u16 = 14;
}

/// Decode the 82-byte base mint. Accepts any buffer at least `MINT_LEN` long
/// (Token-2022 mints are longer; the extra bytes are handled by
/// [`parse_extensions`]).
pub fn parse_mint(data: &[u8]) -> Result<Mint, String> {
    if data.len() < MINT_LEN {
        return Err(format!(
            "account data is {} bytes, too short for a mint ({MINT_LEN})",
            data.len()
        ));
    }
    let mint_authority = read_coption_pubkey(&data[0..36])?;
    let supply = u64::from_le_bytes(data[36..44].try_into().unwrap());
    let decimals = data[44];
    let is_initialized = data[45] != 0;
    let freeze_authority = read_coption_pubkey(&data[46..82])?;

    Ok(Mint {
        mint_authority,
        supply,
        decimals,
        is_initialized,
        freeze_authority,
    })
}

/// Walk the Token-2022 extension TLV region and decode the risk-relevant
/// extensions. Returns an empty vector for a legacy 82-byte mint or any account
/// with no extension region. Malformed TLV lengths terminate the walk rather
/// than panic.
pub fn parse_extensions(data: &[u8]) -> Vec<MintExtension> {
    let mut out = Vec::new();
    // Extensions live after the base-account padding and the 1-byte account type.
    // A plain mint (no extensions) is exactly MINT_LEN; anything without room for
    // the account-type byte + one TLV header has no extensions to read.
    if data.len() <= BASE_ACCOUNT_LEN {
        return out;
    }
    // data[BASE_ACCOUNT_LEN] is the account-type discriminator (expected == 1).
    let mut cursor = BASE_ACCOUNT_LEN + 1;
    while cursor + 4 <= data.len() {
        let ext_type = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        let len = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
        // Type 0 is the uninitialized terminator.
        if ext_type == 0 {
            break;
        }
        let start = cursor + 4;
        let end = match start.checked_add(len) {
            Some(e) if e <= data.len() => e,
            _ => break, // truncated / malformed length: stop reading.
        };
        out.push(decode_extension(ext_type, &data[start..end]));
        cursor = end;
    }
    out
}

fn decode_extension(ext_type: u16, data: &[u8]) -> MintExtension {
    match ext_type {
        ext_type::MINT_CLOSE_AUTHORITY => {
            MintExtension::MintCloseAuthority(read_optional_nonzero_pubkey(data))
        }
        ext_type::PERMANENT_DELEGATE => {
            MintExtension::PermanentDelegate(read_optional_nonzero_pubkey(data))
        }
        ext_type::NON_TRANSFERABLE => MintExtension::NonTransferable,
        ext_type::DEFAULT_ACCOUNT_STATE => match data.first().copied() {
            Some(2) => MintExtension::DefaultAccountStateFrozen,
            Some(state) => MintExtension::DefaultAccountState(state),
            None => MintExtension::Other(ext_type),
        },
        ext_type::TRANSFER_FEE_CONFIG => decode_transfer_fee(data),
        ext_type::TRANSFER_HOOK => {
            // Layout: authority (32) then program_id (32), both optional-nonzero.
            let program_id = data.get(32..64).and_then(read_optional_nonzero_pubkey_opt);
            MintExtension::TransferHook(program_id.flatten())
        }
        ext_type::INTEREST_BEARING_CONFIG => {
            // rate_authority(32) init_ts(8) pre_update_avg_rate(2) last_ts(8) current_rate(2)
            let current = data
                .get(50..52)
                .map(|b| i16::from_le_bytes([b[0], b[1]]))
                .unwrap_or(0);
            MintExtension::InterestBearing {
                current_rate_bps: current,
            }
        }
        other => MintExtension::Other(other),
    }
}

/// TransferFeeConfig: two authorities (optional-nonzero, 32 each), withheld u64,
/// then older and newer `TransferFee` (each: epoch u64, maximum_fee u64,
/// basis_points u16). We report the newer (current) fee.
fn decode_transfer_fee(data: &[u8]) -> MintExtension {
    // newer TransferFee starts at 32 + 32 + 8 + 18 = 90.
    const NEWER_OFFSET: usize = 90;
    let maximum_fee = data
        .get(NEWER_OFFSET + 8..NEWER_OFFSET + 16)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0);
    let basis_points = data
        .get(NEWER_OFFSET + 16..NEWER_OFFSET + 18)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0);
    MintExtension::TransferFee {
        basis_points,
        maximum_fee,
    }
}

/// Read a `COption<Pubkey>`: a 4-byte little-endian tag (0 = None, 1 = Some)
/// followed by the 32-byte key. Any other tag is treated as malformed.
fn read_coption_pubkey(buf: &[u8]) -> Result<Option<Pubkey>, String> {
    if buf.len() < 36 {
        return Err("COption<Pubkey> field is truncated".to_string());
    }
    let tag = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    match tag {
        0 => Ok(None),
        1 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&buf[4..36]);
            Ok(Some(key))
        }
        other => Err(format!("invalid COption tag {other}")),
    }
}

/// Read a Token-2022 `OptionalNonZeroPubkey`: a bare 32-byte key where all-zero
/// means `None`.
fn read_optional_nonzero_pubkey(buf: &[u8]) -> Option<Pubkey> {
    read_optional_nonzero_pubkey_opt(buf).flatten()
}

/// Same as [`read_optional_nonzero_pubkey`] but distinguishes "buffer too short"
/// (`None`) from "present but zero" (`Some(None)`), for callers that slice first.
fn read_optional_nonzero_pubkey_opt(buf: &[u8]) -> Option<Option<Pubkey>> {
    if buf.len() < 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&buf[0..32]);
    if key == DEFAULT_PUBKEY {
        Some(None)
    } else {
        Some(Some(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 82-byte mint buffer for tests.
    fn mint_bytes(
        mint_auth: Option<[u8; 32]>,
        supply: u64,
        decimals: u8,
        freeze_auth: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let mut b = vec![0u8; MINT_LEN];
        if let Some(k) = mint_auth {
            b[0..4].copy_from_slice(&1u32.to_le_bytes());
            b[4..36].copy_from_slice(&k);
        }
        b[36..44].copy_from_slice(&supply.to_le_bytes());
        b[44] = decimals;
        b[45] = 1; // initialized
        if let Some(k) = freeze_auth {
            b[46..50].copy_from_slice(&1u32.to_le_bytes());
            b[50..82].copy_from_slice(&k);
        }
        b
    }

    #[test]
    fn decodes_a_renounced_mint() {
        let b = mint_bytes(None, 1_000_000_000, 6, None);
        let m = parse_mint(&b).unwrap();
        assert_eq!(m.mint_authority, None);
        assert_eq!(m.freeze_authority, None);
        assert_eq!(m.supply, 1_000_000_000);
        assert_eq!(m.decimals, 6);
        assert!(m.is_initialized);
    }

    #[test]
    fn decodes_authorities_when_present() {
        let auth = [7u8; 32];
        let freeze = [9u8; 32];
        let b = mint_bytes(Some(auth), 42, 9, Some(freeze));
        let m = parse_mint(&b).unwrap();
        assert_eq!(m.mint_authority, Some(auth));
        assert_eq!(m.freeze_authority, Some(freeze));
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(parse_mint(&[0u8; 10]).is_err());
    }

    #[test]
    fn rejects_bad_coption_tag() {
        let mut b = mint_bytes(None, 1, 0, None);
        b[0..4].copy_from_slice(&7u32.to_le_bytes()); // invalid tag
        assert!(parse_mint(&b).is_err());
    }

    #[test]
    fn legacy_mint_has_no_extensions() {
        let b = mint_bytes(None, 1, 6, None);
        assert!(parse_extensions(&b).is_empty());
    }

    /// Build a Token-2022 mint with a single extension TLV appended.
    fn mint_with_extension(ext_type: u16, ext_data: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; BASE_ACCOUNT_LEN + 1];
        // valid base mint in the first 82 bytes
        b[45] = 1;
        b[BASE_ACCOUNT_LEN] = ACCOUNT_TYPE_MINT;
        b.extend_from_slice(&ext_type.to_le_bytes());
        b.extend_from_slice(&(ext_data.len() as u16).to_le_bytes());
        b.extend_from_slice(ext_data);
        b
    }

    #[test]
    fn detects_permanent_delegate() {
        let delegate = [3u8; 32];
        let b = mint_with_extension(ext_type::PERMANENT_DELEGATE, &delegate);
        let exts = parse_extensions(&b);
        assert_eq!(exts, vec![MintExtension::PermanentDelegate(Some(delegate))]);
    }

    #[test]
    fn zero_permanent_delegate_is_none() {
        let b = mint_with_extension(ext_type::PERMANENT_DELEGATE, &[0u8; 32]);
        assert_eq!(
            parse_extensions(&b),
            vec![MintExtension::PermanentDelegate(None)]
        );
    }

    #[test]
    fn detects_default_frozen_state() {
        let b = mint_with_extension(ext_type::DEFAULT_ACCOUNT_STATE, &[2u8]);
        assert_eq!(
            parse_extensions(&b),
            vec![MintExtension::DefaultAccountStateFrozen]
        );
    }

    #[test]
    fn detects_non_transferable() {
        let b = mint_with_extension(ext_type::NON_TRANSFERABLE, &[]);
        assert_eq!(parse_extensions(&b), vec![MintExtension::NonTransferable]);
    }

    #[test]
    fn detects_transfer_hook_program() {
        let mut data = vec![0u8; 64];
        let program = [5u8; 32];
        data[32..64].copy_from_slice(&program); // authority zero, program set
        let b = mint_with_extension(ext_type::TRANSFER_HOOK, &data);
        assert_eq!(
            parse_extensions(&b),
            vec![MintExtension::TransferHook(Some(program))]
        );
    }

    #[test]
    fn decodes_transfer_fee_basis_points() {
        let mut data = vec![0u8; 108];
        // newer fee basis_points at offset 90 + 16 = 106
        data[106..108].copy_from_slice(&500u16.to_le_bytes()); // 5%
        data[98..106].copy_from_slice(&1_000u64.to_le_bytes()); // maximum_fee
        let b = mint_with_extension(ext_type::TRANSFER_FEE_CONFIG, &data);
        assert_eq!(
            parse_extensions(&b),
            vec![MintExtension::TransferFee {
                basis_points: 500,
                maximum_fee: 1_000
            }]
        );
    }

    #[test]
    fn truncated_tlv_does_not_panic() {
        let mut b = vec![0u8; BASE_ACCOUNT_LEN + 1];
        b[BASE_ACCOUNT_LEN] = ACCOUNT_TYPE_MINT;
        // header claims 100 bytes of data but none follow
        b.extend_from_slice(&ext_type::PERMANENT_DELEGATE.to_le_bytes());
        b.extend_from_slice(&100u16.to_le_bytes());
        let exts = parse_extensions(&b); // must not panic
        assert!(exts.is_empty());
    }

    #[test]
    fn unknown_extension_is_preserved() {
        let b = mint_with_extension(999, &[1, 2, 3]);
        assert_eq!(parse_extensions(&b), vec![MintExtension::Other(999)]);
    }
}
