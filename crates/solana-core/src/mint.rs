//! Decoding SPL Token and Token-2022 **mint** accounts, including the Token-2022
//! TLV extension region. This is the part that makes `token-risk-check` honest,
//! so the layout constants are spelled out and pinned by tests that build
//! synthetic account bytes — no live network.
//!
//! Base mint layout (both programs share the first 82 bytes):
//! ```text
//!   [ 0.. 4) mint_authority COption tag  (u32 LE: 1=Some, 0=None)
//!   [ 4..36) mint_authority pubkey
//!   [36..44) supply (u64 LE)
//!   [44]     decimals (u8)
//!   [45]     is_initialized (bool)
//!   [46..50) freeze_authority COption tag
//!   [50..82) freeze_authority pubkey
//! ```
//! Token-2022 extension region (only when owner is Token-2022 and len > 82):
//! ```text
//!   [165]    account_type (u8: 1 = Mint)
//!   [166..)  TLV entries: type(u16 LE) len(u16 LE) value[len] ...
//! ```

use crate::error::{CoreError, Result};
use crate::pubkey::Pubkey;

/// Offset of the Token-2022 `account_type` byte (== `Account::LEN`).
const ACCOUNT_TYPE_OFFSET: usize = 165;
/// First byte of the TLV region.
const TLV_START: usize = 166;
/// Base SPL mint length.
const MINT_BASE_LEN: usize = 82;

/// A decoded mint, program-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintAccount {
    pub is_token_2022: bool,
    /// Present ⇒ someone can still mint new supply (inflation risk).
    pub mint_authority: Option<Pubkey>,
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
    /// Present ⇒ someone can freeze holder accounts.
    pub freeze_authority: Option<Pubkey>,
    /// Token-2022 extensions found on the mint, in TLV order.
    pub extensions: Vec<MintExtension>,
}

/// The extensions `token-risk-check` reasons about. Everything else is captured
/// as `Other` so an unknown extension never silently reads as "clean".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintExtension {
    /// A % fee skimmed on every transfer. `basis_points` is the *current*
    /// (newer) rate; 100 bp = 1%.
    TransferFeeConfig { basis_points: u16, maximum_fee: u64 },
    /// An arbitrary program invoked on every transfer — can block, redirect, or
    /// tax. `program_id` set ⇒ active hook.
    TransferHook { program_id: Option<Pubkey> },
    /// A delegate that can move ANY holder's tokens without their signature.
    PermanentDelegate { delegate: Option<Pubkey> },
    /// Soulbound: tokens cannot be transferred at all.
    NonTransferable,
    /// New token accounts start in this state. `frozen` ⇒ holders can't transfer
    /// until an authority thaws them.
    DefaultAccountState { frozen: bool },
    /// The mint account itself can be closed by this authority.
    MintCloseAuthority { authority: Option<Pubkey> },
    /// Transfers can be globally paused. `paused` ⇒ currently halted.
    Pausable { paused: bool },
    /// Balance accrues interest; displayed UI amount differs from raw amount.
    InterestBearing,
    /// Confidential (hidden-amount) transfers are enabled.
    ConfidentialTransfer,
    /// Any other extension, by its numeric type. Presence alone is a signal.
    Other(u16),
}

impl MintExtension {
    /// Numeric ExtensionType discriminant (spl-token-2022).
    pub fn type_id(&self) -> u16 {
        match self {
            MintExtension::TransferFeeConfig { .. } => 1,
            MintExtension::MintCloseAuthority { .. } => 3,
            MintExtension::ConfidentialTransfer => 4,
            MintExtension::DefaultAccountState { .. } => 6,
            MintExtension::NonTransferable => 9,
            MintExtension::InterestBearing => 10,
            MintExtension::PermanentDelegate { .. } => 12,
            MintExtension::TransferHook { .. } => 14,
            MintExtension::Pausable { .. } => 26,
            MintExtension::Other(t) => *t,
        }
    }
}

/// Decode a mint from raw account data. `is_token_2022` is decided by the
/// account owner (the caller passes it from `getAccountInfo`).
pub fn decode_mint(data: &[u8], is_token_2022: bool) -> Result<MintAccount> {
    if data.len() < MINT_BASE_LEN {
        return Err(CoreError::Layout(format!(
            "mint data is {} bytes, need at least {MINT_BASE_LEN}",
            data.len()
        )));
    }

    let mint_authority = read_coption_pubkey(&data[0..36])?;
    let supply = u64::from_le_bytes(data[36..44].try_into().unwrap());
    let decimals = data[44];
    let is_initialized = data[45] != 0;
    let freeze_authority = read_coption_pubkey(&data[46..82])?;

    let mut extensions = Vec::new();
    if is_token_2022 && data.len() > ACCOUNT_TYPE_OFFSET {
        // account_type at 165 must be Mint (1); if not, treat as no extensions.
        if data[ACCOUNT_TYPE_OFFSET] == 1 {
            extensions = parse_tlv_extensions(&data[TLV_START..]);
        }
    }

    Ok(MintAccount {
        is_token_2022,
        mint_authority,
        supply,
        decimals,
        is_initialized,
        freeze_authority,
        extensions,
    })
}

/// COption<Pubkey>: 4-byte LE tag then 32-byte pubkey. Nonzero tag ⇒ Some.
fn read_coption_pubkey(bytes: &[u8]) -> Result<Option<Pubkey>> {
    if bytes.len() < 36 {
        return Err(CoreError::Layout("COption<Pubkey> underrun".into()));
    }
    let tag = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if tag == 0 {
        Ok(None)
    } else {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[4..36]);
        Ok(Some(Pubkey(key)))
    }
}

/// OptionalNonZeroPubkey: 32 bytes, all-zero ⇒ None.
fn read_optional_nonzero_pubkey(bytes: &[u8]) -> Option<Pubkey> {
    if bytes.len() < 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[0..32]);
    if key == [0u8; 32] {
        None
    } else {
        Some(Pubkey(key))
    }
}

/// Walk the TLV region. Malformed/truncated entries stop the walk rather than
/// panic — a partial parse still yields the extensions we did read.
fn parse_tlv_extensions(tlv: &[u8]) -> Vec<MintExtension> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= tlv.len() {
        let ext_type = u16::from_le_bytes(tlv[pos..pos + 2].try_into().unwrap());
        let len = u16::from_le_bytes(tlv[pos + 2..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        // Type 0 (Uninitialized) marks the end of meaningful entries.
        if ext_type == 0 {
            break;
        }
        if pos + len > tlv.len() {
            break; // truncated value; stop cleanly
        }
        let value = &tlv[pos..pos + len];
        pos += len;
        out.push(decode_extension(ext_type, value));
    }
    out
}

fn decode_extension(ext_type: u16, value: &[u8]) -> MintExtension {
    match ext_type {
        1 => {
            // TransferFeeConfig: [authority 32][withdraw_authority 32]
            // [withheld u64][older TransferFee 18][newer TransferFee 18]
            // TransferFee = epoch u64 | maximum_fee u64 | basis_points u16
            // newer starts at 32+32+8+18 = 90; maximum_fee at +8, bp at +16.
            let (basis_points, maximum_fee) = if value.len() >= 108 {
                let maximum_fee = u64::from_le_bytes(value[98..106].try_into().unwrap());
                let basis_points = u16::from_le_bytes(value[106..108].try_into().unwrap());
                (basis_points, maximum_fee)
            } else {
                (0, 0)
            };
            MintExtension::TransferFeeConfig {
                basis_points,
                maximum_fee,
            }
        }
        3 => MintExtension::MintCloseAuthority {
            authority: read_optional_nonzero_pubkey(value),
        },
        4 => MintExtension::ConfidentialTransfer,
        6 => {
            // DefaultAccountState: 1 byte, 2 = Frozen.
            let frozen = value.first().copied() == Some(2);
            MintExtension::DefaultAccountState { frozen }
        }
        9 => MintExtension::NonTransferable,
        10 => MintExtension::InterestBearing,
        12 => MintExtension::PermanentDelegate {
            delegate: read_optional_nonzero_pubkey(value),
        },
        14 => {
            // TransferHook: [authority 32][program_id 32]
            let program_id = if value.len() >= 64 {
                read_optional_nonzero_pubkey(&value[32..64])
            } else {
                None
            };
            MintExtension::TransferHook { program_id }
        }
        26 => {
            // PausableConfig: [authority 32][paused bool]
            let paused = value.get(32).copied() == Some(1);
            MintExtension::Pausable { paused }
        }
        other => MintExtension::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a base mint (82 bytes) with the given fields.
    fn base_mint(
        mint_auth: Option<[u8; 32]>,
        supply: u64,
        decimals: u8,
        freeze_auth: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let mut d = vec![0u8; 82];
        if let Some(k) = mint_auth {
            d[0..4].copy_from_slice(&1u32.to_le_bytes());
            d[4..36].copy_from_slice(&k);
        }
        d[36..44].copy_from_slice(&supply.to_le_bytes());
        d[44] = decimals;
        d[45] = 1; // initialized
        if let Some(k) = freeze_auth {
            d[46..50].copy_from_slice(&1u32.to_le_bytes());
            d[50..82].copy_from_slice(&k);
        }
        d
    }

    /// Extend a base mint into a Token-2022 mint carrying the given TLV entries.
    fn with_extensions(mut base: Vec<u8>, tlv: &[(u16, Vec<u8>)]) -> Vec<u8> {
        base.resize(ACCOUNT_TYPE_OFFSET, 0); // pad [82,165)
        base.push(1); // account_type = Mint at [165]
        for (t, v) in tlv {
            base.extend_from_slice(&t.to_le_bytes());
            base.extend_from_slice(&(v.len() as u16).to_le_bytes());
            base.extend_from_slice(v);
        }
        base
    }

    #[test]
    fn decodes_plain_legacy_mint() {
        let auth = [7u8; 32];
        let d = base_mint(Some(auth), 1_000_000, 6, None);
        let m = decode_mint(&d, false).unwrap();
        assert_eq!(m.decimals, 6);
        assert_eq!(m.supply, 1_000_000);
        assert_eq!(m.mint_authority, Some(Pubkey(auth)));
        assert_eq!(m.freeze_authority, None);
        assert!(m.extensions.is_empty());
    }

    #[test]
    fn renounced_mint_authority_is_none() {
        let d = base_mint(None, 21_000_000, 9, None);
        let m = decode_mint(&d, false).unwrap();
        assert_eq!(m.mint_authority, None);
    }

    #[test]
    fn parses_transfer_fee_basis_points() {
        // Build a TransferFeeConfig value with newer bp = 500 (5%), max = 42.
        let mut v = vec![0u8; 108];
        v[98..106].copy_from_slice(&42u64.to_le_bytes()); // newer.maximum_fee
        v[106..108].copy_from_slice(&500u16.to_le_bytes()); // newer.basis_points
        let d = with_extensions(base_mint(None, 1, 6, None), &[(1, v)]);
        let m = decode_mint(&d, true).unwrap();
        assert_eq!(
            m.extensions,
            vec![MintExtension::TransferFeeConfig {
                basis_points: 500,
                maximum_fee: 42
            }]
        );
    }

    #[test]
    fn detects_active_transfer_hook_and_permanent_delegate() {
        let hook_prog = [9u8; 32];
        let delegate = [3u8; 32];
        let mut hook_val = vec![0u8; 64];
        hook_val[32..64].copy_from_slice(&hook_prog); // program_id set
        let d = with_extensions(
            base_mint(None, 1, 0, None),
            &[(14, hook_val), (12, delegate.to_vec())],
        );
        let m = decode_mint(&d, true).unwrap();
        assert!(m.extensions.contains(&MintExtension::TransferHook {
            program_id: Some(Pubkey(hook_prog))
        }));
        assert!(m.extensions.contains(&MintExtension::PermanentDelegate {
            delegate: Some(Pubkey(delegate))
        }));
    }

    #[test]
    fn detects_non_transferable_and_default_frozen() {
        let d = with_extensions(
            base_mint(None, 1, 0, None),
            &[(9, vec![]), (6, vec![2])],
        );
        let m = decode_mint(&d, true).unwrap();
        assert!(m.extensions.contains(&MintExtension::NonTransferable));
        assert!(m
            .extensions
            .contains(&MintExtension::DefaultAccountState { frozen: true }));
    }

    #[test]
    fn unknown_extension_is_captured_not_dropped() {
        let d = with_extensions(base_mint(None, 1, 0, None), &[(99, vec![1, 2, 3])]);
        let m = decode_mint(&d, true).unwrap();
        assert_eq!(m.extensions, vec![MintExtension::Other(99)]);
    }

    #[test]
    fn legacy_owner_ignores_trailing_bytes() {
        // Even if extra bytes are present, a legacy-owned mint has no extensions.
        let d = with_extensions(base_mint(None, 1, 0, None), &[(9, vec![])]);
        let m = decode_mint(&d, false).unwrap();
        assert!(m.extensions.is_empty());
    }

    #[test]
    fn too_short_is_error() {
        assert!(matches!(decode_mint(&[0u8; 10], false), Err(CoreError::Layout(_))));
    }
}
