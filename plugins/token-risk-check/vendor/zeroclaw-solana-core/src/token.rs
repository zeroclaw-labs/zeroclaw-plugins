//! SPL Token / Token-2022 mint account parsing, including the Token-2022 TLV
//! extension walk. This is what lets a plugin see a transfer fee, transfer
//! hook, or permanent delegate *before* an agent touches a token.
//!
//! Base mint layout (82 bytes): `mint_authority COption<Pubkey> (4+32)` ·
//! `supply u64` · `decimals u8` · `is_initialized u8` ·
//! `freeze_authority COption<Pubkey> (4+32)`.
//!
//! Token-2022 mints pad to the token-account size, place an account-type
//! discriminant at offset 165 (1 = Mint), then append TLV entries:
//! `extension type u16 LE` · `length u16 LE` · `value`.

use crate::pubkey::Pubkey;

pub const BASE_MINT_LEN: usize = 82;
const ACCOUNT_TYPE_OFFSET: usize = 165;
const ACCOUNT_TYPE_MINT: u8 = 1;

/// A parsed Token-2022 extension. Only fields plugins act on are decoded;
/// everything else is carried by name so a risk report can still mention it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// Basis points + max fee from the *newer* transfer-fee schedule.
    TransferFee {
        basis_points: u16,
        max_fee: u64,
    },
    /// Default account state; `frozen` means new holders start frozen.
    DefaultAccountState {
        frozen: bool,
    },
    NonTransferable,
    PermanentDelegate {
        delegate: Pubkey,
    },
    TransferHook {
        program_id: Option<Pubkey>,
    },
    MintCloseAuthority,
    InterestBearing,
    Pausable,
    /// Any other extension, by Token-2022 type number.
    Other(u16),
}

impl Extension {
    pub fn name(&self) -> String {
        match self {
            Extension::TransferFee { .. } => "transfer-fee".to_string(),
            Extension::DefaultAccountState { .. } => "default-account-state".to_string(),
            Extension::NonTransferable => "non-transferable".to_string(),
            Extension::PermanentDelegate { .. } => "permanent-delegate".to_string(),
            Extension::TransferHook { .. } => "transfer-hook".to_string(),
            Extension::MintCloseAuthority => "mint-close-authority".to_string(),
            Extension::InterestBearing => "interest-bearing".to_string(),
            Extension::Pausable => "pausable".to_string(),
            Extension::Other(t) => format!("extension-{t}"),
        }
    }
}

pub struct MintInfo {
    pub mint_authority: Option<Pubkey>,
    pub freeze_authority: Option<Pubkey>,
    pub supply: u64,
    pub decimals: u8,
    pub extensions: Vec<Extension>,
}

fn read_coption_pubkey(data: &[u8]) -> Option<Pubkey> {
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if tag == 0 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[4..36]);
    Some(Pubkey(key))
}

/// A Token-2022 `OptionalNonZeroPubkey`: plain 32 bytes, all-zero = None.
fn read_optional_pubkey(data: &[u8]) -> Option<Pubkey> {
    if data.len() < 32 || data[..32].iter().all(|b| *b == 0) {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    Some(Pubkey(key))
}

/// Parse a mint account's raw data (either token program).
pub fn parse_mint(data: &[u8]) -> Result<MintInfo, String> {
    if data.len() < BASE_MINT_LEN {
        return Err(format!(
            "account data is {} bytes; a mint is at least {BASE_MINT_LEN}",
            data.len()
        ));
    }
    // A mint is exactly 82 bytes (base layout) or >165 (padding + account-type
    // discriminant + TLV). Lengths in between are some other account layout —
    // notably a 165-byte token *account* — and must not parse as a mint.
    if data.len() > BASE_MINT_LEN && data.len() <= ACCOUNT_TYPE_OFFSET {
        return Err(format!(
            "account data is {} bytes: not a mint layout (82 or >165 expected)",
            data.len()
        ));
    }
    let is_initialized = data[45] == 1;
    if !is_initialized {
        return Err("mint account is not initialized".to_string());
    }
    let mint_authority = read_coption_pubkey(&data[0..36]);
    let supply = u64::from_le_bytes(data[36..44].try_into().unwrap());
    let decimals = data[44];
    let freeze_authority = read_coption_pubkey(&data[46..82]);

    let mut extensions = Vec::new();
    if data.len() > ACCOUNT_TYPE_OFFSET {
        if data[ACCOUNT_TYPE_OFFSET] != ACCOUNT_TYPE_MINT {
            return Err("extended account is not a mint".to_string());
        }
        extensions = parse_tlv_extensions(&data[ACCOUNT_TYPE_OFFSET + 1..]);
    }

    Ok(MintInfo {
        mint_authority,
        freeze_authority,
        supply,
        decimals,
        extensions,
    })
}

fn parse_tlv_extensions(mut tlv: &[u8]) -> Vec<Extension> {
    let mut extensions = Vec::new();
    while tlv.len() >= 4 {
        let ext_type = u16::from_le_bytes(tlv[0..2].try_into().unwrap());
        let len = u16::from_le_bytes(tlv[2..4].try_into().unwrap()) as usize;
        if ext_type == 0 {
            break; // Uninitialized padding: end of entries.
        }
        if tlv.len() < 4 + len {
            break; // Truncated entry; stop rather than misparse.
        }
        let value = &tlv[4..4 + len];
        extensions.push(decode_extension(ext_type, value));
        tlv = &tlv[4 + len..];
    }
    extensions
}

fn decode_extension(ext_type: u16, value: &[u8]) -> Extension {
    match ext_type {
        // TransferFeeConfig: two authorities (32+32), withheld u64, then
        // older + newer TransferFee { epoch u64, max_fee u64, bps u16 }.
        // Which schedule is live depends on the current epoch, which this
        // parser cannot know — report the *worse* of the two, since a fee
        // that activates next epoch is still a fee the caller will pay.
        1 if value.len() >= 108 => {
            let older_bps = u16::from_le_bytes(value[88..90].try_into().unwrap());
            let newer_bps = u16::from_le_bytes(value[106..108].try_into().unwrap());
            if older_bps > newer_bps {
                Extension::TransferFee {
                    max_fee: u64::from_le_bytes(value[80..88].try_into().unwrap()),
                    basis_points: older_bps,
                }
            } else {
                Extension::TransferFee {
                    max_fee: u64::from_le_bytes(value[98..106].try_into().unwrap()),
                    basis_points: newer_bps,
                }
            }
        }
        3 => Extension::MintCloseAuthority,
        6 if !value.is_empty() => Extension::DefaultAccountState {
            frozen: value[0] == 2,
        },
        9 => Extension::NonTransferable,
        10 => Extension::InterestBearing,
        12 if value.len() >= 32 => Extension::PermanentDelegate {
            // Spec says non-zero, but treat all-zero defensively as set-ness
            // is the risk signal.
            delegate: read_optional_pubkey(value).unwrap_or(Pubkey([0u8; 32])),
        },
        14 => Extension::TransferHook {
            // TransferHook: authority (32) then hook program id (32).
            program_id: value.get(32..64).and_then(read_optional_pubkey),
        },
        26 => Extension::Pausable,
        other => Extension::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_mint(mint_auth: Option<[u8; 32]>, freeze_auth: Option<[u8; 32]>) -> Vec<u8> {
        let mut data = Vec::with_capacity(BASE_MINT_LEN);
        match mint_auth {
            Some(k) => {
                data.extend_from_slice(&1u32.to_le_bytes());
                data.extend_from_slice(&k);
            }
            None => data.extend_from_slice(&[0u8; 36]),
        }
        data.extend_from_slice(&1_000_000_000u64.to_le_bytes()); // supply
        data.push(6); // decimals
        data.push(1); // initialized
        match freeze_auth {
            Some(k) => {
                data.extend_from_slice(&1u32.to_le_bytes());
                data.extend_from_slice(&k);
            }
            None => data.extend_from_slice(&[0u8; 36]),
        }
        data
    }

    #[test]
    fn parses_plain_mint() {
        let info = parse_mint(&base_mint(Some([3u8; 32]), None)).unwrap();
        assert_eq!(info.decimals, 6);
        assert_eq!(info.supply, 1_000_000_000);
        assert!(info.mint_authority.is_some());
        assert!(info.freeze_authority.is_none());
        assert!(info.extensions.is_empty());
    }

    #[test]
    fn rejects_token_account_sized_data() {
        // A 165-byte token *account* must never parse as a mint, even when
        // its bytes happen to look initialized at the mint offsets.
        for len in [83, 120, 165] {
            let mut data = base_mint(None, None);
            data.resize(len, 0);
            assert!(parse_mint(&data).is_err(), "len {len} must be rejected");
        }
    }

    #[test]
    fn transfer_fee_reports_the_worse_schedule() {
        // Older schedule 400bps, newer 100bps: a parser that only reads the
        // newer one under-reports until the epoch flips.
        let mut data = base_mint(None, None);
        data.resize(ACCOUNT_TYPE_OFFSET, 0);
        data.push(ACCOUNT_TYPE_MINT);
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&108u16.to_le_bytes());
        let mut fee = vec![0u8; 108];
        fee[80..88].copy_from_slice(&9000u64.to_le_bytes()); // older max_fee
        fee[88..90].copy_from_slice(&400u16.to_le_bytes()); // older bps
        fee[98..106].copy_from_slice(&5000u64.to_le_bytes()); // newer max_fee
        fee[106..108].copy_from_slice(&100u16.to_le_bytes()); // newer bps
        data.extend_from_slice(&fee);
        let info = parse_mint(&data).unwrap();
        assert!(matches!(
            info.extensions[0],
            Extension::TransferFee {
                basis_points: 400,
                max_fee: 9000
            }
        ));
    }

    #[test]
    fn rejects_uninitialized_mint() {
        let mut data = base_mint(None, None);
        data[45] = 0;
        assert!(parse_mint(&data).is_err());
    }

    #[test]
    fn parses_token_2022_extensions() {
        let mut data = base_mint(None, Some([4u8; 32]));
        data.resize(ACCOUNT_TYPE_OFFSET, 0);
        data.push(ACCOUNT_TYPE_MINT);
        // Permanent delegate (type 12, len 32).
        data.extend_from_slice(&12u16.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes());
        data.extend_from_slice(&[8u8; 32]);
        // Transfer fee config (type 1, len 108): 250 bps, max fee 5000.
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&108u16.to_le_bytes());
        let mut fee = vec![0u8; 108];
        fee[98..106].copy_from_slice(&5000u64.to_le_bytes());
        fee[106..108].copy_from_slice(&250u16.to_le_bytes());
        data.extend_from_slice(&fee);

        let info = parse_mint(&data).unwrap();
        assert_eq!(info.extensions.len(), 2);
        assert!(matches!(
            info.extensions[0],
            Extension::PermanentDelegate { delegate } if delegate.0 == [8u8; 32]
        ));
        assert!(matches!(
            info.extensions[1],
            Extension::TransferFee {
                basis_points: 250,
                max_fee: 5000
            }
        ));
    }

    #[test]
    fn tlv_stops_at_padding_and_truncation() {
        let mut data = base_mint(None, None);
        data.resize(ACCOUNT_TYPE_OFFSET, 0);
        data.push(ACCOUNT_TYPE_MINT);
        data.extend_from_slice(&[0u8; 8]); // uninitialized padding
        assert!(parse_mint(&data).unwrap().extensions.is_empty());

        let mut truncated = base_mint(None, None);
        truncated.resize(ACCOUNT_TYPE_OFFSET, 0);
        truncated.push(ACCOUNT_TYPE_MINT);
        truncated.extend_from_slice(&9u16.to_le_bytes());
        truncated.extend_from_slice(&64u16.to_le_bytes()); // claims 64, has 0
        assert!(parse_mint(&truncated).unwrap().extensions.is_empty());
    }
}
