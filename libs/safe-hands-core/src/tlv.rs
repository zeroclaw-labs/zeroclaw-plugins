//! Token-2022 mint extension (TLV) parsing — the risk signals the policy
//! engine enforces on: permanent delegate, transfer hook, transfer fee,
//! default-frozen (honeypot pattern).
//!
//! Layout (official spl-token-2022): base mint is 82 bytes. Extended mints
//! have an account-type byte at 82, then TLV entries: type u16 LE, length
//! u16 LE, value. Extension type numbers (official extension.rs):
//! 1 = TransferFeeConfig, 6 = DefaultAccountState, 12 = PermanentDelegate,
//! 14 = TransferHook.

/// Token-2022 program id.
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// The risk signals a mint can carry.
#[derive(Clone, Debug, Default)]
pub struct MintRisk {
    /// Mint owner is the Token-2022 program (false = classic SPL).
    pub is_token_2022: bool,
    pub permanent_delegate: bool,
    pub transfer_hook: bool,
    pub transfer_fee: bool,
    /// DefaultAccountState == Frozen(2): every new token account starts
    /// frozen — the classic honeypot pattern.
    pub default_frozen: bool,
}

const BASE_MINT_LEN: usize = 82;
const ACCOUNT_TYPE_MINT_EXT: u8 = 2; // StateWithExtensions marker for mints

/// Parse a mint account buffer + owner into [`MintRisk`]. Total function:
/// truncated/foreign data yields "no signals", never a panic.
pub fn parse_mint_risk(owner: &str, data: &[u8]) -> MintRisk {
    let mut risk = MintRisk {
        is_token_2022: owner == TOKEN_2022_PROGRAM_ID,
        ..Default::default()
    };
    if !risk.is_token_2022 || data.len() <= BASE_MINT_LEN {
        return risk;
    }
    if data[BASE_MINT_LEN] != ACCOUNT_TYPE_MINT_EXT {
        return risk;
    }
    let mut cursor = BASE_MINT_LEN + 1;
    while cursor + 4 <= data.len() {
        let ext_type = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        let ext_len = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
        cursor += 4;
        if cursor + ext_len > data.len() {
            break; // truncated entry — stop, never overrun
        }
        let value = &data[cursor..cursor + ext_len];
        match ext_type {
            1 => risk.transfer_fee = true,
            6 if value.first() == Some(&2) => risk.default_frozen = true,
            12 => risk.permanent_delegate = true,
            14 if value.len() >= 64 && value[32..64].iter().any(|b| *b != 0) => {
                // TransferHook: authority(32) + program_id(32); nonzero = set.
                risk.transfer_hook = true;
            }
            _ => {}
        }
        cursor += ext_len;
    }
    risk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint_account(owner_is_t22: bool, extensions: &[(u16, Vec<u8>)]) -> (String, Vec<u8>) {
        let owner = if owner_is_t22 {
            TOKEN_2022_PROGRAM_ID.to_string()
        } else {
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()
        };
        let mut data = vec![0u8; BASE_MINT_LEN];
        if !extensions.is_empty() {
            data.push(ACCOUNT_TYPE_MINT_EXT);
            for (t, v) in extensions {
                data.extend_from_slice(&t.to_le_bytes());
                data.extend_from_slice(&(v.len() as u16).to_le_bytes());
                data.extend_from_slice(v);
            }
        }
        (owner, data)
    }

    #[test]
    fn classic_spl_has_no_signals() {
        let (owner, data) = mint_account(false, &[]);
        let r = parse_mint_risk(&owner, &data);
        assert!(!r.is_token_2022);
        assert!(!r.permanent_delegate && !r.transfer_hook && !r.transfer_fee && !r.default_frozen);
    }

    #[test]
    fn permanent_delegate_detected() {
        let (owner, data) = mint_account(true, &[(12, vec![0u8; 32])]);
        let r = parse_mint_risk(&owner, &data);
        assert!(r.permanent_delegate);
    }

    #[test]
    fn transfer_hook_requires_nonzero_program() {
        let (owner, data) = mint_account(true, &[(14, vec![0u8; 64])]);
        assert!(
            !parse_mint_risk(&owner, &data).transfer_hook,
            "zero program id = unset"
        );

        let mut hook = vec![0u8; 64];
        hook[63] = 9;
        let (owner, data) = mint_account(true, &[(14, hook)]);
        assert!(parse_mint_risk(&owner, &data).transfer_hook);
    }

    #[test]
    fn default_frozen_honeypot_detected() {
        let (owner, data) = mint_account(true, &[(6, vec![2])]);
        assert!(parse_mint_risk(&owner, &data).default_frozen);
        let (owner, data) = mint_account(true, &[(6, vec![1])]);
        assert!(
            !parse_mint_risk(&owner, &data).default_frozen,
            "initialized ≠ frozen"
        );
    }

    #[test]
    fn multiple_extensions_parse_in_order() {
        let (owner, data) = mint_account(
            true,
            &[(1, vec![0u8; 10]), (12, vec![0u8; 32]), (6, vec![2])],
        );
        let r = parse_mint_risk(&owner, &data);
        assert!(r.transfer_fee && r.permanent_delegate && r.default_frozen);
    }

    #[test]
    fn truncated_tlv_stops_cleanly() {
        let mut data = vec![0u8; BASE_MINT_LEN + 1];
        data[BASE_MINT_LEN] = ACCOUNT_TYPE_MINT_EXT;
        data.extend_from_slice(&[12, 0, 255, 255]); // declares huge entry, no payload
        let r = parse_mint_risk(TOKEN_2022_PROGRAM_ID, &data);
        assert!(!r.permanent_delegate, "truncated entry must not count");
    }
}
