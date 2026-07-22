#[derive(Debug, Clone, PartialEq)]
pub struct MintExtensions {
    pub supply: u64,
    pub mint_authority: Option<[u8; 32]>,
    pub freeze_authority: Option<[u8; 32]>,
    pub permanent_delegate: Option<[u8; 32]>,
    pub transfer_hook_program_id: Option<[u8; 32]>,
    pub transfer_fee_config: Option<TransferFeeConfig>,
    pub default_account_state: Option<u8>,
    pub unknown_extensions: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransferFeeConfig {
    pub transfer_fee_basis_points: u16,
    pub withdraw_withheld_authority: Option<[u8; 32]>,
}

fn read_coption_pubkey(data: &[u8], offset: usize) -> Result<Option<[u8; 32]>, String> {
    if data.len() < offset + 36 {
        return Err(format!("Truncated COption<Pubkey> at offset {}", offset));
    }
    let tag = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    if tag == 0 {
        Ok(None)
    } else if tag == 1 {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[offset + 4..offset + 36]);
        Ok(Some(pk))
    } else {
        Err(format!("Invalid COption tag: {}", tag))
    }
}

fn read_optional_nonzero_pubkey(data: &[u8], offset: usize) -> Result<Option<[u8; 32]>, String> {
    if data.len() < offset + 32 {
        return Err(format!(
            "Truncated OptionalNonZeroPubkey at offset {}",
            offset
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&data[offset..offset + 32]);
    if pk == [0u8; 32] {
        Ok(None)
    } else {
        Ok(Some(pk))
    }
}

pub fn parse_mint_extensions(data: &[u8]) -> Result<MintExtensions, String> {
    if data.len() < 82 {
        return Err("Data too short for base Mint".into());
    }

    let mut supply_bytes = [0u8; 8];
    supply_bytes.copy_from_slice(&data[36..44]);
    let supply = u64::from_le_bytes(supply_bytes);

    let mint_authority = read_coption_pubkey(data, 0)?;
    let freeze_authority = read_coption_pubkey(data, 46)?;

    let mut exts = MintExtensions {
        supply,
        mint_authority,
        freeze_authority,
        permanent_delegate: None,
        transfer_hook_program_id: None,
        transfer_fee_config: None,
        default_account_state: None,
        unknown_extensions: Vec::new(),
    };

    if data.len() <= 165 {
        return Ok(exts);
    }

    if data[165] != 1 {
        return Err(format!("Invalid AccountType: {}", data[165]));
    }

    // padding checks
    for (i, &b) in data[82..165].iter().enumerate() {
        if b != 0 {
            return Err(format!("Non-zero padding at offset {}", 82 + i));
        }
    }

    let mut offset = 166;
    while offset < data.len() {
        if offset + 2 > data.len() {
            break;
        }

        let ext_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        if ext_type == 0 {
            break; // Uninitialized padding
        }

        if offset + 4 > data.len() {
            return Err("Truncated TLV length".into());
        }

        let ext_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + ext_len;

        if value_end > data.len() {
            return Err(format!(
                "Extension {} length {} exceeds buffer",
                ext_type, ext_len
            ));
        }

        let ext_data = &data[value_start..value_end];

        match ext_type {
            1 => {
                // TransferFeeConfig
                if exts.transfer_fee_config.is_some() {
                    return Err("Duplicate TransferFeeConfig extension found".into());
                }
                if ext_data.len() < 108 {
                    return Err("Truncated TransferFeeConfig".into());
                }
                let withdraw_withheld_authority = read_optional_nonzero_pubkey(ext_data, 32)?;
                
                // Read both older and newer fees, as the older fee is the one currently in effect,
                // and newer fee takes effect next epoch. Both pose immediate or near-term risk.
                let older_transfer_fee_bps = u16::from_le_bytes([ext_data[88], ext_data[89]]);
                let newer_transfer_fee_bps = u16::from_le_bytes([ext_data[106], ext_data[107]]);
                let transfer_fee_basis_points = std::cmp::max(older_transfer_fee_bps, newer_transfer_fee_bps);
                
                exts.transfer_fee_config = Some(TransferFeeConfig {
                    transfer_fee_basis_points,
                    withdraw_withheld_authority,
                });
            }
            6 => {
                // DefaultAccountState
                if exts.default_account_state.is_some() {
                    return Err("Duplicate DefaultAccountState extension found".into());
                }
                if ext_data.is_empty() {
                    return Err("Truncated DefaultAccountState".into());
                }
                exts.default_account_state = Some(ext_data[0]);
            }
            12 => {
                // PermanentDelegate
                if exts.permanent_delegate.is_some() {
                    return Err("Duplicate PermanentDelegate extension found".into());
                }
                if ext_data.len() < 32 {
                    return Err("Truncated PermanentDelegate".into());
                }
                exts.permanent_delegate = read_optional_nonzero_pubkey(ext_data, 0)?;
            }
            14 => {
                // TransferHook
                if exts.transfer_hook_program_id.is_some() || ext_data.len() < 64 {
                    // Just return Err if truncated or duplicate
                    if ext_data.len() < 64 {
                        return Err("Truncated TransferHook".into());
                    }
                    return Err("Duplicate TransferHook extension found".into());
                }
                exts.transfer_hook_program_id = read_optional_nonzero_pubkey(ext_data, 32)?;
            }
            //Replaced silently skipping a non recognized extension discriminant. This ensures any future updates to the token std don't break the plugin
            _ => {
                exts.unknown_extensions.push(ext_type);
            }
        }

        offset = value_end;
    }

    Ok(exts)
}
