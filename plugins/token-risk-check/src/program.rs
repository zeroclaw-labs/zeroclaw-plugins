
pub const BPF_LOADER_UPGRADEABLE_ID: [u8; 32] = [
    2, 168, 246, 145, 78, 136, 161, 111, 225, 236, 214, 144, 219, 10, 113, 31, 238, 86, 170, 94, 60,
    117, 34, 187, 246, 237, 201, 18, 59, 133, 40, 2,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookProgramInfo {
    pub is_executable: bool,
    pub is_upgradeable: bool,
    pub upgrade_authority: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramPointer {
    Immutable,
    Upgradeable([u8; 32]), // ProgramData address
}

pub fn parse_program_pointer(
    data: &[u8],
    owner: &[u8; 32],
    executable: bool,
) -> Result<ProgramPointer, String> {
    if !executable {
        return Err("Program account is not executable".to_string());
    }

    if owner != &BPF_LOADER_UPGRADEABLE_ID {
        // Owned by a different loader (e.g. BpfLoader v1/v2), which is immutable
        return Ok(ProgramPointer::Immutable);
    }

    if data.len() < 36 {
        return Err("Program account data too short for UpgradeableLoaderState::Program".to_string());
    }

    let state = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if state != 2 {
        return Err(format!(
            "Expected UpgradeableLoaderState::Program (2), got {}",
            state
        ));
    }

    let mut programdata_address = [0u8; 32];
    programdata_address.copy_from_slice(&data[4..36]);

    Ok(ProgramPointer::Upgradeable(programdata_address))
}

pub fn parse_programdata_account(data: &[u8]) -> Result<Option<[u8; 32]>, String> {
    if data.len() < 45 {
        return Err("ProgramData account data too short".to_string());
    }

    let state = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if state != 3 {
        return Err(format!(
            "Expected UpgradeableLoaderState::ProgramData (3), got {}",
            state
        ));
    }

    // slot is at 4..12 (u64)
    // upgrade_authority_address option tag is at 12
    let option_tag = data[12];
    if option_tag == 0 {
        Ok(None)
    } else if option_tag == 1 {
        let mut authority = [0u8; 32];
        authority.copy_from_slice(&data[13..45]);
        Ok(Some(authority))
    } else {
        Err(format!(
            "Invalid Option tag for upgrade_authority_address: {}",
            option_tag
        ))
    }
}
