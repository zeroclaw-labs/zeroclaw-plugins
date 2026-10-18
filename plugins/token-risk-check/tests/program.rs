use token_risk_check::program::*;

#[test]
fn test_immutable_program() {
    // Non-bpf-loader-upgradeable owner
    let owner = [1u8; 32]; 
    let res = parse_program_pointer(&[], &owner, true).unwrap();
    assert!(matches!(res, ProgramPointer::Immutable));
}

#[test]
fn test_not_executable() {
    let owner = BPF_LOADER_UPGRADEABLE_ID;
    let res = parse_program_pointer(&[], &owner, false);
    assert!(res.is_err());
}

#[test]
fn test_upgradeable_program_pointer() {
    let owner = BPF_LOADER_UPGRADEABLE_ID;
    let mut data = vec![2, 0, 0, 0];
    let programdata_address = [5u8; 32];
    data.extend_from_slice(&programdata_address);

    let res = parse_program_pointer(&data, &owner, true).unwrap();
    if let ProgramPointer::Upgradeable(addr) = res {
        assert_eq!(addr, programdata_address);
    } else {
        panic!("Expected Upgradeable");
    }
}

#[test]
fn test_upgradeable_program_pointer_truncated() {
    let owner = BPF_LOADER_UPGRADEABLE_ID;
    let data = vec![2, 0, 0, 0];
    let res = parse_program_pointer(&data, &owner, true);
    assert!(res.is_err());
}

#[test]
fn test_programdata_with_authority() {
    let mut data = vec![3, 0, 0, 0]; // state
    data.extend_from_slice(&12345u64.to_le_bytes()); // slot
    data.push(1); // Some
    let authority = [7u8; 32];
    data.extend_from_slice(&authority);

    let res = parse_programdata_account(&data).unwrap();
    assert_eq!(res, Some(authority));
}

#[test]
fn test_programdata_no_authority() {
    let mut data = vec![3, 0, 0, 0]; // state
    data.extend_from_slice(&12345u64.to_le_bytes()); // slot
    data.push(0); // None
    data.extend_from_slice(&[0u8; 32]); // Even if there are extra bytes

    let res = parse_programdata_account(&data).unwrap();
    assert_eq!(res, None);
}

#[test]
fn test_programdata_truncated() {
    let mut data = vec![3, 0, 0, 0];
    data.extend_from_slice(&12345u64.to_le_bytes());
    data.push(1); // Some, but missing the pubkey
    
    let res = parse_programdata_account(&data);
    assert!(res.is_err());
}

#[test]
fn test_programdata_wrong_discriminant() {
    let mut data = vec![2, 0, 0, 0]; // Program-shaped, not ProgramData
    let programdata_address = [5u8; 32];
    data.extend_from_slice(&programdata_address);
    // Needs at least 45 bytes to pass the length check, so pad it
    data.extend_from_slice(&[0u8; 9]);

    let res = parse_programdata_account(&data);
    assert!(res.unwrap_err().contains("Expected UpgradeableLoaderState::ProgramData"));
}

#[test]
fn test_program_pointer_wrong_discriminant() {
    let owner = BPF_LOADER_UPGRADEABLE_ID;
    let mut data = vec![3, 0, 0, 0]; // ProgramData-shaped, not Program
    data.extend_from_slice(&12345u64.to_le_bytes()); // slot
    data.push(1); // Some authority
    data.extend_from_slice(&[9u8; 32]); // authority pubkey

    let res = parse_program_pointer(&data, &owner, true);
    assert!(res.unwrap_err().contains("Expected UpgradeableLoaderState::Program"));
}
