use depin_attest::tx::{build_unsigned_v0_tx, encode_compact_u16, to_base64};
use depin_attest::memo::{build_memo_instruction, AccountMeta, Instruction};

#[test]
fn encode_compact_u16_one_byte_boundary() {
    assert_eq!(encode_compact_u16(0), vec![0x00]);
    assert_eq!(encode_compact_u16(1), vec![0x01]);
    assert_eq!(encode_compact_u16(127), vec![0x7f]);
}

#[test]
fn encode_compact_u16_crosses_to_two_bytes() {
    assert_eq!(encode_compact_u16(128), vec![0x80, 0x01]);
    assert_eq!(encode_compact_u16(16383), vec![0xff, 0x7f]);
}

#[test]
fn encode_compact_u16_crosses_to_three_bytes() {
    assert_eq!(encode_compact_u16(16384), vec![0x80, 0x80, 0x01]);
}

#[test]
fn message_v0_version_prefix_is_0x80() {
    let fee_payer = [1u8; 32];
    let recent_blockhash = [2u8; 32];
    let ix = build_memo_instruction("test").unwrap();
    let tx = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[ix]).unwrap();
    
    // index 0 is signature count (unsigned = 0), index 1 is version prefix
    assert_eq!(tx[1], 0x80);
}

#[test]
fn message_v0_zero_signature_count_prefix() {
    let fee_payer = [1u8; 32];
    let recent_blockhash = [2u8; 32];
    let ix = build_memo_instruction("test").unwrap();
    let tx = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[ix]).unwrap();
    
    // The very first byte must be the compact-u16 zero indicating zero signatures
    assert_eq!(tx[0], 0x00);
}

#[test]
fn message_v0_deduplicates_repeated_accounts() {
    let fee_payer = [1u8; 32];
    let recent_blockhash = [2u8; 32];
    
    // Create an instruction that inexplicably references the fee payer
    let mut ix = build_memo_instruction("test").unwrap();
    ix.accounts.push(AccountMeta {
        pubkey: fee_payer,
        is_signer: true, // upgrading privs shouldn't duplicate
        is_writable: false,
    });
    
    let tx = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[ix]).unwrap();
    
    // account_keys.len is compact-u16 after the 5 byte header (0x00, 0x80, sig_req, ro_signed, ro_unsigned)
    // There should be exactly 2 keys: fee_payer and memo program ID
    assert_eq!(tx[5], 0x02);
    
    // Confirm index 0 is genuinely the fee payer, not something else that happened to load first
    assert_eq!(&tx[6..6 + 32], fee_payer.as_slice());
}

#[test]
fn message_v0_fee_payer_retains_privileges() {
    let fee_payer = [1u8; 32];
    let recent_blockhash = [2u8; 32];
    
    // Create an instruction that inexplicably references the fee payer with LOW privileges
    let mut ix = build_memo_instruction("test").unwrap();
    ix.accounts.push(AccountMeta {
        pubkey: fee_payer,
        is_signer: false, // lower privilege
        is_writable: false, // lower privilege
    });
    
    let tx = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[ix]).unwrap();
    
    // account_keys.len is compact-u16 after the 5 byte header (0x00, 0x80, sig_req, ro_signed, ro_unsigned)
    assert_eq!(tx[5], 0x02);
    
    // Confirm index 0 is genuinely the fee payer
    assert_eq!(&tx[6..6 + 32], fee_payer.as_slice());
    
    // Verify header reflects the retained high privileges:
    // num_required_signatures = 1 (fee_payer)
    // num_readonly_signed_accounts = 0 (fee payer retained writable status)
    assert_eq!(tx[2], 1);
    assert_eq!(tx[3], 0);
}

#[test]
fn message_v0_rejects_empty_instructions() {
    let fee_payer = [1u8; 32];
    let recent_blockhash = [2u8; 32];
    
    let res = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[]);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("zero instructions"));
}

#[test]
fn message_v0_upgrades_account_privileges() {
    let fee_payer = [1u8; 32];
    let recent_blockhash = [2u8; 32];
    let target_pubkey = [3u8; 32];
    
    // Instruction 1: appears as non-signer/non-writable
    let mut ix1 = build_memo_instruction("test1").unwrap();
    ix1.accounts.push(AccountMeta {
        pubkey: target_pubkey,
        is_signer: false,
        is_writable: false,
    });
    
    // Instruction 2: appears as signer/writable
    let mut ix2 = build_memo_instruction("test2").unwrap();
    ix2.accounts.push(AccountMeta {
        pubkey: target_pubkey,
        is_signer: true,
        is_writable: true,
    });
    
    let tx = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[ix1, ix2]).unwrap();
    
    // Keys: fee_payer, target_pubkey, memo_program
    assert_eq!(tx[5], 0x03);
    
    // Confirm index 0 is genuinely the fee payer
    assert_eq!(&tx[6..6 + 32], fee_payer.as_slice());
    
    // Verify target_pubkey is treated as signer_writable
    // It should be placed right after the fee_payer (since signer+writable goes first)
    let target_offset = 6 + 32; // Skip compact-u16(0x03) and fee_payer(32 bytes)
    assert_eq!(&tx[target_offset..target_offset + 32], target_pubkey.as_slice());
    
    // Verify header reflects the upgrade:
    // num_required_signatures = 2 (fee_payer + target)
    // num_readonly_signed_accounts = 0 (both are writable)
    // num_readonly_unsigned_accounts = 1 (memo program)
    assert_eq!(tx[2], 2);
    assert_eq!(tx[3], 0);
    assert_eq!(tx[4], 1);
}

#[test]
fn message_v0_account_key_ordering() {
    let fee_payer = [1u8; 32]; // fee payer
    let unsigned_writable = [2u8; 32]; // unsigned writable
    let signer_readonly = [3u8; 32]; // signer readonly
    let recent_blockhash = [9u8; 32];
    
    let mut ix = build_memo_instruction("test").unwrap();
    ix.accounts.push(AccountMeta {
        pubkey: unsigned_writable,
        is_signer: false,
        is_writable: true,
    });
    ix.accounts.push(AccountMeta {
        pubkey: signer_readonly,
        is_signer: true,
        is_writable: false,
    });
    
    let tx = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[ix.clone()]).unwrap();
    
    // Number of accounts: 4 (fee_payer, signer_ro, unsigned_writable, memo_program)
    assert_eq!(tx[5], 0x04);
    
    let keys_start = 6;
    let expected_order = vec![
        fee_payer,
        signer_readonly,
        unsigned_writable,
        ix.program_id, // unsigned readonly
    ];
    
    for (i, expected_key) in expected_order.iter().enumerate() {
        let start = keys_start + i * 32;
        let end = start + 32;
        assert_eq!(&tx[start..end], expected_key.as_slice());
    }
}

#[test]
fn tx_base64_roundtrip() {
    let fee_payer = [1u8; 32];
    let recent_blockhash = [2u8; 32];
    let ix = build_memo_instruction("roundtrip test").unwrap();
    let tx_bytes = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[ix]).unwrap();
    
    let b64 = to_base64(&tx_bytes);
    use base64::{engine::general_purpose, Engine as _};
    let decoded = general_purpose::STANDARD.decode(&b64).unwrap();
    
    assert_eq!(tx_bytes, decoded);
}

#[test]
fn full_tx_end_to_end_matches_expected_structure() {
    let mut fee_payer = [0u8; 32];
    fee_payer[0] = 0xAA;
    
    let mut blockhash = [0u8; 32];
    blockhash[0] = 0xBB;
    
    let ix = build_memo_instruction("depin_attest: device_123 42.5").unwrap();
    
    let tx = build_unsigned_v0_tx(&fee_payer, &blockhash, &[ix.clone()]).unwrap();
    
    // Parse it back to ensure structure
    assert_eq!(tx[0], 0x00); // 0 sigs
    assert_eq!(tx[1], 0x80); // V0 prefix
    
    // Header
    assert_eq!(tx[2], 1); // num_req_sigs (fee payer)
    assert_eq!(tx[3], 0); // num_ro_signed
    assert_eq!(tx[4], 1); // num_ro_unsigned (memo program)
    
    // Keys len
    assert_eq!(tx[5], 2);
    
    // Keys
    assert_eq!(&tx[6..38], fee_payer.as_slice());
    assert_eq!(&tx[38..70], ix.program_id.as_slice());
    
    // Blockhash
    assert_eq!(&tx[70..102], blockhash.as_slice());
    
    // Instructions len
    assert_eq!(tx[102], 1);
    
    // Instruction 1
    assert_eq!(tx[103], 1); // program_id index (1)
    assert_eq!(tx[104], 0); // accounts len (0)
    
    // Data len
    let data_len = "depin_attest: device_123 42.5".len();
    assert_eq!(tx[105], data_len as u8); // compact-u16 (1 byte for len < 128)
    
    // Data
    let data_start = 106;
    let data_end = data_start + data_len;
    assert_eq!(&tx[data_start..data_end], b"depin_attest: device_123 42.5");
    
    // Empty address table lookups
    assert_eq!(tx[data_end], 0x00);
    
    // Total len
    assert_eq!(tx.len(), data_end + 1);
}

#[test]
fn message_v0_signer_readonly_header_count() {
    let fee_payer = [1u8; 32];
    let signer_readonly = [2u8; 32];
    let recent_blockhash = [9u8; 32];
    
    let mut ix = build_memo_instruction("test").unwrap();
    ix.accounts.push(AccountMeta {
        pubkey: signer_readonly,
        is_signer: true,
        is_writable: false,
    });
    
    let tx = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[ix]).unwrap();
    
    // Header should be:
    // num_required_signatures = 2 (fee_payer + signer_readonly)
    // num_readonly_signed_accounts = 1 (signer_readonly)
    // num_readonly_unsigned_accounts = 1 (memo program)
    assert_eq!(tx[2], 2);
    assert_eq!(tx[3], 1);
    assert_eq!(tx[4], 1);
}

#[test]
fn message_v0_instruction_account_indices_preserved() {
    let fee_payer = [1u8; 32];
    let recent_blockhash = [9u8; 32];
    let acc1 = [2u8; 32]; // writable, unsigned
    let acc2 = [3u8; 32]; // readonly, unsigned
    let acc3 = [4u8; 32]; // readonly, signer
    
    let ix1 = Instruction {
        program_id: [5u8; 32],
        accounts: vec![
            AccountMeta { pubkey: acc1, is_signer: false, is_writable: true },
            AccountMeta { pubkey: acc2, is_signer: false, is_writable: false },
            AccountMeta { pubkey: acc3, is_signer: true, is_writable: false },
        ],
        data: vec![4, 0, 0, 0],
    };
    
    let tx = build_unsigned_v0_tx(&fee_payer, &recent_blockhash, &[ix1]).unwrap();
    
    // Accounts order should be:
    // 0: fee_payer (signer, writable)
    // 1: acc3 (signer, readonly)
    // 2: acc1 (unsigned, writable)
    // 3: acc2 (unsigned, readonly)
    // 4: ix1.program_id (unsigned, readonly)
    
    // keys len
    assert_eq!(tx[5], 5);
    
    let mut offset = 6 + 5 * 32 + 32; // Skip compact-u16(0x05), 5 keys, recent_blockhash
    
    // Instructions len
    assert_eq!(tx[offset], 1);
    offset += 1;
    
    // ix1 program_id index
    assert_eq!(tx[offset], 4);
    offset += 1;
    
    // ix1 accounts len
    assert_eq!(tx[offset], 3);
    offset += 1;
    
    // ix1 accounts indices
    // Must be exactly [2, 3, 1] mapped from [acc1, acc2, acc3] -> [unsigned+writable, unsigned+readonly, signer+readonly]
    assert_eq!(tx[offset], 2);
    assert_eq!(tx[offset+1], 3);
    assert_eq!(tx[offset+2], 1);
}
