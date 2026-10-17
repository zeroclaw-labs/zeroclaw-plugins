use crate::memo::Instruction;
use base64::{engine::general_purpose, Engine as _};

pub fn encode_compact_u16(value: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let mut val = value;
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            break;
        }
    }
    out
}

#[derive(Debug, PartialEq, Clone)]
pub struct MessageV0Header {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Clone, Debug)]
struct AccountInfo {
    pubkey: [u8; 32],
    is_signer: bool,
    is_writable: bool,
}

pub fn build_unsigned_v0_tx(
    fee_payer: &[u8; 32],
    // The `recent_blockhash` parameter in the V0 message format. In this plugin, this holds a durable nonce hash, not a fetched blockhash.
    recent_blockhash: &[u8; 32],
    instructions: &[Instruction],
) -> Result<Vec<u8>, String> {
    
    if instructions.is_empty() {
        return Err("Cannot build a transaction with zero instructions".to_string());
    }
    
    let mut accounts = Vec::new();
    
    // Fee payer always first (signer, writable)
    accounts.push(AccountInfo {
        pubkey: *fee_payer,
        is_signer: true,
        is_writable: true,
    });
    
    // Collect all accounts from instructions
    for ix in instructions {
        for acc in &ix.accounts {
            if let Some(existing) = accounts.iter_mut().find(|a| a.pubkey == acc.pubkey) {
                existing.is_signer |= acc.is_signer;
                existing.is_writable |= acc.is_writable;
            } else {
                accounts.push(AccountInfo {
                    pubkey: acc.pubkey,
                    is_signer: acc.is_signer,
                    is_writable: acc.is_writable,
                });
            }
        }
        
        // program ID is unsigned, readonly
        if let Some(_existing) = accounts.iter_mut().find(|a| a.pubkey == ix.program_id) {
            // Unsigned, readonly by default, keep existing privileges if higher
        } else {
            accounts.push(AccountInfo {
                pubkey: ix.program_id,
                is_signer: false,
                is_writable: false,
            });
        }
    }
    
    // Sort accounts into groups:
    // 1. Signer + Writable (fee payer is first here)
    // 2. Signer + Readonly
    // 3. Unsigned + Writable
    // 4. Unsigned + Readonly
    
    let fee_payer_acc = accounts.remove(0); // Pop fee payer
    
    let mut signer_writable = Vec::new();
    let mut signer_readonly = Vec::new();
    let mut unsigned_writable = Vec::new();
    let mut unsigned_readonly = Vec::new();
    
    for acc in accounts {
        match (acc.is_signer, acc.is_writable) {
            (true, true) => signer_writable.push(acc),
            (true, false) => signer_readonly.push(acc),
            (false, true) => unsigned_writable.push(acc),
            (false, false) => unsigned_readonly.push(acc),
        }
    }
    
    let mut final_keys = Vec::new();
    final_keys.push(fee_payer_acc);
    final_keys.extend(signer_writable);
    final_keys.extend(signer_readonly);
    final_keys.extend(unsigned_writable);
    final_keys.extend(unsigned_readonly);
    
    let mut num_required_signatures = 0;
    let mut num_readonly_signed_accounts = 0;
    let mut num_readonly_unsigned_accounts = 0;
    
    for acc in &final_keys {
        if acc.is_signer {
            num_required_signatures += 1;
            if !acc.is_writable {
                num_readonly_signed_accounts += 1;
            }
        } else {
            if !acc.is_writable {
                num_readonly_unsigned_accounts += 1;
            }
        }
    }
    
    let header = MessageV0Header {
        num_required_signatures,
        num_readonly_signed_accounts,
        num_readonly_unsigned_accounts,
    };
    
    let mut out = vec![
        0x00, // Unsigned marker: 1 byte zero array length for signatures
        0x80, // Versioned transaction prefix
        header.num_required_signatures,
        header.num_readonly_signed_accounts,
        header.num_readonly_unsigned_accounts,
    ];
    
    // Account keys
    out.extend(encode_compact_u16(final_keys.len() as u16));
    for acc in &final_keys {
        out.extend_from_slice(&acc.pubkey);
    }
    
    // Recent blockhash
    out.extend_from_slice(recent_blockhash);
    
    // Instructions
    out.extend(encode_compact_u16(instructions.len() as u16));
    for ix in instructions {
        let prog_idx = final_keys.iter().position(|a| a.pubkey == ix.program_id)
            .ok_or("Program ID not in account keys")? as u8;
        out.push(prog_idx);
        
        out.extend(encode_compact_u16(ix.accounts.len() as u16));
        for acc in &ix.accounts {
            let acc_idx = final_keys.iter().position(|a| a.pubkey == acc.pubkey)
                .ok_or("Account not in account keys")? as u8;
            out.push(acc_idx);
        }
        
        out.extend(encode_compact_u16(ix.data.len() as u16));
        out.extend_from_slice(&ix.data);
    }
    
    // Empty Address Table Lookups
    out.push(0x00); // compact-u16 zero for address_table_lookups length
    
    Ok(out)
}

pub fn to_base64(tx_bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(tx_bytes)
}
