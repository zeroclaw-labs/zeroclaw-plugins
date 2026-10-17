pub const MEMO_PROGRAM_ID_B58: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
// Note: a newer Memo deployment exists (Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH)
// but this legacy v2 address is universally recognized by wallets/explorers
// today — chosen deliberately for demo/compatibility reasons, not by default.

#[derive(Clone, Debug, PartialEq)]
pub struct AccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Instruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

// Sane length bound: 566 bytes. 
// Solana max packet size is 1232 bytes, header + signatures + overhead leaves ~566 bytes max for instructions practically.
pub const MAX_MEMO_LEN: usize = 566;

pub fn build_memo_instruction(memo_text: &str) -> Result<Instruction, String> {
    if memo_text.len() > MAX_MEMO_LEN {
        return Err(format!("Memo text too long: {} bytes exceeds limit of {}", memo_text.len(), MAX_MEMO_LEN));
    }

    let mut program_id = [0u8; 32];
    let decoded = bs58::decode(MEMO_PROGRAM_ID_B58).into_vec().map_err(|e| format!("Failed to decode memo program ID: {}", e))?;
    
    if decoded.len() != 32 {
        return Err("Decoded memo program ID is not 32 bytes".to_string());
    }
    
    program_id.copy_from_slice(&decoded);

    Ok(Instruction {
        program_id,
        accounts: Vec::new(),
        data: memo_text.as_bytes().to_vec(),
    })
}
