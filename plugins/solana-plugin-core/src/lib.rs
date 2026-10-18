use std::fmt;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Pubkey(bytes)
    }

    pub fn from_string(s: &str) -> Result<Self, String> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| format!("Invalid base58: {e}"))?;
        if bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Pubkey(arr))
    }

    pub fn to_string(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl Serialize for Pubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Pubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Pubkey::from_string(&s).map_err(serde::de::Error::custom)
    }
}

// PDA and ATA derivation
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
    let mut bump = 255u8;
    while bump > 0 {
        let mut seeds_with_bump = seeds.to_vec();
        let bump_slice = [bump];
        seeds_with_bump.push(&bump_slice);
        if let Some(addr) = create_program_address(&seeds_with_bump, program_id) {
            return Some((addr, bump));
        }
        bump -= 1;
    }
    None
}

pub fn create_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<Pubkey> {
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(&program_id.0);
    hasher.update(b"ProgramDerivedAddress");
    let hash: [u8; 32] = hasher.finalize().into();

    if is_on_curve(&hash) {
        None
    } else {
        Some(Pubkey(hash))
    }
}

fn is_on_curve(bytes: &[u8; 32]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(bytes).is_ok()
}

pub fn token_program_id() -> Pubkey {
    Pubkey::from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
}

pub fn associated_token_program_id() -> Pubkey {
    Pubkey::from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap()
}

pub fn system_program_id() -> Pubkey {
    Pubkey([0u8; 32])
}

pub fn get_associated_token_address(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    let token_prog = token_program_id();
    let assoc_token_prog = associated_token_program_id();
    let seeds: &[&[u8]] = &[
        wallet.0.as_ref(),
        token_prog.0.as_ref(),
        mint.0.as_ref(),
    ];
    let (addr, _) = find_program_address(seeds, &assoc_token_prog)
        .expect("ATA address derivation should not fail");
    addr
}

// Compact length encoding helper
fn encode_length(mut len: usize, out: &mut Vec<u8>) {
    loop {
        let mut elem = (len & 0x7f) as u8;
        len >>= 7;
        if len == 0 {
            out.push(elem);
            break;
        } else {
            elem |= 0x80;
            out.push(elem);
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
    pub fn writable(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Debug, Clone)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

impl Message {
    pub fn compile(fee_payer: &Pubkey, instructions: &[Instruction], recent_blockhash: [u8; 32]) -> Self {
        let mut account_metas = Vec::new();
        
        // Fee payer is always first, signed and writable
        account_metas.push(AccountMeta::writable(*fee_payer, true));
        
        for inst in instructions {
            for acc in &inst.accounts {
                if let Some(existing) = account_metas.iter_mut().find(|m| m.pubkey == acc.pubkey) {
                    existing.is_signer |= acc.is_signer;
                    existing.is_writable |= acc.is_writable;
                } else {
                    account_metas.push(acc.clone());
                }
            }
            if !account_metas.iter().any(|m| m.pubkey == inst.program_id) {
                account_metas.push(AccountMeta::readonly(inst.program_id, false));
            }
        }
        
        let mut signed_writable = Vec::new();
        let mut signed_readonly = Vec::new();
        let mut unsigned_writable = Vec::new();
        let mut unsigned_readonly = Vec::new();
        
        for meta in account_metas {
            if meta.is_signer {
                if meta.is_writable {
                    signed_writable.push(meta.pubkey);
                } else {
                    signed_readonly.push(meta.pubkey);
                }
            } else {
                if meta.is_writable {
                    unsigned_writable.push(meta.pubkey);
                } else {
                    unsigned_readonly.push(meta.pubkey);
                }
            }
        }
        
        if let Some(pos) = signed_writable.iter().position(|k| k == fee_payer) {
            signed_writable.remove(pos);
        }
        signed_writable.insert(0, *fee_payer);
        
        let mut account_keys = Vec::new();
        account_keys.extend(signed_writable.iter().cloned());
        account_keys.extend(signed_readonly.iter().cloned());
        let num_required_signatures = account_keys.len() as u8;
        let num_readonly_signed_accounts = signed_readonly.len() as u8;
        
        account_keys.extend(unsigned_writable.iter().cloned());
        account_keys.extend(unsigned_readonly.iter().cloned());
        let num_readonly_unsigned_accounts = unsigned_readonly.len() as u8;
        
        let header = MessageHeader {
            num_required_signatures,
            num_readonly_signed_accounts,
            num_readonly_unsigned_accounts,
        };
        
        let compiled_instructions = instructions
            .iter()
            .map(|inst| {
                let program_id_index = account_keys
                    .iter()
                    .position(|k| k == &inst.program_id)
                    .expect("program ID should be in account keys") as u8;
                let accounts = inst
                    .accounts
                    .iter()
                    .map(|acc| {
                        account_keys
                            .iter()
                            .position(|k| k == &acc.pubkey)
                            .expect("account should be in account keys") as u8
                    })
                    .collect();
                CompiledInstruction {
                    program_id_index,
                    accounts,
                    data: inst.data.clone(),
                }
            })
            .collect();
            
        Message {
            header,
            account_keys,
            recent_blockhash,
            instructions: compiled_instructions,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.header.num_required_signatures);
        buf.push(self.header.num_readonly_signed_accounts);
        buf.push(self.header.num_readonly_unsigned_accounts);
        
        encode_length(self.account_keys.len(), &mut buf);
        for key in &self.account_keys {
            buf.extend_from_slice(&key.0);
        }
        
        buf.extend_from_slice(&self.recent_blockhash);
        
        encode_length(self.instructions.len(), &mut buf);
        for inst in &self.instructions {
            buf.push(inst.program_id_index);
            encode_length(inst.accounts.len(), &mut buf);
            buf.extend_from_slice(&inst.accounts);
            encode_length(inst.data.len(), &mut buf);
            buf.extend_from_slice(&inst.data);
        }
        buf
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub signatures: Vec<[u8; 64]>,
    pub message: Message,
}

impl Transaction {
    pub fn new_unsigned(message: Message) -> Self {
        let num_sigs = message.header.num_required_signatures as usize;
        let signatures = vec![[0u8; 64]; num_sigs];
        Self { signatures, message }
    }

    pub fn sign(&mut self, keypairs: &[ed25519_dalek::SigningKey]) {
        let message_bytes = self.message.serialize();
        for (i, key) in keypairs.iter().enumerate() {
            if i < self.signatures.len() {
                use ed25519_dalek::Signer;
                let sig = key.sign(&message_bytes);
                self.signatures[i] = sig.to_bytes();
            }
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_length(self.signatures.len(), &mut buf);
        for sig in &self.signatures {
            buf.extend_from_slice(sig);
        }
        buf.extend_from_slice(&self.message.serialize());
        buf
    }

    pub fn to_base64(&self) -> String {
        base64_encode(&self.serialize())
    }
}

fn base64_encode(input: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((input.len() + 2) / 3 * 4);
    let mut chunks = input.chunks_exact(3);
    while let Some(chunk) = chunks.next() {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        result.push(CHARSET[((n >> 18) & 63) as usize] as char);
        result.push(CHARSET[((n >> 12) & 63) as usize] as char);
        result.push(CHARSET[((n >> 6) & 63) as usize] as char);
        result.push(CHARSET[(n & 63) as usize] as char);
    }
    let remainder = chunks.remainder();
    if remainder.len() == 1 {
        let n = (remainder[0] as u32) << 16;
        result.push(CHARSET[((n >> 18) & 63) as usize] as char);
        result.push(CHARSET[((n >> 12) & 63) as usize] as char);
        result.push('=');
        result.push('=');
    } else if remainder.len() == 2 {
        let n = ((remainder[0] as u32) << 16) | ((remainder[1] as u32) << 8);
        result.push(CHARSET[((n >> 18) & 63) as usize] as char);
        result.push(CHARSET[((n >> 12) & 63) as usize] as char);
        result.push(CHARSET[((n >> 6) & 63) as usize] as char);
        result.push('=');
    }
    result
}

// HttpRequester interface for mocking and clean host testing
pub trait HttpRequester {
    fn post(&self, url: &str, body: &str) -> Result<String, String>;
}

pub fn get_latest_blockhash<R: HttpRequester>(requester: &R, rpc_url: &str) -> Result<[u8; 32], String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash",
        "params": [{
            "commitment": "confirmed"
        }]
    }).to_string();
    
    let resp_str = requester.post(rpc_url, &body)?;
    let parsed: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse blockhash response: {e}"))?;
        
    let blockhash_str = parsed["result"]["value"]["blockhash"]
        .as_str()
        .ok_or_else(|| format!("Invalid blockhash response structure: {parsed}"))?;
        
    let bytes = bs58::decode(blockhash_str)
        .into_vec()
        .map_err(|e| format!("Invalid base58 blockhash: {e}"))?;
    if bytes.len() != 32 {
        return Err("Invalid blockhash length".to_string());
    }
    let mut blockhash = [0u8; 32];
    blockhash.copy_from_slice(&bytes);
    Ok(blockhash)
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct TokenAccountDetails {
    pub mint: String,
    pub owner: String,
    pub delegate: Option<String>,
    pub delegated_amount: Option<u64>,
    pub decimals: u8,
    pub amount: u64,
}

pub fn get_token_account_details<R: HttpRequester>(
    requester: &R,
    rpc_url: &str,
    token_account: &Pubkey,
) -> Result<TokenAccountDetails, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            token_account.to_string(),
            {
                "encoding": "jsonParsed",
                "commitment": "confirmed"
            }
        ]
    }).to_string();
    
    let resp_str = requester.post(rpc_url, &body)?;
    let parsed: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse account info: {e}"))?;
        
    let val = &parsed["result"]["value"];
    if val.is_null() {
        return Err("Account does not exist".to_string());
    }
    
    let data = &val["data"];
    if data["program"].as_str() != Some("spl-token") {
        return Err("Account is not an SPL Token account".to_string());
    }
    
    let parsed_data = &data["parsed"];
    
    let info = &parsed_data["info"];
    let mint = info["mint"].as_str().ok_or("Missing mint")?.to_string();
    let owner = info["owner"].as_str().ok_or("Missing owner")?.to_string();
    let delegate = info["delegate"].as_str().map(|s| s.to_string());
    
    let amount_str = info["tokenAmount"]["amount"].as_str().ok_or("Missing amount")?;
    let amount = amount_str.parse::<u64>().map_err(|e| format!("Invalid amount: {e}"))?;
    
    let decimals = info["tokenAmount"]["decimals"].as_u64().ok_or("Missing decimals")? as u8;
    
    let delegated_amount = if let Some(del_info) = info["delegatedAmount"].as_object() {
        let del_amt_str = del_info.get("amount").and_then(|v| v.as_str()).ok_or("Missing delegated amount")?;
        Some(del_amt_str.parse::<u64>().map_err(|e| format!("Invalid delegated amount: {e}"))?)
    } else {
        None
    };
    
    Ok(TokenAccountDetails {
        mint,
        owner,
        delegate,
        delegated_amount,
        decimals,
        amount,
    })
}

#[derive(Debug, Clone)]
pub struct SignatureInfo {
    pub signature: String,
    pub block_time: Option<i64>,
    pub err: bool,
}

pub fn get_signatures_for_address<R: HttpRequester>(
    requester: &R,
    rpc_url: &str,
    address: &Pubkey,
    limit: usize,
) -> Result<Vec<SignatureInfo>, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            address.to_string(),
            {
                "limit": limit
            }
        ]
    }).to_string();
    
    let resp_str = requester.post(rpc_url, &body)?;
    let parsed: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse signatures: {e}"))?;
        
    let arr = parsed["result"]
        .as_array()
        .ok_or_else(|| format!("Invalid signatures response: {parsed}"))?;
        
    let mut sigs = Vec::new();
    for item in arr {
        let signature = item["signature"].as_str().ok_or("Missing signature")?.to_string();
        let block_time = item["blockTime"].as_i64();
        let err = !item["err"].is_null();
        sigs.push(SignatureInfo { signature, block_time, err });
    }
    Ok(sigs)
}

pub fn get_transaction_transfer_amount<R: HttpRequester>(
    requester: &R,
    rpc_url: &str,
    signature: &str,
    source_token_account: &Pubkey,
) -> Result<u64, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            {
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0
            }
        ]
    }).to_string();
    
    let resp_str = requester.post(rpc_url, &body)?;
    let parsed: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse transaction: {e}"))?;
        
    let result = &parsed["result"];
    if result.is_null() {
        return Ok(0);
    }
    
    let mut total_transferred = 0u64;
    
    let message = &result["transaction"]["message"];
    if let Some(insts) = message["instructions"].as_array() {
        for inst in insts {
            total_transferred += parse_instruction_amount(inst, source_token_account)?;
        }
    }
    
    if let Some(inner_list) = result["meta"]["innerInstructions"].as_array() {
        for inner_group in inner_list {
            if let Some(insts) = inner_group["instructions"].as_array() {
                for inst in insts {
                    total_transferred += parse_instruction_amount(inst, source_token_account)?;
                }
            }
        }
    }
    
    Ok(total_transferred)
}

fn parse_instruction_amount(inst: &serde_json::Value, source_token_account: &Pubkey) -> Result<u64, String> {
    if inst["program"].as_str() == Some("spl-token") {
        let parsed = &inst["parsed"];
        let type_str = parsed["type"].as_str();
        if type_str == Some("transfer") || type_str == Some("transferChecked") {
            let info = &parsed["info"];
            let source = info["source"].as_str().unwrap_or_default();
            if source == source_token_account.to_string() {
                let amount_str = info["amount"].as_str().or_else(|| info["tokenAmount"]["amount"].as_str()).unwrap_or("0");
                let amount = amount_str.parse::<u64>().unwrap_or(0);
                return Ok(amount);
            }
        }
    }
    Ok(0)
}

pub fn send_transaction<R: HttpRequester>(
    requester: &R,
    rpc_url: &str,
    tx_base64: &str,
) -> Result<String, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [
            tx_base64,
            {
                "encoding": "base64",
                "preflightCommitment": "confirmed"
            }
        ]
    }).to_string();
    
    let resp_str = requester.post(rpc_url, &body)?;
    let parsed: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse sendTransaction response: {e}"))?;
        
    if let Some(err) = parsed["error"].as_object() {
        let msg = err.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        return Err(format!("RPC error: {msg}"));
    }
    
    let sig = parsed["result"]
        .as_str()
        .ok_or_else(|| format!("Invalid sendTransaction response: {parsed}"))?;
        
    Ok(sig.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_base58() {
        let expected = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let pubkey = Pubkey::from_string(expected).unwrap();
        assert_eq!(pubkey.to_string(), expected);
    }

    #[test]
    fn test_ata_derivation() {
        let wallet = Pubkey::from_string("DBD8hAwLDRQkTsu6EqviaYNGKPnsAMmQonxf7AH8ZcFY").unwrap();
        let mint = Pubkey::from_string("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU").unwrap();
        let ata = get_associated_token_address(&wallet, &mint);
        // Correct ATA derived via standard Solana SDK
        assert_eq!(ata.to_string(), "Apedt5YdVroQma3W5LxBg44FvmKfYUCyjm65CBDTxyPb");
        assert_ne!(ata.0, [0u8; 32]);
    }

    #[test]
    fn test_transaction_compile_and_serialize() {
        let payer = Pubkey::from_string("DBD8hAwLDRQkTsu6EqviaYNGKPnsAMmQonxf7AH8ZcFY").unwrap();
        let recipient = Pubkey::from_string("DBD8hAwLDRQkTsu6EqviaYNGKPnsAMmQonxf7AH8ZcFY").unwrap();
        let program_id = Pubkey::from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        
        let inst = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::writable(payer, true),
                AccountMeta::writable(recipient, false),
            ],
            data: vec![1, 2, 3],
        };
        
        let blockhash = [7u8; 32];
        let msg = Message::compile(&payer, &[inst], blockhash);
        let mut tx = Transaction::new_unsigned(msg);
        
        let key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        tx.sign(&[key]);
        
        let bytes = tx.serialize();
        assert!(bytes.len() > 0);
        let b64 = tx.to_base64();
        assert!(b64.len() > 0);
    }
}

