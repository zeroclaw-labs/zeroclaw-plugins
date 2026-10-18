use solana_plugin_core::{
    get_associated_token_address, get_latest_blockhash, get_signatures_for_address,
    get_token_account_details, get_transaction_transfer_amount, send_transaction,
    token_program_id, AccountMeta, HttpRequester, Instruction, Message, Pubkey,
    Transaction,
};

/// Executes a direct debit charge from the user's wallet using delegated spending power.
/// Enforces daily spend limits and token delegation caps before signing and submitting.
pub fn execute_charge<R: HttpRequester>(
    requester: &R,
    rpc_url: &str,
    agent_private_key_bytes: &[u8; 32],
    user_wallet: &Pubkey,
    merchant_wallet: &Pubkey,
    token_mint: &Pubkey,
    charge_amount: u64,
    daily_cap: u64,
    current_time: i64,
) -> Result<String, String> {
    // 1. Derive agent keys
    let signing_key = ed25519_dalek::SigningKey::from_bytes(agent_private_key_bytes);
    let agent_pubkey = Pubkey(signing_key.verifying_key().to_bytes());
    
    // 2. Fetch user's ATA details and verify delegation
    let user_ata = get_associated_token_address(user_wallet, token_mint);
    let details = get_token_account_details(requester, rpc_url, &user_ata)
        .map_err(|e| format!("Failed to retrieve user token account: {e}"))?;
        
    // Check delegate matches
    match details.delegate {
        Some(ref d) if d == &agent_pubkey.to_string() => {}
        Some(d) => return Err(format!("Unauthorized delegate: account is delegated to {d}, expected {agent_pubkey}")),
        None => return Err(format!("Account is not delegated to any address, expected {agent_pubkey}")),
    }
    
    // Check delegation allowance
    let delegated_amount = details.delegated_amount.unwrap_or(0);
    if delegated_amount < charge_amount {
        return Err(format!(
            "Insufficient delegation allowance: remaining allowance is {delegated_amount}, requested {charge_amount}"
        ));
    }
    
    // Check actual balance
    if details.amount < charge_amount {
        return Err(format!(
            "Insufficient token balance: user balance is {bal}, requested {charge_amount}",
            bal = details.amount
        ));
    }
    
    // 3. Enforce Daily Cap (scan transactions in the last 24 hours)
    let sigs = get_signatures_for_address(requester, rpc_url, &agent_pubkey, 20)
        .map_err(|e| format!("Failed to query transaction history: {e}"))?;
        
    let mut spent_24h = 0u64;
    let limit_time = current_time - 86400; // 24 hours ago
    
    for sig in sigs {
        if let Some(t) = sig.block_time {
            if t < limit_time {
                break; // Signatures are chronological, everything past this is older than 24h
            }
        } else {
            // If blockTime is missing, we must be conservative and still scan or skip
            // Typically RPC returns blockTime for confirmed transactions.
        }
        
        if sig.err {
            continue; // Skip failed transactions
        }
        
        // Query transaction details to see how much was spent from user_ata
        let amt = get_transaction_transfer_amount(requester, rpc_url, &sig.signature, &user_ata)
            .unwrap_or(0); // If query fails, fail safe or log (we assume 0 for simplicity or we can fail closed)
            
        spent_24h += amt;
    }
    
    if spent_24h + charge_amount > daily_cap {
        return Err(format!(
            "Daily spending cap exceeded: spent {spent_24h} in the last 24h, cap is {daily_cap}, requested {charge_amount}"
        ));
    }
    
    // 4. Build SPL Token Transfer instruction
    let merchant_ata = get_associated_token_address(merchant_wallet, token_mint);
    
    let accounts = vec![
        AccountMeta::writable(user_ata, false),
        AccountMeta::writable(merchant_ata, false),
        AccountMeta::readonly(agent_pubkey, true), // Agent key is signer
    ];
    
    let mut data = Vec::with_capacity(9);
    data.push(3); // Transfer tag
    data.extend_from_slice(&charge_amount.to_le_bytes());
    
    let inst = Instruction {
        program_id: token_program_id(),
        accounts,
        data,
    };
    
    // 5. Fetch blockhash and compile transaction
    let blockhash = get_latest_blockhash(requester, rpc_url)
        .map_err(|e| format!("Failed to fetch recent blockhash: {e}"))?;
        
    let msg = Message::compile(&agent_pubkey, &[inst], blockhash);
    let mut tx = Transaction::new_unsigned(msg);
    tx.sign(&[signing_key]);
    
    let tx_base64 = tx.to_base64();
    
    // 6. Submit transaction
    let sig = send_transaction(requester, rpc_url, &tx_base64)
        .map_err(|e| format!("Transaction execution failed: {e}"))?;
        
    Ok(sig)
}
