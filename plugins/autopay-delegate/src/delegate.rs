use solana_plugin_core::{
    get_associated_token_address, token_program_id, AccountMeta, Instruction, Message, Pubkey,
    Transaction,
};

/// Build an unsigned transaction that delegates SPL token spending power from the owner to the agent.
pub fn build_delegate_transaction(
    owner_wallet: &Pubkey,
    delegate_wallet: &Pubkey,
    token_mint: &Pubkey,
    amount: u64,
    recent_blockhash: [u8; 32],
) -> Result<String, String> {
    let source_ata = get_associated_token_address(owner_wallet, token_mint);
    
    let accounts = vec![
        AccountMeta::writable(source_ata, false),
        AccountMeta::readonly(*delegate_wallet, false),
        AccountMeta::readonly(*owner_wallet, true),
    ];
    
    let mut data = Vec::with_capacity(9);
    data.push(4); // Approve tag
    data.extend_from_slice(&amount.to_le_bytes());
    
    let inst = Instruction {
        program_id: token_program_id(),
        accounts,
        data,
    };
    
    let msg = Message::compile(owner_wallet, &[inst], recent_blockhash);
    let tx = Transaction::new_unsigned(msg);
    Ok(tx.to_base64())
}
