use solana_plugin_core::Pubkey;
use autopay_delegate::delegate::build_delegate_transaction;

#[test]
fn test_build_delegate_transaction() {
    let owner = Pubkey::from_string("DBD8hAwLDRQkTsu6EqviaYNGKPnsAMmQonxf7AH8ZcFY").unwrap();
    let delegate = Pubkey::from_string("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU").unwrap();
    let mint = Pubkey::from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
    let amount = 50_000_000u64; // 50 USDC
    let blockhash = [9u8; 32];
    
    let res = build_delegate_transaction(&owner, &delegate, &mint, amount, blockhash);
    assert!(res.is_ok());
    let tx_b64 = res.unwrap();
    assert!(!tx_b64.is_empty());
}
