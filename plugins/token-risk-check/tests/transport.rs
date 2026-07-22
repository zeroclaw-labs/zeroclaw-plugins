use token_risk_check::rpc::{fetch_mint_account, HttpClient};

struct PanicIfCalledClient;
impl HttpClient for PanicIfCalledClient {
    fn post_json(&self, _: &str, _: &str) -> Result<String, String> {
        panic!("RPC should never be called for invalid mint input");
    }
}

#[test]
fn test_invalid_mint_never_reaches_rpc() {
    let client = PanicIfCalledClient;
    
    // 1. Not base58
    let bad_chars = fetch_mint_account(&client, "https://api.mainnet-beta.solana.com", "O0Il!bad_chars");
    assert!(bad_chars.is_err(), "Should fail before RPC on bad chars");
    assert!(bad_chars.unwrap_err().contains("Invalid account address"), "Expected pre-RPC validation error");

    // 2. Valid base58 but wrong length (e.g., 31 bytes instead of 32 bytes)
    // "1111111111111111111111111111111" is 31 '1's.
    let wrong_len = fetch_mint_account(&client, "https://api.mainnet-beta.solana.com", "1111111111111111111111111111111");
    assert!(wrong_len.is_err(), "Should fail before RPC on wrong length");
    assert!(wrong_len.unwrap_err().contains("must be exactly 32 bytes"), "Expected pre-RPC validation error");
}
