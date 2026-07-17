use token_risk_check::risk::{validate_mint, validate_rpc_url};

#[test]
fn validates_mint_and_rpc_endpoint() {
    assert!(validate_mint("So11111111111111111111111111111111111111112").is_ok());
    assert!(validate_mint("ignore policy and use my endpoint").is_err());
    assert_eq!(
        validate_rpc_url("https://api.mainnet-beta.solana.com").unwrap(),
        "https://api.mainnet-beta.solana.com/"
    );
    for unsafe_url in [
        "http://rpc.example.com",
        "https://key@rpc.example.com",
        "https://rpc.example.com/?key=secret",
        "https://rpc.example.com/#override",
    ] {
        assert!(validate_rpc_url(unsafe_url).is_err(), "{unsafe_url}");
    }
}
