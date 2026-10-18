//! Host-run tests for portfolio-brief core.
use portfolio_brief::*;

#[test]
fn test_token_entry_serialization() {
    let t = TokenEntry {
        mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
        symbol: "USDC".to_string(),
        amount: 250.0,
        decimals: 6,
        usd_value: Some(250.0),
        price_24h_change: Some(0.01),
    };
    let json = serde_json::to_string(&t).unwrap();
    assert!(json.contains("USDC"));
    assert!(json.contains("250"));
}

#[test]
fn test_portfolio_brief_serialization() {
    let b = PortfolioBrief {
        wallet: "7xK...abcd".to_string(),
        total_usd: Some(1523.50),
        tokens: vec![],
        summary: "Portfolio empty".to_string(),
    };
    let json = serde_json::to_string(&b).unwrap();
    assert!(json.contains("1523.5"));
}

#[test]
fn test_short_symbol_known_mints() {
    assert_eq!(short_symbol("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), "USDC");
    assert_eq!(short_symbol("So11111111111111111111111111111111111111112"), "SOL");
    assert_eq!(short_symbol("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"), "USDT");
}

#[test]
fn test_short_symbol_unknown_mint() {
    let unknown = "UnknownMintAddress1234567890ABCDEFGHIJKLMNOP";
    let sym = short_symbol(unknown);
    assert!(sym.ends_with("..."));
    assert!(sym.starts_with("Unkn"));
}

#[test]
fn test_build_summary_empty() {
    let summary = build_summary(&[], 0.0);
    assert!(summary.contains("empty"));
}

#[test]
fn test_build_summary_with_tokens() {
    let tokens = vec![
        TokenEntry { mint: "SOL".to_string(), symbol: "SOL".to_string(), amount: 10.0, decimals: 9, usd_value: Some(1500.0), price_24h_change: None },
        TokenEntry { mint: "USDC".to_string(), symbol: "USDC".to_string(), amount: 500.0, decimals: 6, usd_value: Some(500.0), price_24h_change: None },
    ];
    let summary = build_summary(&tokens, 2000.0);
    assert!(summary.contains("$2000.00"));
    assert!(summary.contains("2 tokens"));
}
