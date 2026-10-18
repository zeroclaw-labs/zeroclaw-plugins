//! Integration tests for the portfolio-brief core, exercised as the wasm
//! `execute` path drives it: valued holdings in, shaped brief out. Host-run with
//! a plain `cargo test`, no network.

use portfolio_brief::brief::{build, render, Holding};

fn h(label: &str, amount: f64, usd: Option<f64>, chg: Option<f64>) -> Holding {
    Holding {
        label: label.to_string(),
        ui_amount: amount,
        usd_value: usd,
        change_24h_pct: chg,
    }
}

#[test]
fn realistic_wallet_renders_a_compact_sorted_brief() {
    let holdings = vec![
        h("SOL", 12.5, Some(977.13), Some(2.3)),
        h("USDC", 250.0, Some(250.0), Some(-0.01)),
        h("BONK", 1_200_000.0, Some(7.43), Some(5.1)),
        h("Abc1…wxyz", 5.0, None, None), // unpriced dust
    ];
    let brief = build(holdings, 10);
    let text = render("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", &brief);

    // Total is the sum of priced holdings.
    assert!(text.contains("total ~$1,234.56"));
    // Sorted by value: SOL first.
    let sol_pos = text.find("SOL").unwrap();
    let bonk_pos = text.find("BONK").unwrap();
    assert!(sol_pos < bonk_pos);
    // Unpriced dust is summarized, not listed as a value line.
    assert!(text.contains("1 unpriced token"));
    // Stays small enough for a briefing SOP.
    assert!(
        text.len() < 500,
        "brief should be compact: {} bytes",
        text.len()
    );
}

#[test]
fn empty_wallet_is_handled_gracefully() {
    let brief = build(vec![], 10);
    let text = render("owner", &brief);
    assert!(text.contains("total ~$0"));
    assert!(text.contains("no priced holdings"));
}
