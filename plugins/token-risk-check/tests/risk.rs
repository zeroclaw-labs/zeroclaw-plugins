//! Integration tests for the token-risk core, exercised exactly as the wasm
//! `execute` entry point drives it: decode a mint, decode extensions, compute
//! holder stats, assess, render. Runs on the host with a plain `cargo test`,
//! covering the same code the component runs inside the wasmtime host.

use solana_core::mint::{parse_extensions, parse_mint, MINT_LEN};
use token_risk_check::risk::{assess, holder_stats, render, RiskInput, Severity, TokenProgram};

/// Build a raw 82-byte SPL mint (as `getAccountInfo` would return, decoded).
fn raw_mint(mint_auth: Option<[u8; 32]>, freeze_auth: Option<[u8; 32]>, supply: u64) -> Vec<u8> {
    let mut b = vec![0u8; MINT_LEN];
    if let Some(k) = mint_auth {
        b[0..4].copy_from_slice(&1u32.to_le_bytes());
        b[4..36].copy_from_slice(&k);
    }
    b[36..44].copy_from_slice(&supply.to_le_bytes());
    b[44] = 6; // decimals
    b[45] = 1; // initialized
    if let Some(k) = freeze_auth {
        b[46..50].copy_from_slice(&1u32.to_le_bytes());
        b[50..82].copy_from_slice(&k);
    }
    b
}

#[test]
fn clean_renounced_token_reads_green() {
    let data = raw_mint(None, None, 1_000_000_000_000);
    let input = RiskInput {
        program: TokenProgram::SplToken,
        mint: parse_mint(&data).unwrap(),
        extensions: parse_extensions(&data),
        holders: holder_stats(&[10, 10, 10], 1_000_000_000_000),
    };
    let report = assess(&input);
    assert_eq!(report.level, Severity::Green);

    let text = render(
        "So11111111111111111111111111111111111111112",
        &input,
        &report,
    );
    assert!(text.contains("🟢 GREEN"));
    assert!(text.contains("Mint authority renounced"));
}

#[test]
fn mintable_freezable_token_reads_amber() {
    let data = raw_mint(Some([1u8; 32]), Some([2u8; 32]), 1_000_000);
    let input = RiskInput {
        program: TokenProgram::SplToken,
        mint: parse_mint(&data).unwrap(),
        extensions: parse_extensions(&data),
        holders: None,
    };
    let report = assess(&input);
    assert_eq!(report.level, Severity::Amber);
    let text = render("MintAddr", &input, &report);
    assert!(text.contains("Mint authority active"));
    assert!(text.contains("Freeze authority active"));
}

#[test]
fn concentrated_holdings_dominate_the_verdict() {
    let data = raw_mint(None, None, 1_000);
    // one holder with 900 of 1000 supply
    let input = RiskInput {
        program: TokenProgram::SplToken,
        mint: parse_mint(&data).unwrap(),
        extensions: parse_extensions(&data),
        holders: holder_stats(&[900, 50, 50], 1_000),
    };
    let report = assess(&input);
    assert_eq!(report.level, Severity::Red);
    let text = render("MintAddr", &input, &report);
    assert!(text.contains("Top holder controls 90.0%"));
}

#[test]
fn output_is_compact_enough_for_a_context_window() {
    // Worst case with many findings still renders small (trap #3).
    let data = raw_mint(Some([1u8; 32]), Some([2u8; 32]), 1_000);
    let input = RiskInput {
        program: TokenProgram::SplToken2022,
        mint: parse_mint(&data).unwrap(),
        extensions: vec![
            solana_core::mint::MintExtension::PermanentDelegate(Some([3u8; 32])),
            solana_core::mint::MintExtension::TransferFee {
                basis_points: 250,
                maximum_fee: 0,
            },
            solana_core::mint::MintExtension::TransferHook(Some([4u8; 32])),
        ],
        holders: holder_stats(&[600, 300, 50], 1_000),
    };
    let report = assess(&input);
    let text = render("MintAddr", &input, &report);
    assert!(
        text.len() < 1_000,
        "render should stay compact: {} bytes",
        text.len()
    );
    assert!(text.starts_with("RISK: 🔴 RED"));
}
