//! Deterministic offline demo of the same scoring core used by the component.
//! No wallet, key, RPC, or network access is involved.

use token_risk_check::risk::{
    assess, HolderEvidence, LpEvidence, LpStatus, MarketEvidence, MintEvidence, RiskConfig,
    RiskEvidence, TokenProgram,
};

const DEMO_MINT: &str = "So11111111111111111111111111111111111111112";

fn safe_mint() -> MintEvidence {
    MintEvidence {
        program: TokenProgram::Legacy,
        supply: 1_000_000,
        decimals: 6,
        mint_authority: false,
        freeze_authority: false,
        extension_names: Vec::new(),
        transfer_fee_bps: None,
        transfer_fee_authority: false,
        transfer_hook: false,
        permanent_delegate: false,
        default_frozen: false,
        non_transferable: false,
        confidential_transfer: false,
        pausable_authority: false,
        paused: false,
        permissioned_burn_authority: false,
        scaled_ui_amount_authority: false,
        unassessed_extensions: Vec::new(),
    }
}

fn complete_evidence(mint: MintEvidence) -> RiskEvidence {
    RiskEvidence {
        mint,
        holders: Some(HolderEvidence {
            owner_amounts: vec![
                ("owner-a".into(), 100_000),
                ("owner-b".into(), 100_000),
                ("owner-c".into(), 100_000),
                ("owner-d".into(), 100_000),
            ],
            unresolved_accounts: 0,
        }),
        holders_error: None,
        market: Some(MarketEvidence {
            pair_count: 2,
            max_liquidity_usd: 100_000.0,
            dex_id: Some("orca".into()),
            pair_address: Some("demo-pair".into()),
        }),
        market_error: None,
        lp_security: Some(LpEvidence {
            status: LpStatus::Locked,
            burned_pct: Some(0.0),
            locked_pct: Some(100.0),
            pool_type: Some("standard".into()),
            provider: "fixture",
        }),
        lp_security_error: None,
    }
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_else(|| "red".to_string());
    let evidence = match scenario.as_str() {
        "green" => complete_evidence(safe_mint()),
        "red" => {
            let mut mint = safe_mint();
            mint.program = TokenProgram::Token2022;
            mint.extension_names = vec!["transferHook".into(), "permanentDelegate".into()];
            mint.transfer_hook = true;
            mint.permanent_delegate = true;
            mint.transfer_fee_bps = Some(1_250);
            complete_evidence(mint)
        }
        "incomplete" => RiskEvidence {
            mint: safe_mint(),
            holders: None,
            holders_error: Some("demo RPC timeout".into()),
            market: None,
            market_error: Some("demo market timeout".into()),
            lp_security: None,
            lp_security_error: Some("demo LP-security timeout".into()),
        },
        _ => {
            eprintln!("usage: cargo run --example demo -- [green|red|incomplete]");
            std::process::exit(2);
        }
    };

    let report = assess(DEMO_MINT, &evidence, &RiskConfig::default());
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("demo report must serialize")
    );
}
