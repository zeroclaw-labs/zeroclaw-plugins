//! Pure risk-assessment logic. No wasm, no wit-bindgen — this whole module is
//! exercised by `cargo test` on the host against `solana_core::rpc::MockTransport`.
//!
//! Custody tier: **T0 (Read)**. This tool only issues RPC reads and returns
//! text. It holds no key and constructs no transaction, so there is nothing a
//! prompt injection can make it *do* — the worst case is a wrong string, never a
//! moved lamport. See the README threat model.

use solana_core::error::CoreError;
use solana_core::mint::{decode_mint, MintAccount, MintExtension};
use solana_core::pubkey::{programs, Pubkey};
use solana_core::rpc::{RpcTransport, SolanaRpc};
use solana_core::shape;

/// Severity of a single finding, worst-wins for the overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Green,
    Amber,
    Red,
}

impl Severity {
    fn dot(self) -> &'static str {
        match self {
            Severity::Green => "🟢",
            Severity::Amber => "🟠",
            Severity::Red => "🔴",
        }
    }
    fn word(self) -> &'static str {
        match self {
            Severity::Green => "GREEN",
            Severity::Amber => "AMBER",
            Severity::Red => "RED",
        }
    }
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub label: String,
}

/// The full assessment, ready to render into ~200 tokens of chat text.
#[derive(Debug, Clone)]
pub struct RiskReport {
    pub mint: Pubkey,
    pub program: &'static str,
    pub decimals: u8,
    pub supply_ui: String,
    pub verdict: Severity,
    pub findings: Vec<Finding>,
    pub top1_pct: Option<f64>,
    pub top10_pct: Option<f64>,
    pub holder_note: Option<String>,
}

/// Run the assessment: two RPC reads (`getAccountInfo`, `getTokenLargestAccounts`),
/// no signing. Errors are user-facing strings (bad mint, not a token, RPC down).
pub fn assess<T: RpcTransport>(rpc: &SolanaRpc<T>, mint: &Pubkey) -> Result<RiskReport, CoreError> {
    let account = rpc
        .get_account_info(mint)?
        .ok_or_else(|| CoreError::Invalid("no account at that address (not a token mint)".into()))?;

    let is_2022 = account.owner == programs::token_2022();
    let is_legacy = account.owner == programs::token();
    if !is_2022 && !is_legacy {
        return Err(CoreError::Invalid(format!(
            "not an SPL token mint; owned by {}",
            shape::short_pubkey(&account.owner)
        )));
    }

    let decoded = decode_mint(&account.data, is_2022)?;
    let mut findings = classify(&decoded);

    // Holder concentration from the largest-accounts read. Best-effort: if it
    // fails or supply is zero, we still return the authority/extension findings.
    let (top1_pct, top10_pct, holder_note) = match rpc.get_token_largest_accounts(mint) {
        Ok(holders) if decoded.supply > 0 => {
            let supply = decoded.supply as f64;
            let top1 = holders.first().map(|h| h.amount as f64 / supply);
            let top10: f64 = holders.iter().take(10).map(|h| h.amount as f64 / supply).sum();
            if let Some(p) = top1 {
                if p >= 0.50 {
                    findings.push(Finding {
                        severity: Severity::Amber,
                        label: format!(
                            "Largest holder controls {} of supply (may be an LP/exchange vault)",
                            shape::percent(p)
                        ),
                    });
                } else if p >= 0.25 {
                    findings.push(Finding {
                        severity: Severity::Amber,
                        label: format!("Concentrated: top holder {}", shape::percent(p)),
                    });
                }
            }
            (
                top1,
                Some(top10),
                Some("top holders may include LP/exchange vaults".to_string()),
            )
        }
        _ => (None, None, None),
    };

    // A clean bill of health deserves an explicit green line.
    if findings.is_empty() {
        findings.push(Finding {
            severity: Severity::Green,
            label: "Mint authority renounced, no freeze authority, no risky extensions".into(),
        });
    }

    let verdict = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Green);

    Ok(RiskReport {
        mint: *mint,
        program: if is_2022 { "Token-2022" } else { "SPL Token" },
        decimals: decoded.decimals,
        supply_ui: shape::ui_amount(decoded.supply as u128, decoded.decimals),
        verdict,
        findings,
        top1_pct,
        top10_pct,
        holder_note,
    })
}

/// Turn decoded mint state into findings. This is the opinionated core and is
/// unit-tested exhaustively.
fn classify(m: &MintAccount) -> Vec<Finding> {
    let mut f = Vec::new();

    if m.mint_authority.is_some() {
        f.push(Finding {
            severity: Severity::Amber,
            label: "Mint authority active — supply can still be inflated".into(),
        });
    }
    if m.freeze_authority.is_some() {
        f.push(Finding {
            severity: Severity::Amber,
            label: "Freeze authority active — your account can be frozen".into(),
        });
    }

    for ext in &m.extensions {
        match ext {
            MintExtension::TransferHook { program_id: Some(_) } => f.push(Finding {
                severity: Severity::Red,
                label: "Transfer hook active — an arbitrary program runs on every transfer (can block or redirect)".into(),
            }),
            MintExtension::TransferHook { program_id: None } => {}
            MintExtension::PermanentDelegate { delegate: Some(_) } => f.push(Finding {
                severity: Severity::Red,
                label: "Permanent delegate set — a third party can move anyone's tokens without consent".into(),
            }),
            MintExtension::PermanentDelegate { delegate: None } => {}
            MintExtension::NonTransferable => f.push(Finding {
                severity: Severity::Red,
                label: "Non-transferable (soulbound) — these tokens cannot be sent".into(),
            }),
            MintExtension::DefaultAccountState { frozen: true } => f.push(Finding {
                severity: Severity::Red,
                label: "Accounts default to FROZEN — you can't transfer until an authority thaws you".into(),
            }),
            MintExtension::DefaultAccountState { frozen: false } => {}
            MintExtension::TransferFeeConfig { basis_points, .. } if *basis_points > 0 => {
                f.push(Finding {
                    severity: Severity::Amber,
                    label: format!(
                        "Transfer fee {} bps ({}%) skimmed on every transfer",
                        basis_points,
                        shape::ui_amount(*basis_points as u128 * 100, 2)
                    ),
                })
            }
            MintExtension::TransferFeeConfig { .. } => {}
            MintExtension::Pausable { paused: true } => f.push(Finding {
                severity: Severity::Red,
                label: "Transfers are currently PAUSED".into(),
            }),
            MintExtension::Pausable { paused: false } => f.push(Finding {
                severity: Severity::Amber,
                label: "Pausable — transfers can be globally halted by an authority".into(),
            }),
            MintExtension::MintCloseAuthority { authority: Some(_) } => f.push(Finding {
                severity: Severity::Amber,
                label: "Mint can be closed by its close authority".into(),
            }),
            MintExtension::MintCloseAuthority { authority: None } => {}
            MintExtension::InterestBearing => f.push(Finding {
                severity: Severity::Amber,
                label: "Interest-bearing — displayed balance differs from raw amount".into(),
            }),
            MintExtension::ConfidentialTransfer => f.push(Finding {
                severity: Severity::Amber,
                label: "Confidential transfers enabled — amounts can be hidden".into(),
            }),
            MintExtension::Other(t) => f.push(Finding {
                severity: Severity::Amber,
                label: format!("Unrecognized Token-2022 extension #{t} — review before trusting"),
            }),
        }
    }

    f
}

/// Render the report as compact chat text (~200 tokens, never raw JSON).
pub fn render(r: &RiskReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} {} — token risk check\n",
        r.verdict.dot(),
        r.verdict.word()
    ));
    out.push_str(&format!(
        "Mint {} ({})  decimals {}  supply {}\n",
        shape::short_pubkey(&r.mint),
        r.program,
        r.decimals,
        r.supply_ui
    ));
    out.push_str("Findings:\n");
    for f in &r.findings {
        out.push_str(&format!("• {} {}\n", f.severity.dot(), f.label));
    }
    if let (Some(t1), Some(t10)) = (r.top1_pct, r.top10_pct) {
        out.push_str(&format!(
            "Holders: top1 {}, top10 {}",
            shape::percent(t1),
            shape::percent(t10)
        ));
        if let Some(note) = &r.holder_note {
            out.push_str(&format!(" ({note})"));
        }
        out.push('\n');
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use solana_core::base64;
    use solana_core::rpc::MockTransport;

    // ---- helpers to fabricate account bytes + RPC envelopes -----------------

    fn base_mint(mint_auth: bool, supply: u64, decimals: u8, freeze: bool) -> Vec<u8> {
        let mut d = vec![0u8; 82];
        if mint_auth {
            d[0..4].copy_from_slice(&1u32.to_le_bytes());
            d[4..36].copy_from_slice(&[1u8; 32]);
        }
        d[36..44].copy_from_slice(&supply.to_le_bytes());
        d[44] = decimals;
        d[45] = 1;
        if freeze {
            d[46..50].copy_from_slice(&1u32.to_le_bytes());
            d[50..82].copy_from_slice(&[2u8; 32]);
        }
        d
    }

    fn with_ext(mut base: Vec<u8>, tlv: &[(u16, Vec<u8>)]) -> Vec<u8> {
        base.resize(165, 0);
        base.push(1);
        for (t, v) in tlv {
            base.extend_from_slice(&t.to_le_bytes());
            base.extend_from_slice(&(v.len() as u16).to_le_bytes());
            base.extend_from_slice(v);
        }
        base
    }

    fn account_env(owner: &str, data: &[u8]) -> serde_json::Value {
        json!({"context": {"slot": 1}, "value": {
            "lamports": 1_000_000u64,
            "owner": owner,
            "data": [base64::encode(data), "base64"],
            "executable": false,
            "rentEpoch": 0
        }})
    }

    fn holders_env(pairs: &[(&str, &str)]) -> serde_json::Value {
        let arr: Vec<_> = pairs
            .iter()
            .map(|(addr, amt)| json!({"address": addr, "amount": amt, "decimals": 6, "uiAmountString": "0"}))
            .collect();
        json!({"context": {"slot": 1}, "value": arr})
    }

    const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const TOKEN22: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    const SYSTEM: &str = "11111111111111111111111111111111";
    const A_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn rpc(results: Vec<serde_json::Value>) -> SolanaRpc<MockTransport> {
        SolanaRpc::new(MockTransport::with_results(results))
    }

    // ---- tests --------------------------------------------------------------

    #[test]
    fn clean_renounced_mint_is_green() {
        // No mint authority, no freeze, no extensions, well distributed.
        let data = base_mint(false, 1_000_000_000, 6, false);
        let r = assess(
            &rpc(vec![
                account_env(TOKEN, &data),
                holders_env(&[(SYSTEM, "10000000"), (A_MINT, "10000000")]),
            ]),
            &Pubkey::from_base58(A_MINT).unwrap(),
        )
        .unwrap();
        assert_eq!(r.verdict, Severity::Green);
        assert!(render(&r).contains("GREEN"));
    }

    #[test]
    fn mint_and_freeze_authority_are_amber() {
        let data = base_mint(true, 1_000_000_000, 6, true);
        let r = assess(
            &rpc(vec![
                account_env(TOKEN, &data),
                holders_env(&[(SYSTEM, "1")]),
            ]),
            &Pubkey::from_base58(A_MINT).unwrap(),
        )
        .unwrap();
        assert_eq!(r.verdict, Severity::Amber);
        let text = render(&r);
        assert!(text.contains("Mint authority active"));
        assert!(text.contains("Freeze authority active"));
    }

    #[test]
    fn active_transfer_hook_is_red() {
        let mut hook = vec![0u8; 64];
        hook[32..64].copy_from_slice(&[9u8; 32]); // program_id set
        let data = with_ext(base_mint(false, 1000, 0, false), &[(14, hook)]);
        let r = assess(
            &rpc(vec![
                account_env(TOKEN22, &data),
                holders_env(&[(SYSTEM, "1")]),
            ]),
            &Pubkey::from_base58(A_MINT).unwrap(),
        )
        .unwrap();
        assert_eq!(r.verdict, Severity::Red);
        assert!(render(&r).contains("Transfer hook active"));
    }

    #[test]
    fn permanent_delegate_is_red() {
        let data = with_ext(base_mint(false, 1000, 0, false), &[(12, vec![7u8; 32])]);
        let r = assess(
            &rpc(vec![account_env(TOKEN22, &data), holders_env(&[])]),
            &Pubkey::from_base58(A_MINT).unwrap(),
        )
        .unwrap();
        assert_eq!(r.verdict, Severity::Red);
        assert!(render(&r).contains("Permanent delegate"));
    }

    #[test]
    fn transfer_fee_is_amber_with_percentage() {
        let mut v = vec![0u8; 108];
        v[106..108].copy_from_slice(&250u16.to_le_bytes()); // 2.5%
        let data = with_ext(base_mint(false, 1000, 6, false), &[(1, v)]);
        let r = assess(
            &rpc(vec![account_env(TOKEN22, &data), holders_env(&[])]),
            &Pubkey::from_base58(A_MINT).unwrap(),
        )
        .unwrap();
        assert_eq!(r.verdict, Severity::Amber);
        assert!(render(&r).contains("250 bps"));
    }

    #[test]
    fn concentration_over_50pct_flags_amber() {
        // supply 1000, top holder 900 = 90%.
        let data = base_mint(false, 1000, 0, false);
        let r = assess(
            &rpc(vec![
                account_env(TOKEN, &data),
                holders_env(&[(SYSTEM, "900"), (A_MINT, "100")]),
            ]),
            &Pubkey::from_base58(A_MINT).unwrap(),
        )
        .unwrap();
        assert_eq!(r.verdict, Severity::Amber);
        assert_eq!(r.top1_pct, Some(0.9));
        assert!(render(&r).contains("Largest holder controls"));
    }

    #[test]
    fn non_spl_owner_is_rejected() {
        // owned by System program => not a token mint.
        let err = assess(
            &rpc(vec![account_env(SYSTEM, &[0u8; 82])]),
            &Pubkey::from_base58(A_MINT).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(_)));
    }

    #[test]
    fn missing_account_is_rejected() {
        let err = assess(
            &rpc(vec![json!({"context": {"slot": 1}, "value": null})]),
            &Pubkey::from_base58(A_MINT).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(_)));
    }

    #[test]
    fn output_is_compact() {
        // Guard against context-flooding: a full report stays well under ~1.2KB.
        let data = base_mint(true, 5_000_000_000_000_000, 6, true);
        let r = assess(
            &rpc(vec![
                account_env(TOKEN, &data),
                holders_env(&[(SYSTEM, "1000"), (A_MINT, "500")]),
            ]),
            &Pubkey::from_base58(A_MINT).unwrap(),
        )
        .unwrap();
        assert!(render(&r).len() < 1200, "report too long: {}", render(&r).len());
    }
}
