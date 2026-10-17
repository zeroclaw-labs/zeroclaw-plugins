//! Pure risk analysis and output shaping. Turns parsed mint facts + holder
//! amounts into a red/amber/green verdict with reasons, rendered compactly —
//! an agent context window is a paid resource, so the report is ~200 tokens,
//! not the RPC's 40KB.

use crate::spl::{Extension, MintInfo, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Green,
    Amber,
    Red,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Green => "GREEN",
            Verdict::Amber => "AMBER",
            Verdict::Red => "RED",
        }
    }
}

#[derive(Debug)]
pub struct Reason {
    pub severity: Verdict,
    pub text: String,
}

#[derive(Debug)]
pub struct Report {
    pub verdict: Verdict,
    pub reasons: Vec<Reason>,
    pub program: &'static str,
    pub supply_ui: String,
    pub top1_pct: Option<f64>,
    pub top10_pct: Option<f64>,
}

/// Concentration thresholds. getTokenLargestAccounts can't tell an AMM pool or
/// a locker from a whale wallet, so these fire as AMBER (context needed), and
/// only an outright majority holder escalates to RED.
const TOP1_AMBER: f64 = 30.0;
const TOP1_RED: f64 = 50.0;
const TOP10_AMBER: f64 = 70.0;

pub fn analyze(
    mint: &MintInfo,
    owner_program: &str,
    supply: u128,
    largest: &[u128],
) -> Result<Report, String> {
    let program = match owner_program {
        TOKEN_PROGRAM => "spl-token",
        TOKEN_2022_PROGRAM => "token-2022",
        other => return Err(format!("account is not a token mint (owner {other})")),
    };

    let mut reasons = Vec::new();
    let mut push = |severity: Verdict, text: String| reasons.push(Reason { severity, text });

    if mint.mint_authority.is_some() {
        push(
            Verdict::Amber,
            "mint authority live: supply can be inflated at will".into(),
        );
    }
    if mint.freeze_authority.is_some() {
        push(
            Verdict::Amber,
            "freeze authority live: any holder account can be frozen".into(),
        );
    }

    for ext in &mint.extensions {
        match ext {
            Extension::PermanentDelegate { .. } => push(
                Verdict::Red,
                "permanent delegate: a fixed key can transfer or burn ANY holder's tokens".into(),
            ),
            Extension::TransferHook {
                program_id: Some(_),
            } => push(
                Verdict::Amber,
                "transfer hook: an external program runs on every transfer and can reject them"
                    .into(),
            ),
            Extension::DefaultAccountState { frozen: true } => push(
                Verdict::Red,
                "default account state FROZEN: new holders cannot move tokens until thawed".into(),
            ),
            Extension::NonTransferable => push(
                Verdict::Red,
                "non-transferable (soulbound): tokens cannot be sold or moved".into(),
            ),
            Extension::TransferFee { basis_points } if *basis_points > 0 => push(
                if *basis_points >= 1000 {
                    Verdict::Red
                } else {
                    Verdict::Amber
                },
                format!(
                    "transfer fee {}.{:02}% taken on every transfer",
                    basis_points / 100,
                    basis_points % 100
                ),
            ),
            Extension::InterestBearing => push(
                Verdict::Amber,
                "interest-bearing: displayed balance drifts from raw amount".into(),
            ),
            Extension::Pausable => push(
                Verdict::Amber,
                "pausable: the issuer can halt ALL transfers at any time".into(),
            ),
            Extension::ScaledUiAmount => push(
                Verdict::Amber,
                "scaled UI amount: displayed balances use an issuer-set multiplier".into(),
            ),
            Extension::ConfidentialMintBurn => push(
                Verdict::Amber,
                "confidential mint/burn: supply changes can be hidden".into(),
            ),
            Extension::PermissionedBurn => push(
                Verdict::Amber,
                "permissioned burn: issuer-mediated burn semantics — review issuer docs".into(),
            ),
            Extension::Unknown(ty) => push(
                Verdict::Amber,
                format!("unrecognized Token-2022 extension type {ty}: behavior unknown"),
            ),
            _ => {}
        }
    }

    let pct = |part: u128| -> Option<f64> {
        (supply > 0).then(|| (part as f64 / supply as f64) * 100.0)
    };
    let top1_pct = largest.first().and_then(|&a| pct(a));
    let top10_pct = pct(largest.iter().take(10).sum::<u128>());

    if let Some(p) = top1_pct {
        if p >= TOP1_RED {
            push(
                Verdict::Red,
                format!("top holder owns {p:.1}% of supply (majority control)"),
            );
        } else if p >= TOP1_AMBER {
            push(
                Verdict::Amber,
                format!("top holder owns {p:.1}% of supply (may be a pool/locker — verify)"),
            );
        }
    }
    if let (Some(p), None) = (top10_pct, top1_pct.filter(|&p| p >= TOP1_AMBER)) {
        if p >= TOP10_AMBER {
            push(
                Verdict::Amber,
                format!("top 10 holders own {p:.1}% of supply"),
            );
        }
    }

    let verdict = reasons
        .iter()
        .map(|r| r.severity)
        .max()
        .unwrap_or(Verdict::Green);

    Ok(Report {
        verdict,
        reasons,
        program,
        supply_ui: format_supply(supply, mint.decimals),
        top1_pct,
        top10_pct,
    })
}

/// Render for an LLM context: one verdict line, one facts line, one line per
/// reason. No JSON blob, no raw account dumps.
pub fn render(mint_addr: &str, r: &Report) -> String {
    let mut out = format!(
        "{} — {} ({}), supply {}",
        r.verdict.label(),
        mint_addr,
        r.program,
        r.supply_ui
    );
    if let (Some(t1), Some(t10)) = (r.top1_pct, r.top10_pct) {
        out.push_str(&format!(
            ", top holder {t1:.1}% / top10 {t10:.1}%"
        ));
    }
    if r.reasons.is_empty() {
        out.push_str(
            "\nNo risk flags: authorities revoked, no trap extensions, dispersed supply.",
        );
    } else {
        for reason in &r.reasons {
            out.push_str(&format!(
                "\n[{}] {}",
                reason.severity.label(),
                reason.text
            ));
        }
    }
    out
}

fn format_supply(raw: u128, decimals: u8) -> String {
    let d = decimals as u32;
    let whole = raw / 10u128.pow(d.min(38));
    if whole >= 1_000_000_000 {
        format!("{:.1}B", whole as f64 / 1e9)
    } else if whole >= 1_000_000 {
        format!("{:.1}M", whole as f64 / 1e6)
    } else {
        whole.to_string()
    }
}
