use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenProgram {
    Legacy,
    Token2022,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ExtensionObservation {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LiquiditySnapshot {
    pub pair_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_pair: Option<String>,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RiskInput {
    pub mint: String,
    pub program: TokenProgram,
    pub initialized: bool,
    pub supply: u64,
    pub decimals: u8,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub extensions: Vec<ExtensionObservation>,
    /// Largest token accounts in descending order. `None` means the RPC check failed.
    pub largest_accounts: Option<Vec<u64>>,
    /// `None` means liquidity was unavailable or intentionally not queried.
    pub liquidity: Option<LiquiditySnapshot>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Green,
    Amber,
    Red,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RiskReport {
    pub mint: String,
    pub custody_tier: String,
    pub verdict: Verdict,
    pub score: u8,
    pub program: TokenProgram,
    pub top1_bps: Option<u16>,
    pub top10_bps: Option<u16>,
    pub liquidity_usd: Option<f64>,
    pub findings: Vec<Finding>,
}

/// Rejects prompts, URLs, whitespace, and non-pubkey text before any network call.
pub fn validate_mint_address(mint: &str) -> Result<(), String> {
    if mint.is_empty() || mint.len() > 44 || mint.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err("mint must be one base58 Solana public key".to_string());
    }

    let mut decoded = [0u8; 32];
    let mut leading_zeroes = 0usize;
    for (index, byte) in mint.bytes().enumerate() {
        let digit = base58_digit(byte).ok_or_else(|| "mint is not valid base58".to_string())?;
        if index == leading_zeroes && digit == 0 {
            leading_zeroes += 1;
        }

        let mut carry = digit as u16;
        for output in decoded.iter_mut().rev() {
            let value = (*output as u16) * 58 + carry;
            *output = value as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            return Err("mint is longer than a 32-byte public key".to_string());
        }
    }

    let significant = decoded
        .iter()
        .position(|byte| *byte != 0)
        .map(|first| decoded.len() - first)
        .unwrap_or(0);
    if leading_zeroes + significant != 32 {
        return Err("mint must decode to exactly 32 bytes".to_string());
    }
    Ok(())
}

fn base58_digit(byte: u8) -> Option<u8> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

fn extension_key(kind: &str) -> String {
    kind.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn add_finding(
    findings: &mut Vec<Finding>,
    score: &mut u16,
    points: u16,
    code: &str,
    severity: Severity,
    message: impl Into<String>,
) {
    *score = score.saturating_add(points);
    findings.push(Finding {
        code: code.to_string(),
        severity,
        message: message.into(),
    });
}

fn concentration_bps(amount: u64, supply: u64) -> u16 {
    if supply == 0 {
        return 0;
    }
    (((amount as u128) * 10_000u128 / (supply as u128)).min(10_000)) as u16
}

pub fn assess(input: &RiskInput) -> RiskReport {
    let mut findings = Vec::new();
    let mut score = 0u16;
    let mut forced_red = false;

    if !input.initialized {
        add_finding(
            &mut findings,
            &mut score,
            100,
            "mint_uninitialized",
            Severity::Critical,
            "mint account is not initialized",
        );
        forced_red = true;
    }

    if input.supply == 0 {
        add_finding(
            &mut findings,
            &mut score,
            35,
            "zero_supply",
            Severity::High,
            "reported token supply is zero",
        );
    }

    if input.mint_authority.is_some() {
        add_finding(
            &mut findings,
            &mut score,
            25,
            "mint_authority_live",
            Severity::High,
            "mint authority can still expand supply",
        );
    }

    if input.freeze_authority.is_some() {
        add_finding(
            &mut findings,
            &mut score,
            20,
            "freeze_authority_live",
            Severity::High,
            "freeze authority can freeze token accounts",
        );
    }

    for ext in &input.extensions {
        let key = extension_key(&ext.kind);
        match key.as_str() {
            "permanentdelegate" => {
                add_finding(
                    &mut findings,
                    &mut score,
                    45,
                    "permanent_delegate",
                    Severity::Critical,
                    "permanent delegate can transfer or burn from any holder account",
                );
                forced_red = true;
            }
            "transferhook" | "transferhookaccount" => add_finding(
                &mut findings,
                &mut score,
                20,
                "transfer_hook",
                Severity::High,
                "custom program logic executes on token transfers",
            ),
            "transferfeeconfig" | "transferfeeamount" => add_finding(
                &mut findings,
                &mut score,
                10,
                "transfer_fee",
                Severity::Medium,
                "transfers may be charged a configurable fee",
            ),
            "nontransferable" | "nontransferableaccount" => add_finding(
                &mut findings,
                &mut score,
                15,
                "non_transferable",
                Severity::High,
                "token transfers are restricted by a non-transferable extension",
            ),
            "confidentialtransfermint" | "confidentialtransferfeeconfig" => add_finding(
                &mut findings,
                &mut score,
                15,
                "confidential_transfer",
                Severity::Medium,
                "confidential balances reduce public supply-flow observability",
            ),
            "defaultaccountstate" => add_finding(
                &mut findings,
                &mut score,
                10,
                "default_account_state",
                Severity::Medium,
                "new token accounts may start in a restricted state",
            ),
            "metadatapointer"
            | "tokenmetadata"
            | "interestbearingconfig"
            | "scaleduiconfig"
            | "grouppointer"
            | "groupmemberpointer" => findings.push(Finding {
                code: "token2022_extension_present".to_string(),
                severity: Severity::Info,
                message: format!("Token-2022 extension present: {}", ext.kind),
            }),
            _ => add_finding(
                &mut findings,
                &mut score,
                5,
                "unknown_extension",
                Severity::Low,
                format!("unclassified Token-2022 extension: {}", ext.kind),
            ),
        }
    }

    let (top1_bps, top10_bps) = match &input.largest_accounts {
        Some(accounts) if !accounts.is_empty() && input.supply > 0 => {
            let top1 = concentration_bps(accounts[0], input.supply);
            let top10_amount = accounts
                .iter()
                .take(10)
                .fold(0u128, |sum, amount| sum.saturating_add(*amount as u128))
                .min(input.supply as u128) as u64;
            let top10 = concentration_bps(top10_amount, input.supply);

            if top1 >= 5_000 {
                add_finding(
                    &mut findings,
                    &mut score,
                    30,
                    "top_holder_majority",
                    Severity::Critical,
                    format!("largest token account controls {}% of supply", top1 / 100),
                );
                forced_red = true;
            } else if top1 >= 2_500 {
                add_finding(
                    &mut findings,
                    &mut score,
                    18,
                    "top_holder_concentrated",
                    Severity::High,
                    format!("largest token account controls {}% of supply", top1 / 100),
                );
            } else if top1 >= 1_000 {
                add_finding(
                    &mut findings,
                    &mut score,
                    8,
                    "top_holder_elevated",
                    Severity::Medium,
                    format!("largest token account controls {}% of supply", top1 / 100),
                );
            }

            if top10 >= 8_000 {
                add_finding(
                    &mut findings,
                    &mut score,
                    12,
                    "top10_concentrated",
                    Severity::High,
                    format!(
                        "ten largest token accounts control {}% of supply",
                        top10 / 100
                    ),
                );
            }
            (Some(top1), Some(top10))
        }
        _ => {
            add_finding(
                &mut findings,
                &mut score,
                20,
                "holder_data_unavailable",
                Severity::High,
                "holder concentration unavailable; report cannot be green",
            );
            (None, None)
        }
    };

    let liquidity_usd = input.liquidity.as_ref().and_then(|l| l.max_usd);
    match liquidity_usd {
        None => add_finding(
            &mut findings,
            &mut score,
            15,
            "liquidity_unverified",
            Severity::High,
            "no verifiable DEX liquidity evidence; report cannot be green",
        ),
        Some(usd) if usd < 10_000.0 => add_finding(
            &mut findings,
            &mut score,
            20,
            "liquidity_critical",
            Severity::High,
            format!("largest observed pool has only ${usd:.0} liquidity"),
        ),
        Some(usd) if usd < 50_000.0 => add_finding(
            &mut findings,
            &mut score,
            8,
            "liquidity_thin",
            Severity::Medium,
            format!("largest observed pool has ${usd:.0} liquidity"),
        ),
        Some(_) => {}
    }

    if findings.is_empty() {
        findings.push(Finding {
            code: "no_material_flags".to_string(),
            severity: Severity::Info,
            message: "no material flags found in the checked evidence".to_string(),
        });
    }

    let clamped_score = score.min(100) as u8;
    let verdict = if forced_red || clamped_score >= 50 {
        Verdict::Red
    } else if clamped_score >= 20 {
        Verdict::Amber
    } else {
        Verdict::Green
    };

    RiskReport {
        mint: input.mint.clone(),
        custody_tier: "T0 Read".to_string(),
        verdict,
        score: clamped_score,
        program: input.program.clone(),
        top1_bps,
        top10_bps,
        liquidity_usd,
        findings,
    }
}

/// A deliberately small agent-facing payload. Full explanations live in the README;
/// execution returns only decision-grade evidence instead of raw RPC responses.
pub fn compact_json(report: &RiskReport) -> Result<String, serde_json::Error> {
    let flags: Vec<serde_json::Value> = report
        .findings
        .iter()
        .take(8)
        .map(|finding| {
            serde_json::json!({
                "code": finding.code,
                "severity": finding.severity,
            })
        })
        .collect();

    serde_json::to_string(&serde_json::json!({
        "custody": report.custody_tier,
        "verdict": report.verdict,
        "score": report.score,
        "mint": report.mint,
        "program": report.program,
        "top1_bps": report.top1_bps,
        "top10_bps": report.top10_bps,
        "liquidity_usd": report.liquidity_usd,
        "flags": flags,
        "truncated_flags": report.findings.len().saturating_sub(8),
    }))
}
