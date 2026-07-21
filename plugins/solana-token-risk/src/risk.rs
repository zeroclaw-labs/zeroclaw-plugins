//! Pure parsing, validation, and bounded rendering for the `solana-token-risk`
//! component. This module deliberately has no network, wallet, signer, or WASI
//! dependency, so all safety-sensitive interpretation is host-testable.

use serde_json::Value;

const MAX_DECIMALS: u8 = 38;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintInfo {
    pub owner_program: String,
    pub supply: u128,
    pub decimals: u8,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Concentration {
    pub returned_accounts: usize,
    pub top_one_bps: u32,
    pub top_five_bps: u32,
}

/// Validate a Solana public-key-shaped base58 string without ever treating it as
/// a secret. A decoded key must be exactly 32 bytes.
pub fn validate_mint(input: &str) -> Result<String, String> {
    let mint = input.trim();
    if !(32..=44).contains(&mint.len()) {
        return Err("mint must be a 32-byte base58 public key".to_string());
    }

    let decoded = bs58::decode(mint)
        .into_vec()
        .map_err(|_| "mint must be valid base58".to_string())?;
    if decoded.len() != 32 {
        return Err("mint must decode to exactly 32 bytes".to_string());
    }

    Ok(mint.to_string())
}

/// Parse the `result` member returned by Solana `getAccountInfo` with
/// `encoding: jsonParsed`. Rejecting unparsed or partial data is intentional:
/// an ambiguous authority state must never be rendered as safe.
pub fn parse_mint_account(result: &Value) -> Result<MintInfo, String> {
    let value = result
        .get("value")
        .and_then(Value::as_object)
        .ok_or_else(|| "mint account was not found".to_string())?;
    let owner_program = required_string(value.get("owner"), "mint account owner")?;
    let info = value
        .get("data")
        .and_then(|data| data.get("parsed"))
        .and_then(|parsed| parsed.get("info"))
        .and_then(Value::as_object)
        .ok_or_else(|| "RPC did not return parsed mint data".to_string())?;

    let supply = required_string(info.get("supply"), "mint supply")?
        .parse::<u128>()
        .map_err(|_| "mint supply was not an unsigned integer".to_string())?;
    let decimals_u64 = info
        .get("decimals")
        .and_then(Value::as_u64)
        .ok_or_else(|| "mint decimals were missing".to_string())?;
    let decimals =
        u8::try_from(decimals_u64).map_err(|_| "mint decimals were out of range".to_string())?;
    if decimals > MAX_DECIMALS {
        return Err("mint decimals exceed the safe display limit".to_string());
    }

    Ok(MintInfo {
        owner_program,
        supply,
        decimals,
        mint_authority: optional_string(info.get("mintAuthority"), "mint authority")?,
        freeze_authority: optional_string(info.get("freezeAuthority"), "freeze authority")?,
    })
}

/// Parse `getTokenLargestAccounts`. These are token *accounts*, not unique
/// beneficial owners; pools, exchanges, and custody services can aggregate many
/// people. The distinction is kept all the way through to the final text.
pub fn parse_largest_accounts(result: &Value, supply: u128) -> Result<Concentration, String> {
    let accounts = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or_else(|| "RPC did not return largest token accounts".to_string())?;

    let amounts = accounts
        .iter()
        .map(|account| {
            required_string(account.get("amount"), "largest-account amount")?
                .parse::<u128>()
                .map_err(|_| "largest-account amount was not an unsigned integer".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    if supply == 0 {
        return Ok(Concentration {
            returned_accounts: amounts.len(),
            top_one_bps: 0,
            top_five_bps: 0,
        });
    }

    let top_one = amounts.first().copied().unwrap_or(0);
    let top_five = amounts
        .iter()
        .take(5)
        .copied()
        .fold(0_u128, u128::saturating_add);

    Ok(Concentration {
        returned_accounts: amounts.len(),
        top_one_bps: basis_points(top_one, supply),
        top_five_bps: basis_points(top_five, supply),
    })
}

/// Render a compact, bounded interpretation suitable for an agent context. It
/// does not make financial recommendations and explicitly states the limits of
/// the on-chain observations.
pub fn render_summary(mint: &str, info: &MintInfo, concentration: &Concentration) -> String {
    let mut lines = vec![
        "Solana token mint summary — T0 read-only".to_string(),
        format!("Mint: {}", abbreviate(mint)),
        format!("Program: {}", abbreviate(&info.owner_program)),
        format!(
            "Supply: {} ({} decimals)",
            format_token_amount(info.supply, info.decimals),
            info.decimals
        ),
        authority_line("Mint authority", info.mint_authority.as_deref(), "supply can change"),
        authority_line(
            "Freeze authority",
            info.freeze_authority.as_deref(),
            "accounts can be frozen",
        ),
        format!(
            "Top token-account concentration: top 1 {}, top 5 {} of reported supply ({} accounts returned).",
            format_bps(concentration.top_one_bps),
            format_bps(concentration.top_five_bps),
            concentration.returned_accounts
        ),
    ];

    let mut indicators = Vec::new();
    if info.mint_authority.is_some() {
        indicators.push("mint authority is present");
    }
    if info.freeze_authority.is_some() {
        indicators.push("freeze authority is present");
    }
    if concentration.top_five_bps >= 8_000 {
        indicators.push("top-five token-account concentration is high");
    } else if concentration.top_five_bps >= 5_000 {
        indicators.push("top-five token-account concentration is material");
    }
    if indicators.is_empty() {
        lines.push(
            "Observed indicators: no authority or top-five concentration flag triggered."
                .to_string(),
        );
    } else {
        lines.push(format!("Observed indicators: {}.", indicators.join("; ")));
    }

    lines.push(
        "Limits: account concentration is not unique-holder concentration; pools/custody can aggregate users. RPC data is informational, not a security or investment verdict.".to_string(),
    );
    lines.push(
        "No transaction, signature, private key, or wallet access was requested or produced."
            .to_string(),
    );
    lines.join("\n")
}

fn required_string(value: Option<&Value>, field: &str) -> Result<String, String> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("{field} was missing"))
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !text.is_empty() => Ok(Some(text.clone())),
        _ => Err(format!("{field} had an invalid shape")),
    }
}

fn basis_points(part: u128, whole: u128) -> u32 {
    let basis_points = part.saturating_mul(10_000) / whole;
    basis_points.min(10_000) as u32
}

fn format_bps(basis_points: u32) -> String {
    format!("{}.{:02}%", basis_points / 100, basis_points % 100)
}

fn format_token_amount(amount: u128, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }

    let scale = 10_u128.pow(u32::from(decimals));
    let whole = amount / scale;
    let fraction = amount % scale;
    if fraction == 0 {
        return whole.to_string();
    }

    let mut fraction_text = format!("{:0width$}", fraction, width = usize::from(decimals));
    while fraction_text.ends_with('0') {
        fraction_text.pop();
    }
    format!("{whole}.{fraction_text}")
}

fn abbreviate(value: &str) -> String {
    const EDGE: usize = 6;
    if value.len() <= EDGE * 2 + 1 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..EDGE], &value[value.len() - EDGE..])
    }
}

fn authority_line(label: &str, authority: Option<&str>, consequence: &str) -> String {
    match authority {
        Some(value) => format!("{label}: present ({}) — {consequence}.", abbreviate(value)),
        None => format!("{label}: absent."),
    }
}
