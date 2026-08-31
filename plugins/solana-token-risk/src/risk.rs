//! Pure parsing, validation, and bounded rendering for the `solana-token-risk`
//! component. This module deliberately has no network, wallet, signer, or WASI
//! dependency, so all safety-sensitive interpretation is host-testable.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::Value;

const MAX_DECIMALS: u8 = 38;
const MINT_BASE_LENGTH: usize = 82;
const EXTENSION_BASE_LENGTH: usize = 165;
const MINT_ACCOUNT_TYPE: u8 = 1;
const MAX_RENDERED_EXTENSION_NAMES: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintInfo {
    pub owner_program: String,
    pub supply: u128,
    pub decimals: u8,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    /// Present only when the account was decoded from canonical base64 data.
    /// `jsonParsed` RPC responses do not expose enough of Token-2022's TLV
    /// layout to make extension claims safely.
    pub token_2022_extensions: Option<Token2022Extensions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token2022Extensions {
    pub names: Vec<String>,
    pub additional_count: usize,
    pub transfer_fee: Option<TransferFeeConfig>,
    pub permanent_delegate: Option<Option<String>>,
    pub transfer_hook: Option<TransferHook>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferFeeConfig {
    /// The future/current fee schedule stored in the extension. The plugin
    /// deliberately does not resolve the current epoch with a third RPC call.
    pub newer_fee_basis_points: u16,
    pub newer_maximum_fee: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferHook {
    pub authority: Option<String>,
    pub program_id: Option<String>,
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
    let data = value
        .get("data")
        .ok_or_else(|| "mint account data was missing".to_string())?;

    if let Some(encoded) = data.as_array().and_then(|parts| {
        if parts.len() == 2 && parts.get(1).and_then(Value::as_str) == Some("base64") {
            parts.first().and_then(Value::as_str)
        } else {
            None
        }
    }) {
        let bytes = BASE64
            .decode(encoded)
            .map_err(|_| "mint account base64 data was invalid".to_string())?;
        return parse_raw_mint(&owner_program, &bytes);
    }

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
        token_2022_extensions: None,
    })
}

/// Decode a canonical base64 mint account, including the Token-2022 extension
/// TLV region. The extension region begins after the standard 165-byte account
/// envelope plus its one-byte `AccountType` discriminator; this matches the
/// upstream Token-2022 state layout.
fn parse_raw_mint(owner_program: &str, data: &[u8]) -> Result<MintInfo, String> {
    if data.len() < MINT_BASE_LENGTH {
        return Err("mint account data was shorter than the 82-byte mint layout".to_string());
    }

    let supply = u64::from_le_bytes(
        data[36..44]
            .try_into()
            .map_err(|_| "mint supply bytes were invalid".to_string())?,
    ) as u128;
    let decimals = data[44];
    if decimals > MAX_DECIMALS {
        return Err("mint decimals exceed the safe display limit".to_string());
    }
    if data[45] != 1 {
        return Err("mint account was not initialized".to_string());
    }

    let token_2022_extensions = parse_token_2022_extensions(data)?;
    Ok(MintInfo {
        owner_program: owner_program.to_string(),
        supply,
        decimals,
        mint_authority: parse_coption_pubkey(&data[..36], "mint authority")?,
        freeze_authority: parse_coption_pubkey(&data[46..82], "freeze authority")?,
        token_2022_extensions,
    })
}

fn parse_token_2022_extensions(data: &[u8]) -> Result<Option<Token2022Extensions>, String> {
    if data.len() == MINT_BASE_LENGTH {
        return Ok(None);
    }
    if data.len() <= EXTENSION_BASE_LENGTH {
        return Err("extended mint account was missing its AccountType discriminator".to_string());
    }
    if data[MINT_BASE_LENGTH..EXTENSION_BASE_LENGTH]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err("extended mint account had non-zero padding".to_string());
    }
    if data[EXTENSION_BASE_LENGTH] != MINT_ACCOUNT_TYPE {
        return Err("extended mint account did not declare the Mint account type".to_string());
    }

    let tlv = &data[EXTENSION_BASE_LENGTH + 1..];
    let mut cursor = 0;
    let mut extensions = Token2022Extensions {
        names: Vec::new(),
        additional_count: 0,
        transfer_fee: None,
        permanent_delegate: None,
        transfer_hook: None,
    };

    while cursor < tlv.len() {
        if tlv.len() - cursor < 2 {
            if tlv[cursor..].iter().all(|byte| *byte == 0) {
                break;
            }
            return Err("Token-2022 extension type was truncated".to_string());
        }
        let extension_type = u16::from_le_bytes([tlv[cursor], tlv[cursor + 1]]);
        if extension_type == 0 {
            if tlv[cursor..].iter().all(|byte| *byte == 0) {
                break;
            }
            return Err("Token-2022 extension padding was malformed".to_string());
        }
        if tlv.len() - cursor < 4 {
            return Err("Token-2022 extension length was truncated".to_string());
        }
        let length = u16::from_le_bytes([tlv[cursor + 2], tlv[cursor + 3]]) as usize;
        let value_start = cursor + 4;
        let value_end = value_start.saturating_add(length);
        if value_end > tlv.len() {
            return Err("Token-2022 extension exceeded mint account data".to_string());
        }
        let value = &tlv[value_start..value_end];
        record_extension_name(&mut extensions, extension_type);

        match extension_type {
            // `TransferFeeConfig`: two nullable pubkeys, withheld amount, and
            // two 18-byte fee schedules. We report the newer schedule without
            // guessing which epoch currently applies.
            1 => {
                if value.len() != 108 {
                    return Err("TransferFeeConfig had an unexpected length".to_string());
                }
                extensions.transfer_fee =
                    Some(TransferFeeConfig {
                        newer_maximum_fee: u64::from_le_bytes(value[98..106].try_into().map_err(
                            |_| "TransferFeeConfig maximum fee was invalid".to_string(),
                        )?),
                        newer_fee_basis_points: u16::from_le_bytes(
                            value[106..108].try_into().map_err(|_| {
                                "TransferFeeConfig basis points were invalid".to_string()
                            })?,
                        ),
                    });
            }
            // `PermanentDelegate` is a nullable 32-byte address.
            12 => {
                if value.len() != 32 {
                    return Err("PermanentDelegate had an unexpected length".to_string());
                }
                extensions.permanent_delegate = Some(parse_nullable_pubkey(value));
            }
            // `TransferHook` contains a nullable authority and nullable hook
            // program id, both 32-byte addresses.
            14 => {
                if value.len() != 64 {
                    return Err("TransferHook had an unexpected length".to_string());
                }
                extensions.transfer_hook = Some(TransferHook {
                    authority: parse_nullable_pubkey(&value[..32]),
                    program_id: parse_nullable_pubkey(&value[32..]),
                });
            }
            _ => {}
        }

        cursor = value_end;
    }

    Ok(Some(extensions))
}

fn record_extension_name(extensions: &mut Token2022Extensions, extension_type: u16) {
    if extensions.names.len() < MAX_RENDERED_EXTENSION_NAMES {
        extensions
            .names
            .push(extension_name(extension_type).to_string());
    } else {
        extensions.additional_count += 1;
    }
}

fn extension_name(extension_type: u16) -> &'static str {
    match extension_type {
        1 => "TransferFeeConfig",
        2 => "TransferFeeAmount",
        3 => "MintCloseAuthority",
        4 => "ConfidentialTransferMint",
        5 => "ConfidentialTransferAccount",
        6 => "DefaultAccountState",
        7 => "ImmutableOwner",
        8 => "MemoTransfer",
        9 => "NonTransferable",
        10 => "InterestBearingConfig",
        11 => "CpiGuard",
        12 => "PermanentDelegate",
        13 => "NonTransferableAccount",
        14 => "TransferHook",
        15 => "TransferHookAccount",
        16 => "ConfidentialTransferFeeConfig",
        17 => "ConfidentialTransferFeeAmount",
        18 => "MetadataPointer",
        19 => "TokenMetadata",
        20 => "GroupPointer",
        21 => "TokenGroup",
        22 => "GroupMemberPointer",
        23 => "TokenGroupMember",
        24 => "ConfidentialMintBurn",
        25 => "ScaledUiAmount",
        26 => "Pausable",
        27 => "PausableAccount",
        28 => "PermissionedBurn",
        _ => "UnknownToken2022Extension",
    }
}

fn parse_coption_pubkey(data: &[u8], field: &str) -> Result<Option<String>, String> {
    if data.len() != 36 {
        return Err(format!("{field} had an invalid byte length"));
    }
    match u32::from_le_bytes(
        data[..4]
            .try_into()
            .map_err(|_| format!("{field} option tag was invalid"))?,
    ) {
        0 => Ok(None),
        1 => Ok(Some(bs58::encode(&data[4..]).into_string())),
        _ => Err(format!("{field} option tag was invalid")),
    }
}

fn parse_nullable_pubkey(data: &[u8]) -> Option<String> {
    if data.iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(bs58::encode(data).into_string())
    }
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

    if let Some(extensions) = &info.token_2022_extensions {
        lines.push(format!(
            "Token-2022 extensions: {}.",
            render_extension_names(extensions)
        ));
        if let Some(fee) = &extensions.transfer_fee {
            lines.push(format!(
                "Transfer fee configuration: newer schedule {} (max {} base units); current epoch is intentionally not inferred.",
                format_bps(u32::from(fee.newer_fee_basis_points)),
                fee.newer_maximum_fee
            ));
        }
        if let Some(delegate) = &extensions.permanent_delegate {
            lines.push(authority_line(
                "Permanent delegate",
                delegate.as_deref(),
                "may transfer or burn tokens from any account",
            ));
        }
        if let Some(hook) = &extensions.transfer_hook {
            lines.push(match hook.program_id.as_deref() {
                Some(program_id) => format!(
                    "Transfer hook: present (program {}) — transfers require additional program logic.",
                    abbreviate(program_id)
                ),
                None => "Transfer hook: present but no hook program id is configured.".to_string(),
            });
        }
    }

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
    if let Some(extensions) = &info.token_2022_extensions {
        if extensions.transfer_fee.is_some() {
            indicators.push("Token-2022 transfer fee configuration is present");
        }
        if matches!(extensions.permanent_delegate, Some(Some(_))) {
            indicators.push("a permanent delegate is present");
        }
        if extensions.transfer_hook.is_some() {
            indicators.push("a transfer hook is present");
        }
        if extensions
            .names
            .iter()
            .any(|name| name == "NonTransferable")
        {
            indicators.push("a non-transferable extension is present");
        }
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

fn render_extension_names(extensions: &Token2022Extensions) -> String {
    if extensions.names.is_empty() {
        return "none".to_string();
    }
    if extensions.additional_count == 0 {
        return extensions.names.join(", ");
    }
    format!(
        "{} (and {} more)",
        extensions.names.join(", "),
        extensions.additional_count
    )
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
