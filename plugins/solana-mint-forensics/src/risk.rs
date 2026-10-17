//! Pure, deterministic Solana mint parsing and risk policy.

use std::{collections::HashSet, net::IpAddr};

use base64::Engine;
use serde::Serialize;
use serde_json::Value;

pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

const MINT_LEN: usize = 82;
const TOKEN_2022_TLV_START: usize = 166;
const MAX_LARGEST_ACCOUNTS: usize = 20;
const MAX_EXTENSIONS: usize = 64;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Red,
    Amber,
    Green,
    Unknown,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Red => "red",
            Self::Amber => "amber",
            Self::Green => "green",
            Self::Unknown => "unknown",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Concentration {
    pub top_1_percent: Option<String>,
    pub top_10_percent: Option<String>,
    pub accounts_sampled: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EvidenceSlots {
    pub account: u64,
    pub supply: u64,
    pub largest_accounts: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RiskReport {
    pub mint: String,
    pub verdict: Status,
    pub headline: String,
    pub program: String,
    pub decimals: u8,
    pub raw_supply: String,
    pub extensions: Vec<String>,
    pub concentration: Concentration,
    pub slots: EvidenceSlots,
    pub checks: Vec<Check>,
    pub limitations: Vec<String>,
}

#[derive(Debug)]
struct MintState {
    mint_authority: Option<String>,
    supply: u64,
    decimals: u8,
    initialized: bool,
    freeze_authority: Option<String>,
}

#[derive(Debug)]
struct Extension {
    kind: u16,
    name: String,
    data: Vec<u8>,
}

pub fn validate_mint(value: &str) -> Result<(), String> {
    if value.len() < 32 || value.len() > 44 {
        return Err("mint must be a canonical Base58 Solana address".to_string());
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| "mint must be valid Base58".to_string())?;
    if decoded.len() != 32 || bs58::encode(&decoded).into_string() != value {
        return Err("mint must be a canonical 32-byte Base58 address".to_string());
    }
    Ok(())
}

/// The URL comes only from the operator-owned jailed config, never tool args.
/// Still reject credentials, local names, private IP literals, and non-TLS RPC.
pub fn validate_rpc_url(value: &str) -> Result<(), String> {
    if value.len() > 512 || !value.starts_with("https://") {
        return Err("rpc_url must be an HTTPS URL of at most 512 bytes".to_string());
    }
    let rest = &value[8..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err("rpc_url must have a host and no embedded credentials".to_string());
    }
    let host = if authority.starts_with('[') {
        authority
            .strip_prefix('[')
            .and_then(|v| v.split(']').next())
            .ok_or_else(|| "rpc_url has an invalid IPv6 host".to_string())?
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    let lower = host.to_ascii_lowercase();
    if lower.is_empty()
        || lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
    {
        return Err("local RPC hosts are not allowed".to_string());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        let blocked = match ip {
            IpAddr::V4(ip) => {
                ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || ip.is_unspecified()
                    || ip.octets()[0] == 0
            }
            IpAddr::V6(ip) => {
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || ip.is_multicast()
                    || ip.to_ipv4_mapped().is_some_and(|mapped| {
                        mapped.is_private()
                            || mapped.is_loopback()
                            || mapped.is_link_local()
                            || mapped.is_unspecified()
                    })
            }
        };
        if blocked {
            return Err("private, local, and special-use RPC IPs are not allowed".to_string());
        }
    }
    Ok(())
}

pub fn analyze_rpc_response(mint: &str, body: &str) -> Result<RiskReport, String> {
    validate_mint(mint)?;
    if body.len() > 1_048_576 {
        return Err("RPC response exceeded 1 MiB".to_string());
    }
    let entries: Vec<Value> = serde_json::from_str(body)
        .map_err(|error| format!("invalid JSON-RPC response: {error}"))?;
    if entries.len() != 3 {
        return Err("RPC batch must contain exactly three responses".to_string());
    }
    let account_response = response_by_id(&entries, 1)?;
    let largest_response = entry_by_id(&entries, 2)?;
    let supply_response = response_by_id(&entries, 3)?;
    let account_slot = context_slot(account_response, "mint account")?;
    let supply_slot = context_slot(supply_response, "supply")?;

    let account = account_response
        .pointer("/result/value")
        .ok_or_else(|| "mint account does not exist".to_string())?;
    if account.is_null() {
        return Err("mint account does not exist".to_string());
    }
    let owner = account
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "RPC mint account omitted owner".to_string())?;
    let program = match owner {
        TOKEN_PROGRAM_ID => "SPL Token",
        TOKEN_2022_PROGRAM_ID => "Token-2022",
        _ => return Err("account is not owned by SPL Token or Token-2022".to_string()),
    };
    let encoded = account
        .pointer("/data/0")
        .and_then(Value::as_str)
        .ok_or_else(|| "RPC mint account omitted base64 data".to_string())?;
    if encoded.len() > 65_536 {
        return Err("encoded mint account exceeded 64 KiB".to_string());
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "mint account data was not valid base64".to_string())?;
    let state = parse_mint(&data)?;
    let extensions = if owner == TOKEN_2022_PROGRAM_ID {
        parse_extensions(&data)?
    } else {
        if data.len() != MINT_LEN {
            return Err("legacy SPL mint had a non-canonical account length".to_string());
        }
        Vec::new()
    };

    let rpc_supply = supply_response
        .pointer("/result/value/amount")
        .and_then(Value::as_str)
        .ok_or_else(|| "RPC supply response omitted amount".to_string())?
        .parse::<u64>()
        .map_err(|_| "RPC supply amount was not a u64".to_string())?;
    let rpc_decimals = supply_response
        .pointer("/result/value/decimals")
        .and_then(Value::as_u64)
        .ok_or_else(|| "RPC supply response omitted decimals".to_string())?;
    if rpc_decimals > u8::MAX as u64 {
        return Err("RPC decimals exceeded u8".to_string());
    }

    let concentration_available = largest_response.get("error").is_none();
    let largest_slot = if concentration_available {
        Some(context_slot(largest_response, "largest accounts")?)
    } else {
        None
    };
    let largest: &[Value] = if concentration_available {
        largest_response
            .pointer("/result/value")
            .and_then(Value::as_array)
            .ok_or_else(|| "RPC largest-accounts response omitted value".to_string())?
            .as_slice()
    } else {
        &[]
    };
    if largest.len() > MAX_LARGEST_ACCOUNTS {
        return Err("RPC returned more than 20 largest accounts".to_string());
    }
    let mut amounts = Vec::with_capacity(largest.len());
    let mut addresses = HashSet::with_capacity(largest.len());
    for item in largest {
        let address = item
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| "largest account omitted address".to_string())?;
        validate_mint(address)
            .map_err(|_| "largest account contained an invalid Solana address".to_string())?;
        if !addresses.insert(address) {
            return Err("RPC returned a duplicate largest-account address".to_string());
        }
        let amount = item
            .get("amount")
            .and_then(Value::as_str)
            .ok_or_else(|| "largest account omitted amount".to_string())?
            .parse::<u64>()
            .map_err(|_| "largest account amount was not a u64".to_string())?;
        amounts.push(amount);
    }
    amounts.sort_unstable_by(|a, b| b.cmp(a));
    let top_1_bps = percent_bps(amounts.first().copied().unwrap_or(0), state.supply);
    let top_10_total = amounts
        .iter()
        .take(10)
        .fold(0u128, |sum, value| sum + *value as u128);
    if amounts.iter().any(|amount| *amount > state.supply) || top_10_total > state.supply as u128 {
        return Err("RPC largest-account balances exceeded mint supply".to_string());
    }
    let top_10_bps = percent_bps_u128(top_10_total, state.supply);

    let mut checks = Vec::new();
    checks.push(match &state.mint_authority {
        Some(authority) => check(
            "mint_authority",
            Status::Red,
            format!("Active authority {authority} can increase supply"),
        ),
        None => check("mint_authority", Status::Green, "Mint authority is revoked"),
    });
    checks.push(match &state.freeze_authority {
        Some(authority) => check(
            "freeze_authority",
            Status::Amber,
            format!("Active authority {authority} can freeze token accounts"),
        ),
        None => check(
            "freeze_authority",
            Status::Green,
            "Freeze authority is revoked",
        ),
    });
    checks.push(if state.initialized {
        check("mint_state", Status::Green, "Mint is initialized")
    } else {
        check("mint_state", Status::Red, "Mint is not initialized")
    });

    checks.push(transfer_hook_check(&extensions));
    checks.push(extension_check(
        &extensions,
        1,
        "transfer_fee",
        Status::Amber,
        "Transfer-fee configuration can withhold tokens on transfers",
    ));
    checks.push(optional_authority_check(
        &extensions,
        12,
        "permanent_delegate",
        "Permanent delegate can transfer or burn tokens from any account",
    ));
    checks.push(pausable_check(&extensions));
    checks.push(optional_authority_check(
        &extensions,
        28,
        "permissioned_burn",
        "Burning requires approval from a configured authority",
    ));

    let default_frozen = extensions
        .iter()
        .find(|extension| extension.kind == 6)
        .and_then(|extension| extension.data.first())
        .copied()
        == Some(2);
    checks.push(if default_frozen {
        check(
            "default_account_state",
            Status::Red,
            "New token accounts default to frozen",
        )
    } else if extensions.iter().any(|extension| extension.kind == 6) {
        check(
            "default_account_state",
            Status::Green,
            "Default account state extension is present but not frozen",
        )
    } else {
        check(
            "default_account_state",
            Status::Green,
            "No default-frozen account extension",
        )
    });

    let unknown: Vec<u16> = extensions
        .iter()
        .filter(|extension| extension.name.starts_with("Unknown("))
        .map(|extension| extension.kind)
        .collect();
    checks.push(if unknown.is_empty() {
        check(
            "unknown_extensions",
            Status::Green,
            "All Token-2022 extensions are recognized",
        )
    } else {
        check(
            "unknown_extensions",
            Status::Amber,
            format!("Unknown extension types require manual review: {unknown:?}"),
        )
    });

    let supply_matches = state.supply == rpc_supply && state.decimals == rpc_decimals as u8;
    checks.push(if supply_matches {
        check(
            "supply_consistency",
            Status::Green,
            "Mint bytes and RPC supply response agree",
        )
    } else {
        check(
            "supply_consistency",
            Status::Amber,
            if account_slot == supply_slot {
                "Mint bytes and RPC supply disagree at the same context slot; retry on a trusted RPC"
                    .to_string()
            } else {
                format!(
                    "Supply changed across context slots {account_slot} and {supply_slot}; retry for a stable snapshot"
                )
            },
        )
    });

    checks.push(
        if !concentration_available || (amounts.is_empty() && state.supply > 0) {
            check(
                "holder_concentration",
                Status::Unknown,
                "Largest-account data was unavailable; concentration was not scored",
            )
        } else if state.supply == 0 {
            check(
                "holder_concentration",
                Status::Unknown,
                "Zero supply; concentration is undefined",
            )
        } else if top_1_bps >= 5_000 || top_10_bps >= 8_000 {
            check(
                "holder_concentration",
                Status::Red,
                format!(
                    "Top token account holds {}; top 10 hold {}",
                    format_bps(top_1_bps),
                    format_bps(top_10_bps)
                ),
            )
        } else if top_1_bps >= 2_000 || top_10_bps >= 5_000 {
            check(
                "holder_concentration",
                Status::Amber,
                format!(
                    "Top token account holds {}; top 10 hold {}",
                    format_bps(top_1_bps),
                    format_bps(top_10_bps)
                ),
            )
        } else {
            check(
                "holder_concentration",
                Status::Green,
                format!(
                    "Top token account holds {}; top 10 hold {}",
                    format_bps(top_1_bps),
                    format_bps(top_10_bps)
                ),
            )
        },
    );
    checks.push(check(
        "liquidity_pool_status",
        Status::Unknown,
        "Not inferred from mint data; verify pool ownership and locked/burned LP tokens separately",
    ));

    let verdict = aggregate(&checks);
    let headline = match verdict {
        Status::Red => "High-risk controls or concentration detected",
        Status::Amber => "No critical flag, but manual review is required",
        Status::Green => "No configured mint-level risk rule triggered",
        Status::Unknown => "Insufficient data for a mint-level verdict",
    }
    .to_string();

    Ok(RiskReport {
        mint: mint.to_string(),
        verdict,
        headline,
        program: program.to_string(),
        decimals: state.decimals,
        raw_supply: state.supply.to_string(),
        extensions: extensions.into_iter().map(|extension| extension.name).collect(),
        concentration: Concentration {
            top_1_percent: concentration_available.then(|| format_bps(top_1_bps)),
            top_10_percent: concentration_available.then(|| format_bps(top_10_bps)),
            accounts_sampled: amounts.len(),
        },
        slots: EvidenceSlots {
            account: account_slot,
            supply: supply_slot,
            largest_accounts: largest_slot,
        },
        checks,
        limitations: vec![
            "Largest-account concentration is by token account, not beneficial owner; custodians and pools can distort it".to_string(),
            "This T0 read-only report does not inspect source code, metadata URLs, markets, liquidity locks, price, or off-chain identities".to_string(),
            "A green result is not an endorsement and cannot prove a token is safe".to_string(),
        ],
    })
}

fn response_by_id(entries: &[Value], id: u64) -> Result<&Value, String> {
    let entry = entry_by_id(entries, id)?;
    if let Some(error) = entry.get("error") {
        return Err(format!("Solana RPC method {id} failed: {error}"));
    }
    Ok(entry)
}

fn context_slot(entry: &Value, label: &str) -> Result<u64, String> {
    entry
        .pointer("/result/context/slot")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("RPC {label} response omitted context slot"))
}

fn entry_by_id(entries: &[Value], id: u64) -> Result<&Value, String> {
    entries
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_u64) == Some(id))
        .ok_or_else(|| format!("RPC batch omitted response id {id}"))
}

fn parse_mint(data: &[u8]) -> Result<MintState, String> {
    if data.len() < MINT_LEN {
        return Err("mint account was shorter than 82 bytes".to_string());
    }
    Ok(MintState {
        mint_authority: parse_coption_pubkey(&data[0..36])?,
        supply: u64::from_le_bytes(data[36..44].try_into().expect("fixed slice")),
        decimals: data[44],
        initialized: match data[45] {
            0 => false,
            1 => true,
            _ => return Err("mint initialized flag was invalid".to_string()),
        },
        freeze_authority: parse_coption_pubkey(&data[46..82])?,
    })
}

fn parse_coption_pubkey(data: &[u8]) -> Result<Option<String>, String> {
    let tag = u32::from_le_bytes(data[0..4].try_into().expect("fixed slice"));
    match tag {
        0 => Ok(None),
        1 => Ok(Some(bs58::encode(&data[4..36]).into_string())),
        _ => Err("mint authority option tag was invalid".to_string()),
    }
}

fn parse_extensions(data: &[u8]) -> Result<Vec<Extension>, String> {
    if data.len() == MINT_LEN {
        return Ok(Vec::new());
    }
    if data.len() < TOKEN_2022_TLV_START {
        return Err("Token-2022 extended mint had truncated padding".to_string());
    }
    if data[82..165].iter().any(|byte| *byte != 0) {
        return Err("Token-2022 mint padding was not zeroed".to_string());
    }
    if data[165] != 1 {
        return Err("Token-2022 account type was not Mint".to_string());
    }

    let mut extensions = Vec::new();
    let mut offset = TOKEN_2022_TLV_START;
    while offset < data.len() {
        if data[offset..].iter().all(|byte| *byte == 0) {
            break;
        }
        if data.len() - offset < 4 {
            return Err("Token-2022 extension header was truncated".to_string());
        }
        let kind = u16::from_le_bytes(data[offset..offset + 2].try_into().expect("fixed slice"));
        if kind == 0 {
            return Err(
                "Token-2022 TLV contained non-zero data after an uninitialized entry".to_string(),
            );
        }
        let len = u16::from_le_bytes(
            data[offset + 2..offset + 4]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        offset += 4;
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| "Token-2022 extension payload was truncated".to_string())?;
        if extensions
            .iter()
            .any(|extension: &Extension| extension.kind == kind)
        {
            return Err(format!("duplicate Token-2022 extension type {kind}"));
        }
        if extensions.len() >= MAX_EXTENSIONS {
            return Err("Token-2022 mint exceeded 64 extensions".to_string());
        }
        extensions.push(Extension {
            kind,
            name: extension_name(kind),
            data: data[offset..end].to_vec(),
        });
        offset = end;
    }
    Ok(extensions)
}

fn extension_name(kind: u16) -> String {
    let name = match kind {
        0 => "Uninitialized",
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
        _ => return format!("Unknown({kind})"),
    };
    name.to_string()
}

fn extension_check(
    extensions: &[Extension],
    kind: u16,
    name: &str,
    present_status: Status,
    reason: &str,
) -> Check {
    if extensions.iter().any(|extension| extension.kind == kind) {
        check(name, present_status, reason)
    } else {
        check(name, Status::Green, format!("No {name} extension"))
    }
}

fn transfer_hook_check(extensions: &[Extension]) -> Check {
    let Some(extension) = extensions.iter().find(|extension| extension.kind == 14) else {
        return check("transfer_hook", Status::Green, "No transfer_hook extension");
    };
    if extension.data.len() != 64 {
        return check(
            "transfer_hook",
            Status::Red,
            "Transfer hook extension had a malformed length; fail closed",
        );
    }
    let authority_active = extension.data[..32].iter().any(|byte| *byte != 0);
    let program_active = extension.data[32..].iter().any(|byte| *byte != 0);
    if program_active {
        check(
            "transfer_hook",
            Status::Red,
            "Active transfer-hook program can run logic during every transfer",
        )
    } else if authority_active {
        check(
            "transfer_hook",
            Status::Amber,
            "Transfer hook is disabled now, but an authority can enable it",
        )
    } else {
        check(
            "transfer_hook",
            Status::Green,
            "Transfer hook is permanently disabled",
        )
    }
}

fn optional_authority_check(
    extensions: &[Extension],
    kind: u16,
    name: &str,
    active_reason: &str,
) -> Check {
    let Some(extension) = extensions.iter().find(|extension| extension.kind == kind) else {
        return check(name, Status::Green, format!("No {name} extension"));
    };
    if extension.data.len() != 32 {
        return check(
            name,
            Status::Red,
            format!("{name} extension had a malformed length; fail closed"),
        );
    }
    if extension.data.iter().any(|byte| *byte != 0) {
        check(name, Status::Red, active_reason)
    } else {
        check(name, Status::Green, format!("{name} is disabled"))
    }
}

fn pausable_check(extensions: &[Extension]) -> Check {
    let Some(extension) = extensions.iter().find(|extension| extension.kind == 26) else {
        return check("pausable", Status::Green, "No pausable extension");
    };
    if extension.data.len() != 33 {
        return check(
            "pausable",
            Status::Red,
            "Pausable extension had a malformed length; fail closed",
        );
    }
    let authority_active = extension.data[..32].iter().any(|byte| *byte != 0);
    let paused = extension.data[32] != 0;
    if paused {
        check(
            "pausable",
            Status::Red,
            "Token movement is currently paused",
        )
    } else if authority_active {
        check(
            "pausable",
            Status::Red,
            "Pausable authority can halt minting, burning, and transfers",
        )
    } else {
        check("pausable", Status::Green, "Pause authority is disabled")
    }
}

fn check(name: impl Into<String>, status: Status, reason: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status,
        reason: reason.into(),
    }
}

fn percent_bps(value: u64, supply: u64) -> u64 {
    percent_bps_u128(value as u128, supply)
}

fn percent_bps_u128(value: u128, supply: u64) -> u64 {
    if supply == 0 {
        0
    } else {
        ((value.saturating_mul(10_000) / supply as u128).min(10_000)) as u64
    }
}

fn format_bps(bps: u64) -> String {
    format!("{}.{:02}%", bps / 100, bps % 100)
}

fn aggregate(checks: &[Check]) -> Status {
    if checks.iter().any(|check| check.status == Status::Red) {
        Status::Red
    } else if checks.iter().any(|check| check.status == Status::Amber) {
        Status::Amber
    } else if checks.iter().any(|check| check.status == Status::Green) {
        Status::Green
    } else {
        Status::Unknown
    }
}
