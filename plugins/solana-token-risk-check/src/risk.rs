//! Pure parsing and risk-policy core. RPC JSON is untrusted data: arbitrary
//! strings are never copied into findings, and malformed responses fail closed.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;
use serde_json::{json, Value};

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const NATIVE_SOL_MINT: &str = "So11111111111111111111111111111111111111112";
const MAX_LARGEST_ACCOUNTS: usize = 20;
pub const MAX_RPC_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_FINALIZED_SLOT_SPREAD: u64 = 512;

/// Validate HTTP before reading a response body. The status body is never
/// reflected because an untrusted server can place instructions in it.
pub fn validate_http_status(status: u16) -> Result<(), &'static str> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err("RPC HTTP status was not successful")
    }
}

/// Append one streamed body chunk without ever allocating beyond `limit`.
pub fn append_bounded_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> Result<(), &'static str> {
    let remaining = limit
        .checked_sub(body.len())
        .ok_or("RPC response exceeds byte limit")?;
    if chunk.len() > remaining {
        return Err("RPC response exceeds byte limit");
    }
    body.extend_from_slice(chunk);
    Ok(())
}

pub fn parse_bounded_json(body: &[u8]) -> Result<Value, &'static str> {
    serde_json::from_slice(body).map_err(|_| "RPC returned invalid JSON")
}

pub struct Config {
    pub rpc_url: String,
}

impl Config {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, &'static str> {
        let rpc_url = section
            .get("rpc_url")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or("missing plugin config: rpc_url")?;
        validate_rpc_url(rpc_url)?;
        Ok(Self {
            rpc_url: rpc_url.to_string(),
        })
    }
}

fn validate_rpc_url(url: &str) -> Result<(), &'static str> {
    if url.len() > 2048 || url.chars().any(char::is_control) || url.contains('#') {
        return Err("rpc_url is invalid");
    }
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("rpc_url must use HTTPS (HTTP is allowed only for loopback)");
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err("rpc_url must not contain credentials");
    }
    let host = authority
        .strip_prefix('[')
        .and_then(|value| value.split(']').next())
        .unwrap_or_else(|| authority.split(':').next().unwrap_or_default());
    if !secure && !matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return Err("plain HTTP rpc_url is allowed only for loopback");
    }
    Ok(())
}

pub fn validate_mint(mint: &str) -> Result<(), &'static str> {
    if !(32..=44).contains(&mint.len()) || !mint.bytes().all(is_base58) {
        return Err("mint must be a 32-byte base58 Solana public key");
    }
    let mut bytes = [0u8; 33];
    let mut length = 1usize;
    for ch in mint.bytes() {
        let mut carry = base58_value(ch).ok_or("mint contains invalid base58")? as u32;
        for byte in bytes[..length].iter_mut() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            if length == bytes.len() {
                return Err("mint must be a 32-byte base58 Solana public key");
            }
            bytes[length] = (carry & 0xff) as u8;
            length += 1;
            carry >>= 8;
        }
    }
    let leading_zeroes = mint.bytes().take_while(|byte| *byte == b'1').count();
    let decoded_len = leading_zeroes + length - usize::from(length == 1 && bytes[0] == 0);
    if decoded_len != 32 {
        return Err("mint must be a 32-byte base58 Solana public key");
    }
    Ok(())
}

fn is_base58(byte: u8) -> bool {
    base58_value(byte).is_some()
}

fn base58_value(byte: u8) -> Option<u8> {
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

pub struct Requests {
    pub mint_account: Value,
    pub supply: Value,
    pub largest_accounts: Value,
}

/// Minimal transport boundary: production uses `wasi:http`; host tests use a
/// deterministic in-memory mock and never touch the network.
pub trait RpcTransport {
    fn send(&mut self, request: &Value) -> Result<Value, &'static str>;
}

pub fn check_with_transport<T: RpcTransport>(
    mint: &str,
    transport: &mut T,
) -> Result<Report, &'static str> {
    validate_mint(mint)?;
    reject_unsupported_native_mint(mint)?;
    let initial = build_requests(mint);
    let mint_account = transport.send(&initial.mint_account)?;
    rpc_result(&mint_account, 1)?;
    let supply = transport.send(&initial.supply)?;
    rpc_result(&supply, 2)?;
    let largest_accounts = transport.send(&initial.largest_accounts)?;
    let largest = parse_largest(&largest_accounts)?;
    let min_context_slot = [
        context_slot(&mint_account, 1)?,
        context_slot(&supply, 2)?,
        context_slot(&largest_accounts, 3)?,
    ]
    .into_iter()
    .max()
    .ok_or("RPC snapshot slot is missing")?;
    let addresses: Vec<String> = largest.iter().map(|entry| entry.address.clone()).collect();
    let owners = transport.send(&owner_request(&addresses, min_context_slot))?;
    rpc_result(&owners, 4)?;
    analyze_rpc(
        mint,
        RpcResponses {
            mint_account: &mint_account,
            supply: &supply,
            largest_accounts: &largest_accounts,
            owners: &owners,
        },
    )
}

pub fn build_requests(mint: &str) -> Requests {
    let config = json!({"encoding": "jsonParsed", "commitment": "finalized"});
    Requests {
        mint_account: request(1, "getAccountInfo", json!([mint, config.clone()])),
        supply: request(
            2,
            "getTokenSupply",
            json!([mint, {"commitment": "finalized"}]),
        ),
        largest_accounts: request(
            3,
            "getTokenLargestAccounts",
            json!([mint, {"commitment": "finalized"}]),
        ),
    }
}

fn owner_request(token_accounts: &[String], min_context_slot: u64) -> Value {
    request(
        4,
        "getMultipleAccounts",
        json!([token_accounts, {
            "encoding": "jsonParsed",
            "commitment": "finalized",
            "minContextSlot": min_context_slot
        }]),
    )
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

#[derive(Clone)]
struct LargestAccount {
    address: String,
    amount: u128,
}

fn parse_largest(response: &Value) -> Result<Vec<LargestAccount>, &'static str> {
    let result = rpc_result(response, 3)?;
    let values = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or("RPC largest-accounts result has an invalid shape")?;
    if values.len() > MAX_LARGEST_ACCOUNTS {
        return Err("RPC returned too many largest token accounts");
    }
    let mut seen = BTreeMap::<String, ()>::new();
    values
        .iter()
        .map(|entry| {
            let address = entry
                .get("address")
                .and_then(Value::as_str)
                .ok_or("RPC largest account address is invalid")?;
            validate_mint(address)?;
            if seen.insert(address.to_string(), ()).is_some() {
                return Err("RPC returned a duplicate largest token account");
            }
            let amount = amount(entry.get("amount"), "RPC largest-account amount is invalid")?
                .parse::<u64>()
                .map(u128::from)
                .map_err(|_| "RPC largest-account amount exceeds Solana's u64 token amount")?;
            Ok(LargestAccount {
                address: address.to_string(),
                amount,
            })
        })
        .collect()
}

pub struct RpcResponses<'a> {
    pub mint_account: &'a Value,
    pub supply: &'a Value,
    pub largest_accounts: &'a Value,
    pub owners: &'a Value,
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Green,
    Amber,
    Red,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct Finding {
    pub code: &'static str,
    pub level: RiskLevel,
    pub summary: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Concentration {
    pub sample_scope: &'static str,
    pub token_accounts_sampled: usize,
    pub unique_owners_in_sample: usize,
    pub sampled_supply_bps: u64,
    pub top_1_owner_bps: u64,
    pub top_5_owners_bps: u64,
    pub top_10_owners_bps: u64,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub commitment: &'static str,
    pub min_slot: u64,
    pub max_slot: u64,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: &'static str,
    pub mint: String,
    pub overall: RiskLevel,
    pub token_program: &'static str,
    pub supply_raw: String,
    pub decimals: u8,
    pub mint_authority_active: bool,
    pub freeze_authority_active: bool,
    pub token_2022_extensions: Vec<&'static str>,
    pub snapshot: Snapshot,
    pub concentration: Concentration,
    pub findings: Vec<Finding>,
    pub limitations: [&'static str; 3],
}

pub fn analyze_rpc(mint: &str, rpc: RpcResponses<'_>) -> Result<Report, &'static str> {
    validate_mint(mint)?;
    reject_unsupported_native_mint(mint)?;
    let mint_result = rpc_result(rpc.mint_account, 1)?;
    let account = mint_result
        .get("value")
        .filter(|value| !value.is_null())
        .ok_or("mint account was not found")?;
    let program_id = account
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("mint account owner is invalid")?;
    let token_program = match program_id {
        TOKEN_PROGRAM => "spl-token",
        TOKEN_2022_PROGRAM => "spl-token-2022",
        _ => return Err("account is not owned by a supported Solana token program"),
    };
    let info = account
        .pointer("/data/parsed/info")
        .and_then(Value::as_object)
        .ok_or("mint account is not valid jsonParsed mint data")?;
    if account.pointer("/data/parsed/type").and_then(Value::as_str) != Some("mint") {
        return Err("account is not a parsed token mint");
    }
    if info.get("isInitialized").and_then(Value::as_bool) != Some(true) {
        return Err("token mint is not initialized");
    }
    let mint_authority_active = nullable_pubkey(info.get("mintAuthority"))?;
    let freeze_authority_active = nullable_pubkey(info.get("freezeAuthority"))?;

    let supply_result = rpc_result(rpc.supply, 2)?;
    let supply_value = supply_result
        .get("value")
        .and_then(Value::as_object)
        .ok_or("RPC supply result has an invalid shape")?;
    let supply_raw = amount(supply_value.get("amount"), "RPC supply amount is invalid")?;
    let supply_num = supply_raw
        .parse::<u64>()
        .map(u128::from)
        .map_err(|_| "RPC supply exceeds Solana's u64 token amount")?;
    let decimals = supply_value
        .get("decimals")
        .and_then(Value::as_u64)
        .filter(|value| *value <= u8::MAX as u64)
        .ok_or("RPC supply decimals are invalid")? as u8;
    if amount(info.get("supply"), "parsed mint supply is invalid")? != supply_raw
        || info.get("decimals").and_then(Value::as_u64) != Some(u64::from(decimals))
    {
        return Err("parsed mint and token-supply responses disagree");
    }

    let extensions = parse_extensions(info.get("extensions"))?;
    let largest = parse_largest(rpc.largest_accounts)?;
    let amounts: Vec<u128> = largest.iter().map(|entry| entry.amount).collect();
    let owners = parse_owners(mint, program_id, rpc.owners, &largest)?;
    let concentration = concentration(&amounts, &owners, supply_num)?;
    let slots = [
        context_slot(rpc.mint_account, 1)?,
        context_slot(rpc.supply, 2)?,
        context_slot(rpc.largest_accounts, 3)?,
        context_slot(rpc.owners, 4)?,
    ];
    if slots[3] < slots[..3].iter().copied().max().unwrap_or(0) {
        return Err("owner snapshot predates its minContextSlot");
    }
    let min_slot = slots.iter().copied().min().unwrap_or(0);
    let max_slot = slots.iter().copied().max().unwrap_or(0);
    if min_slot == 0 || max_slot - min_slot > MAX_FINALIZED_SLOT_SPREAD {
        return Err("finalized RPC snapshot slots are inconsistent");
    }

    let mut findings = Vec::new();
    if mint_authority_active {
        findings.push(Finding {
            code: "MINT_AUTHORITY_ACTIVE",
            level: RiskLevel::Red,
            summary: "An active mint authority can increase token supply.",
        });
    }
    if freeze_authority_active {
        findings.push(Finding {
            code: "FREEZE_AUTHORITY_ACTIVE",
            level: RiskLevel::Red,
            summary: "An active freeze authority can freeze token accounts.",
        });
    }
    for extension in &extensions {
        if let Some(finding) = extension.finding.as_ref() {
            findings.push(*finding);
        }
    }
    if concentration.top_1_owner_bps >= 5000 {
        findings.push(Finding {
            code: "TOP_OWNER_AT_LEAST_50_PERCENT",
            level: RiskLevel::Red,
            summary: "One owner controls at least 50% of raw supply in the sampled accounts.",
        });
    } else if concentration.top_1_owner_bps >= 2000 {
        findings.push(Finding {
            code: "TOP_OWNER_AT_LEAST_20_PERCENT",
            level: RiskLevel::Amber,
            summary: "One owner controls at least 20% of raw supply in the sampled accounts.",
        });
    }
    if concentration.top_10_owners_bps >= 8000 {
        findings.push(Finding {
            code: "TOP_TEN_AT_LEAST_80_PERCENT",
            level: RiskLevel::Amber,
            summary: "The top ten sampled owners control at least 80% of raw supply.",
        });
    }
    if findings.is_empty() {
        findings.push(Finding {
            code: "NO_CHECKED_RISK_FLAGGED",
            level: RiskLevel::Green,
            summary: "No risk covered by this limited check crossed its threshold.",
        });
    }
    let overall = if findings
        .iter()
        .any(|finding| matches!(finding.level, RiskLevel::Red))
    {
        RiskLevel::Red
    } else if findings
        .iter()
        .any(|finding| matches!(finding.level, RiskLevel::Amber))
    {
        RiskLevel::Amber
    } else {
        RiskLevel::Green
    };

    Ok(Report {
        schema_version: "1",
        mint: mint.to_string(),
        overall,
        token_program,
        supply_raw: supply_raw.to_string(),
        decimals,
        mint_authority_active,
        freeze_authority_active,
        token_2022_extensions: extensions.iter().map(|extension| extension.name).collect(),
        snapshot: Snapshot {
            commitment: "finalized",
            min_slot,
            max_slot,
        },
        concentration,
        findings,
        limitations: [
            "Point-in-time RPC data can be stale, incomplete, or supplied by an untrusted endpoint.",
            "Concentration covers only the largest token accounts returned by getTokenLargestAccounts and aggregates their parsed owners.",
            "This check does not inspect markets, liquidity, metadata, off-chain control, upgradeable programs, or transaction behavior.",
        ],
    })
}

fn reject_unsupported_native_mint(mint: &str) -> Result<(), &'static str> {
    if mint == NATIVE_SOL_MINT {
        Err("native SOL mint has no meaningful mint-supply concentration; unsupported")
    } else {
        Ok(())
    }
}

fn rpc_result(response: &Value, expected_id: u64) -> Result<&Value, &'static str> {
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || response.get("id").and_then(Value::as_u64) != Some(expected_id)
    {
        return Err("RPC response envelope is invalid");
    }
    if response.get("error").is_some() {
        return Err("RPC returned an error");
    }
    response.get("result").ok_or("RPC result is missing")
}

fn context_slot(response: &Value, expected_id: u64) -> Result<u64, &'static str> {
    rpc_result(response, expected_id)?
        .pointer("/context/slot")
        .and_then(Value::as_u64)
        .filter(|slot| *slot > 0)
        .ok_or("RPC context slot is invalid")
}

fn nullable_pubkey(value: Option<&Value>) -> Result<bool, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::String(address)) => {
            validate_mint(address)?;
            Ok(true)
        }
        _ => Err("mint authority field is invalid"),
    }
}

fn amount<'a>(value: Option<&'a Value>, error: &'static str) -> Result<&'a str, &'static str> {
    let value = value.and_then(Value::as_str).ok_or(error)?;
    if value.is_empty() || value.len() > 40 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(error);
    }
    Ok(value)
}

struct ParsedExtension {
    name: &'static str,
    finding: Option<Finding>,
}

fn parse_extensions(value: Option<&Value>) -> Result<Vec<ParsedExtension>, &'static str> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .ok_or("Token-2022 extensions are invalid")?;
    if entries.len() > 32 {
        return Err("too many Token-2022 extensions");
    }
    let mut output: Vec<ParsedExtension> = Vec::new();
    for entry in entries {
        let entry = entry
            .as_object()
            .ok_or("Token-2022 extension entry is invalid")?;
        let name = entry
            .get("extension")
            .and_then(Value::as_str)
            .ok_or("Token-2022 extension name is invalid")?;
        let canonical = canonical_extension(name)
            .ok_or("unknown Token-2022 extension; refusing an incomplete risk result")?;
        if output.iter().any(|extension| extension.name == canonical) {
            return Err("duplicate Token-2022 extension entry");
        }
        let state = if extension_requires_state(canonical) {
            Some(
                entry
                    .get("state")
                    .and_then(Value::as_object)
                    .ok_or("Token-2022 extension state is invalid")?,
            )
        } else {
            None
        };
        output.push(ParsedExtension {
            name: canonical,
            finding: extension_finding(canonical, state)?,
        });
    }
    output.sort_unstable_by_key(|extension| extension.name);
    Ok(output)
}

fn canonical_extension(name: &str) -> Option<&'static str> {
    match name {
        "transferFeeConfig" => Some("transfer-fee-config"),
        "transferHook" => Some("transfer-hook"),
        "permanentDelegate" => Some("permanent-delegate"),
        "confidentialTransferMint" => Some("confidential-transfer-mint"),
        "confidentialTransferFeeConfig" => Some("confidential-transfer-fee-config"),
        "defaultAccountState" => Some("default-account-state"),
        "nonTransferable" => Some("non-transferable"),
        "interestBearingConfig" => Some("interest-bearing-config"),
        "metadataPointer" => Some("metadata-pointer"),
        "groupPointer" => Some("group-pointer"),
        "groupMemberPointer" => Some("group-member-pointer"),
        "mintCloseAuthority" => Some("mint-close-authority"),
        "scaledUiAmountConfig" => Some("scaled-ui-amount-config"),
        "pausableConfig" => Some("pausable-config"),
        "tokenMetadata" => Some("token-metadata"),
        "tokenGroup" => Some("token-group"),
        "tokenGroupMember" => Some("token-group-member"),
        "confidentialMintBurn" => Some("confidential-mint-burn"),
        "permissionedBurnConfig" => Some("permissioned-burn-config"),
        _ => None,
    }
}

fn extension_requires_state(extension: &str) -> bool {
    extension != "non-transferable"
}

fn extension_finding(
    extension: &str,
    state: Option<&serde_json::Map<String, Value>>,
) -> Result<Option<Finding>, &'static str> {
    let state = || state.ok_or("Token-2022 extension state is invalid");
    let (code, level, summary) = match extension {
        "transfer-hook" => {
            optional_pubkey(state()?, "authority")?;
            if !optional_pubkey(state()?, "programId")? {
                return Ok(None);
            }
            (
                "TRANSFER_HOOK",
                RiskLevel::Red,
                "An active transfer-hook program can run custom logic during transfers.",
            )
        }
        "permanent-delegate" => {
            if !optional_pubkey(state()?, "delegate")? {
                return Ok(None);
            }
            (
                "PERMANENT_DELEGATE",
                RiskLevel::Red,
                "An active permanent delegate can transfer or burn tokens from any account.",
            )
        }
        "transfer-fee-config" => {
            let config_authority = optional_pubkey(state()?, "transferFeeConfigAuthority")?;
            let withdraw_authority = optional_pubkey(state()?, "withdrawWithheldAuthority")?;
            let older_bps = transfer_fee_bps(state()?, "olderTransferFee")?;
            let newer_bps = transfer_fee_bps(state()?, "newerTransferFee")?;
            if !config_authority && !withdraw_authority && older_bps == 0 && newer_bps == 0 {
                return Ok(None);
            }
            (
                "TRANSFER_FEE_CONFIG_ACTIVE",
                RiskLevel::Amber,
                "Active fee settings or authorities may withhold value from transfers.",
            )
        }
        "confidential-transfer-mint" | "confidential-transfer-fee-config" => (
            "CONFIDENTIAL_TRANSFER",
            RiskLevel::Amber,
            "Confidential transfer features reduce ordinary balance transparency.",
        ),
        "default-account-state" => {
            match state()?.get("accountState").and_then(Value::as_str) {
                Some("initialized") => return Ok(None),
                Some("frozen") | Some("uninitialized") => {}
                _ => return Err("Token-2022 default account state is invalid"),
            }
            (
                "DEFAULT_ACCOUNT_STATE",
                RiskLevel::Amber,
                "New token accounts default to a restricted state.",
            )
        }
        "non-transferable" => (
            "NON_TRANSFERABLE",
            RiskLevel::Amber,
            "Tokens may be non-transferable.",
        ),
        "interest-bearing-config" => (
            "INTEREST_BEARING_DISPLAY",
            RiskLevel::Amber,
            "Displayed UI amounts may change under an interest-bearing configuration.",
        ),
        "mint-close-authority" => {
            if !optional_pubkey(state()?, "closeAuthority")? {
                return Ok(None);
            }
            (
                "MINT_CLOSE_AUTHORITY",
                RiskLevel::Amber,
                "The mint is closable by an active authority.",
            )
        }
        "scaled-ui-amount-config" => (
            "SCALED_UI_AMOUNT",
            RiskLevel::Amber,
            "Displayed UI amounts may differ from raw token amounts.",
        ),
        "pausable-config" => {
            let authority = optional_pubkey(state()?, "authority")?;
            let paused = state()?
                .get("paused")
                .and_then(Value::as_bool)
                .ok_or("Token-2022 pausable state is invalid")?;
            if !authority && !paused {
                return Ok(None);
            }
            (
                "PAUSABLE_CONFIG_ACTIVE",
                RiskLevel::Red,
                "Transfers are paused or an active authority can pause them.",
            )
        }
        "confidential-mint-burn" => (
            "CONFIDENTIAL_MINT_BURN",
            RiskLevel::Amber,
            "Confidential mint/burn features reduce ordinary supply transparency.",
        ),
        "permissioned-burn-config" => {
            if !optional_pubkey(state()?, "authority")? {
                return Ok(None);
            }
            (
                "PERMISSIONED_BURN",
                RiskLevel::Red,
                "An active authority may burn tokens without the token-account owner's signature.",
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(Finding {
        code,
        level,
        summary,
    }))
}

fn optional_pubkey(
    state: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<bool, &'static str> {
    match state.get(field) {
        Some(Value::Null) => Ok(false),
        Some(Value::String(address)) => {
            validate_mint(address).map_err(|_| "Token-2022 extension public key is invalid")?;
            Ok(true)
        }
        _ => Err("Token-2022 extension public key state is invalid"),
    }
}

fn transfer_fee_bps(
    state: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<u64, &'static str> {
    state
        .get(field)
        .and_then(Value::as_object)
        .and_then(|fee| fee.get("transferFeeBasisPoints"))
        .and_then(Value::as_u64)
        .filter(|bps| *bps <= 10_000)
        .ok_or("Token-2022 transfer fee state is invalid")
}

fn parse_owners(
    mint: &str,
    token_program_id: &str,
    response: &Value,
    expected_accounts: &[LargestAccount],
) -> Result<Vec<String>, &'static str> {
    let result = rpc_result(response, 4)?;
    let entries = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or("RPC owner-account result has an invalid shape")?;
    if entries.len() != expected_accounts.len() || entries.len() > MAX_LARGEST_ACCOUNTS {
        return Err("RPC owner-account count does not match largest accounts");
    }
    entries
        .iter()
        .zip(expected_accounts)
        .map(|(entry, expected_account)| {
            let entry = entry
                .as_object()
                .ok_or("largest token account was not found")?;
            if entry.get("owner").and_then(Value::as_str) != Some(token_program_id) {
                return Err("largest account is not owned by the mint's token program");
            }
            if entry
                .get("data")
                .and_then(|v| v.get("parsed"))
                .and_then(|v| v.get("type"))
                .and_then(Value::as_str)
                != Some("account")
            {
                return Err("largest account is not a parsed token account");
            }
            let info = entry
                .get("data")
                .and_then(|v| v.get("parsed"))
                .and_then(|v| v.get("info"))
                .and_then(Value::as_object)
                .ok_or("largest token account is not valid jsonParsed data")?;
            if info.get("mint").and_then(Value::as_str) != Some(mint) {
                return Err("largest token account belongs to a different mint");
            }
            let parsed_amount = amount(
                info.get("tokenAmount")
                    .and_then(|value| value.get("amount")),
                "largest token account parsed amount is invalid",
            )?
            .parse::<u64>()
            .map(u128::from)
            .map_err(|_| "largest token account amount exceeds Solana's u64 token amount")?;
            if parsed_amount != expected_account.amount {
                return Err("largest-account and parsed-account amounts disagree");
            }
            let owner = info
                .get("owner")
                .and_then(Value::as_str)
                .ok_or("largest token account owner is invalid")?;
            validate_mint(owner)?;
            Ok(owner.to_string())
        })
        .collect()
}

fn concentration(
    amounts: &[u128],
    owners: &[String],
    supply: u128,
) -> Result<Concentration, &'static str> {
    if amounts.len() != owners.len() {
        return Err("concentration inputs are inconsistent");
    }
    let mut by_owner = BTreeMap::<&str, u128>::new();
    for (amount, owner) in amounts.iter().zip(owners) {
        let current = by_owner.entry(owner).or_default();
        *current = current
            .checked_add(*amount)
            .ok_or("owner amount overflow")?;
    }
    let mut totals: Vec<u128> = by_owner.values().copied().collect();
    totals.sort_unstable_by(|a, b| b.cmp(a));
    let sampled = totals
        .iter()
        .try_fold(0u128, |total, value| total.checked_add(*value))
        .ok_or("sample amount overflow")?;
    if sampled > supply {
        return Err("sampled token-account balances exceed mint supply");
    }
    Ok(Concentration {
        sample_scope: "largest-token-accounts-returned-by-rpc",
        token_accounts_sampled: amounts.len(),
        unique_owners_in_sample: totals.len(),
        sampled_supply_bps: bps(sampled, supply),
        top_1_owner_bps: bps(sum_top(&totals, 1)?, supply),
        top_5_owners_bps: bps(sum_top(&totals, 5)?, supply),
        top_10_owners_bps: bps(sum_top(&totals, 10)?, supply),
    })
}

fn sum_top(values: &[u128], count: usize) -> Result<u128, &'static str> {
    values.iter().take(count).try_fold(0u128, |total, value| {
        total
            .checked_add(*value)
            .ok_or("concentration sum overflow")
    })
}

fn bps(value: u128, supply: u128) -> u64 {
    if supply == 0 {
        return 0;
    }
    (value * 10_000 / supply) as u64
}
