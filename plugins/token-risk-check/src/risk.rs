use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use url::{Host, Url};

use crate::liquidity::parse_liquidity;
use crate::model::{serialize_bounded, ModelArgs};
use crate::model::{
    Assessment, AuthorityEvidence, ConcentrationEvidence, ConsistencyEvidence, ExtensionEvidence,
    LiquidityEvidence, PermanentDelegateEvidence, Reason, TransferFeeEvidence,
    TransferHookEvidence, Verdict,
};
use crate::solana::{
    parse_account_info_response, parse_epoch_response, parse_largest_response, parse_mint_account,
    parse_multiple_accounts_response, parse_token_account, pubkey_string, validate_mint,
    MintAccount, ParseError, TOKEN_2022_PROGRAM_ID,
};

pub const MAX_RPC_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_LIQUIDITY_RESPONSE_BYTES: usize = 128 * 1024;
pub const MAX_SLOT_SKEW: u64 = 32;

pub fn tool_name() -> &'static str {
    "token-risk-check"
}

pub fn tool_description() -> &'static str {
    "A read-only Solana mint risk assessment covering authorities, wallet-owner concentration, indexed liquidity, and dangerous Token-2022 extensions."
}

pub fn tool_parameters_schema() -> String {
    json!({
        "type": "object",
        "properties": {
            "mint": {
                "type": "string",
                "minLength": 32,
                "maxLength": 44,
                "pattern": "^[1-9A-HJ-NP-Za-km-z]+$",
                "description": "Canonical Base58 Solana mint public key."
            }
        },
        "required": ["mint"],
        "additionalProperties": false
    })
    .to_string()
}

pub fn execute_json_with<T: ReadTransport>(
    args: &str,
    config: &Config,
    transport: &mut T,
) -> String {
    let args: ModelArgs = match serde_json::from_str(args) {
        Ok(value) => value,
        Err(_) => {
            return serialize_bounded(&Assessment::unknown(
                "",
                "INVALID_EXECUTE_ARGS",
                "arguments must contain only one canonical mint field",
            ));
        }
    };
    if validate_mint(&args.mint).is_err() {
        return serialize_bounded(&Assessment::unknown(
            "",
            "INVALID_MINT",
            "mint must be a canonical 32-byte Base58 public key",
        ));
    }
    match analyze_with(&args.mint, config, transport) {
        Ok(assessment) => serialize_bounded(&assessment),
        Err(AnalysisError::InvalidConfig) => serialize_bounded(&Assessment::unknown(
            &args.mint,
            "INVALID_CONFIG",
            "jailed rpc_url configuration is missing or unsafe",
        )),
        Err(AnalysisError::InvalidMint) => serialize_bounded(&Assessment::unknown(
            "",
            "INVALID_MINT",
            "mint must be a canonical 32-byte Base58 public key",
        )),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestKind {
    Rpc { id: u64, method: &'static str },
    Liquidity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub kind: RequestKind,
    pub method: &'static str,
    pub url: String,
    pub body: Option<String>,
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    pub final_url: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    Unavailable,
    Redirect,
    TooLarge,
    Dns,
    Tls,
    Timeout,
    Denied,
}

pub fn classify_transport_error(error: &str) -> TransportError {
    let normalized = error.to_ascii_lowercase();
    if normalized.contains("dns") || normalized.contains("destination-not-found") {
        TransportError::Dns
    } else if normalized.contains("tls") || normalized.contains("certificate") {
        TransportError::Tls
    } else if normalized.contains("timeout") || normalized.contains("timed out") {
        TransportError::Timeout
    } else if normalized.contains("denied")
        || normalized.contains("prohibited")
        || normalized.contains("not permitted")
    {
        TransportError::Denied
    } else {
        TransportError::Unavailable
    }
}

pub trait ReadTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    rpc_url: String,
}

impl Config {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
        }
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn validate(&self) -> Result<(), AnalysisError> {
        let url = Url::parse(&self.rpc_url).map_err(|_| AnalysisError::InvalidConfig)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
        {
            return Err(AnalysisError::InvalidConfig);
        }
        let unsafe_host = match url.host() {
            Some(Host::Domain(host)) => {
                let host = host.to_ascii_lowercase();
                host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local")
            }
            Some(Host::Ipv4(address)) => ipv4_is_non_public(address.octets()),
            Some(Host::Ipv6(address)) => {
                address.is_unspecified()
                    || address.is_loopback()
                    || address.is_multicast()
                    || (address.segments()[0] & 0xfe00) == 0xfc00
                    || (address.segments()[0] & 0xffc0) == 0xfe80
                    || address
                        .to_ipv4_mapped()
                        .is_some_and(|value| ipv4_is_non_public(value.octets()))
            }
            None => true,
        };
        if unsafe_host {
            return Err(AnalysisError::InvalidConfig);
        }
        Ok(())
    }
}

fn ipv4_is_non_public([a, b, c, _d]: [u8; 4]) -> bool {
    a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..=19).contains(&b))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisError {
    InvalidMint,
    InvalidConfig,
}

fn rpc_request(url: &str, id: u64, method: &'static str, params: serde_json::Value) -> Request {
    Request {
        kind: RequestKind::Rpc { id, method },
        method: "POST",
        url: url.to_string(),
        body: Some(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string()),
        max_response_bytes: MAX_RPC_RESPONSE_BYTES,
    }
}

fn liquidity_request(mint: &str) -> Request {
    Request {
        kind: RequestKind::Liquidity,
        method: "GET",
        url: format!("https://api.dexscreener.com/token-pairs/v1/solana/{mint}"),
        body: None,
        max_response_bytes: MAX_LIQUIDITY_RESPONSE_BYTES,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadError {
    Unavailable,
    Redirect,
    Status,
    UrlMismatch,
    TooLarge,
    InvalidUtf8,
    Dns,
    Tls,
    Timeout,
    Denied,
}

fn get_body<T: ReadTransport>(transport: &mut T, request: Request) -> Result<String, ReadError> {
    let expected_url = request.url.clone();
    let limit = request.max_response_bytes;
    let response = transport.send(request).map_err(|error| match error {
        TransportError::Unavailable => ReadError::Unavailable,
        TransportError::Redirect => ReadError::Redirect,
        TransportError::TooLarge => ReadError::TooLarge,
        TransportError::Dns => ReadError::Dns,
        TransportError::Tls => ReadError::Tls,
        TransportError::Timeout => ReadError::Timeout,
        TransportError::Denied => ReadError::Denied,
    })?;
    if response.status != 200 {
        return Err(ReadError::Status);
    }
    if response.final_url != expected_url {
        return Err(ReadError::UrlMismatch);
    }
    if response.body.len() > limit {
        return Err(ReadError::TooLarge);
    }
    String::from_utf8(response.body).map_err(|_| ReadError::InvalidUtf8)
}

fn mint_read_failure(mint: &str, error: ReadError) -> Result<Assessment, AnalysisError> {
    let (code, message) = match error {
        ReadError::Unavailable => (
            "MINT_HTTP_UNAVAILABLE",
            "mint HTTP transport is unavailable",
        ),
        ReadError::Redirect => (
            "MINT_HTTP_REDIRECT",
            "mint HTTP request attempted a redirect",
        ),
        ReadError::Status => ("MINT_HTTP_STATUS", "mint HTTP response was not status 200"),
        ReadError::UrlMismatch => (
            "MINT_RESPONSE_URL_MISMATCH",
            "mint HTTP response URL did not match the reviewed request URL",
        ),
        ReadError::TooLarge => (
            "MINT_RESPONSE_TOO_LARGE",
            "mint HTTP response exceeded the byte limit",
        ),
        ReadError::InvalidUtf8 => (
            "MINT_RESPONSE_INVALID_UTF8",
            "mint HTTP response was not valid UTF-8",
        ),
        ReadError::Dns => (
            "MINT_HTTP_DNS",
            "mint HTTP destination could not be resolved",
        ),
        ReadError::Tls => ("MINT_HTTP_TLS", "mint HTTP TLS negotiation failed"),
        ReadError::Timeout => ("MINT_HTTP_TIMEOUT", "mint HTTP request timed out"),
        ReadError::Denied => (
            "MINT_HTTP_DENIED",
            "mint HTTP request was denied by the host transport policy",
        ),
    };
    unknown(mint, code, message)
}

fn unknown(
    mint: &str,
    code: &'static str,
    message: &'static str,
) -> Result<Assessment, AnalysisError> {
    Ok(Assessment::unknown(mint, code, message))
}

pub fn analyze_with<T: ReadTransport>(
    mint: &str,
    config: &Config,
    transport: &mut T,
) -> Result<Assessment, AnalysisError> {
    let mint_bytes = validate_mint(mint).map_err(|_| AnalysisError::InvalidMint)?;
    config.validate()?;

    let mint_body = match get_body(
        transport,
        rpc_request(
            config.rpc_url(),
            1,
            "getAccountInfo",
            json!([mint,{"encoding":"base64","commitment":"finalized"}]),
        ),
    ) {
        Ok(v) => v,
        Err(error) => return mint_read_failure(mint, error),
    };
    let mint_raw = match parse_account_info_response(&mint_body, 1) {
        Ok(v) => v,
        Err(_) => {
            return unknown(
                mint,
                "MINT_EVIDENCE_INVALID",
                "mint account evidence is malformed",
            )
        }
    };
    let mint_account = match parse_mint_account(&mint_raw.value.owner_program, &mint_raw.value.data)
    {
        Ok(v) => v,
        Err(_) => {
            return unknown(
                mint,
                "MINT_ACCOUNT_INVALID",
                "mint account bytes are invalid",
            )
        }
    };
    if mint_account.supply == 0 {
        return unknown(
            mint,
            "ZERO_SUPPLY",
            "holder concentration is undefined for a zero-supply mint",
        );
    }

    let largest_body = match get_body(
        transport,
        rpc_request(
            config.rpc_url(),
            2,
            "getTokenLargestAccounts",
            json!([mint,{"commitment":"finalized","minContextSlot":mint_raw.slot}]),
        ),
    ) {
        Ok(v) => v,
        Err(_) => {
            return unknown(
                mint,
                "CONCENTRATION_UNAVAILABLE",
                "holder concentration evidence is unavailable",
            )
        }
    };
    let largest = match parse_largest_response(&largest_body, 2) {
        Ok(v) => v,
        Err(_) => {
            return unknown(
                mint,
                "CONCENTRATION_INVALID",
                "largest token accounts evidence is malformed",
            )
        }
    };
    if largest.value.is_empty() {
        return unknown(
            mint,
            "CONCENTRATION_EMPTY",
            "holder concentration evidence contains no token accounts",
        );
    }
    if largest.slot < mint_raw.slot {
        return unknown(
            mint,
            "CONTEXT_REVERSED",
            "RPC context slots moved backwards",
        );
    }

    let addresses: Vec<&str> = largest.value.iter().map(|v| v.address.as_str()).collect();
    let owners_body = match get_body(
        transport,
        rpc_request(
            config.rpc_url(),
            3,
            "getMultipleAccounts",
            json!([addresses,{"encoding":"base64","commitment":"finalized","minContextSlot":largest.slot}]),
        ),
    ) {
        Ok(v) => v,
        Err(_) => {
            return unknown(
                mint,
                "OWNER_EVIDENCE_UNAVAILABLE",
                "token-account owner evidence is unavailable",
            )
        }
    };
    let owner_raw = match parse_multiple_accounts_response(&owners_body, 3, largest.value.len()) {
        Ok(v) => v,
        Err(_) => {
            return unknown(
                mint,
                "OWNER_EVIDENCE_INVALID",
                "token-account owner evidence is malformed",
            )
        }
    };
    if owner_raw.slot < largest.slot {
        return unknown(
            mint,
            "CONTEXT_REVERSED",
            "RPC context slots moved backwards",
        );
    }

    let (concentration, top_bps) = match aggregate_owners(
        &largest.value,
        &owner_raw.value,
        mint_account.program,
        &mint_bytes,
        mint_account.supply,
    ) {
        Ok(v) => v,
        Err(_) => {
            return unknown(
                mint,
                "OWNER_EVIDENCE_INCONSISTENT",
                "owner evidence is inconsistent with largest accounts",
            )
        }
    };

    let fee_epoch = if mint_account.extensions.transfer_fee.is_some() {
        let epoch_body = match get_body(
            transport,
            rpc_request(
                config.rpc_url(),
                4,
                "getEpochInfo",
                json!([{"commitment":"finalized"}]),
            ),
        ) {
            Ok(v) => v,
            Err(_) => {
                return unknown(
                    mint,
                    "EPOCH_UNAVAILABLE",
                    "transfer-fee epoch evidence is unavailable",
                )
            }
        };
        let epoch = match parse_epoch_response(&epoch_body, 4) {
            Ok(v) => v,
            Err(_) => {
                return unknown(
                    mint,
                    "EPOCH_INVALID",
                    "transfer-fee epoch evidence is malformed",
                )
            }
        };
        Some(epoch)
    } else {
        None
    };

    let liquidity = match get_body(transport, liquidity_request(mint)) {
        Ok(body) => parse_liquidity(mint, &body).unwrap_or_else(|_| LiquidityEvidence::unknown()),
        Err(_) => LiquidityEvidence::unknown(),
    };

    Ok(build_assessment(
        mint,
        mint_raw.slot,
        largest.slot,
        owner_raw.slot,
        mint_account,
        concentration,
        top_bps,
        fee_epoch,
        liquidity,
    ))
}

fn aggregate_owners(
    largest: &[crate::solana::LargestAccount],
    accounts: &[crate::solana::RawAccount],
    program: &str,
    mint: &[u8; 32],
    supply: u64,
) -> Result<(ConcentrationEvidence, u16), ParseError> {
    if largest.is_empty() || largest.len() != accounts.len() || supply == 0 {
        return Err(ParseError::Mismatch);
    }
    let mut seen = BTreeSet::new();
    let mut owners = BTreeMap::<[u8; 32], u128>::new();
    let mut observed = 0_u128;
    for (row, raw) in largest.iter().zip(accounts) {
        if !seen.insert(row.address.as_str()) {
            return Err(ParseError::Duplicate);
        }
        let account =
            parse_token_account(&row.address, program, mint, &raw.owner_program, &raw.data)?;
        if account.amount != row.amount {
            return Err(ParseError::Mismatch);
        }
        observed = observed
            .checked_add(account.amount as u128)
            .ok_or(ParseError::InvalidAmount)?;
        if observed > supply as u128 {
            return Err(ParseError::InvalidAmount);
        }
        let value = owners.entry(account.owner).or_default();
        *value = value
            .checked_add(account.amount as u128)
            .ok_or(ParseError::InvalidAmount)?;
    }
    let top = owners.values().copied().max().unwrap_or(0);
    let top_bps_u128 = top.checked_mul(10_000).ok_or(ParseError::InvalidAmount)? / supply as u128;
    let top_bps = u16::try_from(top_bps_u128).map_err(|_| ParseError::InvalidAmount)?;
    Ok((
        ConcentrationEvidence {
            status: "observed_top_n_lower_bound",
            top_owner_bps: Some(top_bps),
            observed_owner_count: owners.len(),
            observed_account_count: largest.len(),
            observed_amount: observed.to_string(),
            top_n_lower_bound: true,
        },
        top_bps,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_assessment(
    mint: &str,
    mint_slot: u64,
    largest_slot: u64,
    owner_slot: u64,
    account: MintAccount,
    concentration: ConcentrationEvidence,
    top_bps: u16,
    fee_epoch: Option<u64>,
    liquidity: LiquidityEvidence,
) -> Assessment {
    let transfer_fee = match (&account.extensions.transfer_fee, fee_epoch) {
        (Some(config), Some(epoch)) => {
            let selected_is_newer = epoch >= config.newer.epoch;
            let selected = config.active_at(epoch);
            TransferFeeEvidence {
                status: if selected.basis_points > 0 {
                    "active"
                } else {
                    "configured_inactive_current_epoch"
                },
                config_authority: config.config_authority.as_ref().map(pubkey_string),
                withdraw_withheld_authority: config.withdraw_authority.as_ref().map(pubkey_string),
                withheld_amount: Some(config.withheld_amount.to_string()),
                observed_epoch: Some(epoch),
                selected_schedule: Some(if selected_is_newer { "newer" } else { "older" }),
                selected_basis_points: Some(selected.basis_points),
                selected_maximum_fee: Some(selected.maximum_fee.to_string()),
                newer_epoch: Some(config.newer.epoch),
                newer_basis_points: Some(config.newer.basis_points),
                newer_maximum_fee: Some(config.newer.maximum_fee.to_string()),
            }
        }
        (None, None) => TransferFeeEvidence::absent(),
        _ => TransferFeeEvidence::unknown(),
    };
    let transfer_hook = TransferHookEvidence {
        status: if account.extensions.transfer_hook_program.is_some() {
            "active"
        } else if account.extensions.transfer_hook_present {
            "configured_inactive"
        } else {
            "absent"
        },
        authority: account
            .extensions
            .transfer_hook_authority
            .as_ref()
            .map(pubkey_string),
        program_id: account
            .extensions
            .transfer_hook_program
            .as_ref()
            .map(pubkey_string),
    };
    let permanent_delegate = PermanentDelegateEvidence {
        status: if account.extensions.permanent_delegate.is_some() {
            "active"
        } else if account.extensions.permanent_delegate_present {
            "configured_inactive"
        } else {
            "absent"
        },
        address: account
            .extensions
            .permanent_delegate
            .as_ref()
            .map(pubkey_string),
    };
    let selected_fee_bps = transfer_fee.selected_basis_points.unwrap_or(0);
    let mut assessment = Assessment {
        version: "1",
        mint: mint.to_string(),
        verdict: Verdict::Green,
        complete: true,
        token_program: if account.program == TOKEN_2022_PROGRAM_ID {
            "token-2022"
        } else {
            "token"
        },
        supply: Some(account.supply.to_string()),
        decimals: Some(account.decimals),
        mint_authority: AuthorityEvidence {
            status: if account.mint_authority.is_some() { "active" } else { "revoked" },
            address: account.mint_authority.as_ref().map(pubkey_string),
        },
        freeze_authority: AuthorityEvidence {
            status: if account.freeze_authority.is_some() { "active" } else { "revoked" },
            address: account.freeze_authority.as_ref().map(pubkey_string),
        },
        concentration,
        liquidity,
        extensions: ExtensionEvidence {
            token_2022: account.program == TOKEN_2022_PROGRAM_ID,
            transfer_fee,
            transfer_hook,
            permanent_delegate,
            unknown_extension_types: account.extensions.unknown_types.clone(),
        },
        consistency: ConsistencyEvidence {
            status: "same_slot",
            mint_slot: Some(mint_slot),
            largest_accounts_slot: Some(largest_slot),
            owner_accounts_slot: Some(owner_slot),
        },
        reasons: Vec::new(),
        limitations: vec![
            "holder concentration is a lower bound over the RPC top-N token accounts",
            "indexed liquidity does not prove LP lock, burn, ownership, sellability, or price impact",
        ],
    };

    if account.mint_authority.is_some() {
        assessment.push_reason(Reason {
            code: "MINT_AUTHORITY_ACTIVE",
            severity: Verdict::Red,
            message: "mint authority can increase supply",
        });
    }
    if account.freeze_authority.is_some() {
        assessment.push_reason(Reason {
            code: "FREEZE_AUTHORITY_ACTIVE",
            severity: Verdict::Amber,
            message: "freeze authority can freeze token accounts",
        });
    }
    if top_bps >= 5_000 {
        assessment.push_reason(Reason {
            code: "OWNER_CONCENTRATION_HIGH",
            severity: Verdict::Red,
            message: "one observed owner controls at least 50% of supply",
        });
    } else if top_bps >= 2_000 {
        assessment.push_reason(Reason {
            code: "OWNER_CONCENTRATION_ELEVATED",
            severity: Verdict::Amber,
            message: "one observed owner controls at least 20% of supply",
        });
    }
    if selected_fee_bps > 0 {
        assessment.push_reason(Reason {
            code: "TRANSFER_FEE_ACTIVE",
            severity: Verdict::Amber,
            message: "Token-2022 transfer fee is active for the current epoch",
        });
    }
    if account.extensions.transfer_hook_program.is_some() {
        assessment.push_reason(Reason {
            code: "TRANSFER_HOOK_ACTIVE",
            severity: Verdict::Red,
            message: "Token-2022 transfer hook can run custom transfer logic",
        });
    }
    if account.extensions.permanent_delegate.is_some() {
        assessment.push_reason(Reason {
            code: "PERMANENT_DELEGATE_ACTIVE",
            severity: Verdict::Red,
            message: "Token-2022 permanent delegate is active",
        });
    }
    if !account.extensions.unknown_types.is_empty() {
        assessment.complete = false;
        assessment.push_reason(Reason {
            code: "UNKNOWN_EXTENSION",
            severity: Verdict::Amber,
            message: "unrecognized Token-2022 extension prevents a complete assessment",
        });
    }
    if assessment.liquidity.status != "observed" {
        assessment.complete = false;
        assessment.push_reason(Reason {
            code: "LIQUIDITY_NOT_PROVEN",
            severity: Verdict::Amber,
            message: "positive indexed liquidity was not observed",
        });
    }
    let skew = owner_slot.saturating_sub(mint_slot);
    if mint_slot != largest_slot || largest_slot != owner_slot {
        assessment.consistency.status = if skew <= MAX_SLOT_SKEW {
            "bounded_skew"
        } else {
            "incomplete_skew"
        };
        assessment.push_reason(Reason {
            code: "CONTEXT_SLOT_SKEW",
            severity: Verdict::Amber,
            message: "RPC evidence was observed at different context slots",
        });
        if skew > MAX_SLOT_SKEW {
            assessment.complete = false;
        }
    }
    assessment.verdict = if assessment
        .reasons
        .iter()
        .any(|r| r.severity == Verdict::Red)
    {
        Verdict::Red
    } else if !assessment.complete || !assessment.reasons.is_empty() {
        Verdict::Amber
    } else {
        Verdict::Green
    };
    assessment
}
