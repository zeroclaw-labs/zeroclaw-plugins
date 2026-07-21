use std::collections::{BTreeSet, HashMap};

use crate::address::Address;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

pub fn parse_invocation(value: &str) -> Result<Invocation, serde_json::Error> {
    serde_json::from_str(value)
}

pub const DEFAULT_MAX_ACCOUNTS: usize = 256;
pub const MAX_ACCOUNTS_LIMIT: usize = 512;
pub const DEFAULT_MAX_FINDINGS: usize = 5;
pub const MAX_FINDINGS_LIMIT: usize = 10;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1_500_000;
pub const MAX_RESPONSE_BYTES_LIMIT: usize = 4_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExplorerCluster {
    MainnetBeta,
    Devnet,
    Testnet,
}

impl ExplorerCluster {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "mainnet-beta" => Ok(Self::MainnetBeta),
            "devnet" => Ok(Self::Devnet),
            "testnet" => Ok(Self::Testnet),
            _ => Err(ConfigError::InvalidExplorerCluster),
        }
    }

    pub fn explorer_query(self) -> &'static str {
        match self {
            Self::MainnetBeta => "",
            Self::Devnet => "?cluster=devnet",
            Self::Testnet => "?cluster=testnet",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelConfig {
    pub rpc_url: String,
    pub owner: Address,
    pub expected_genesis_hash: Address,
    pub explorer_cluster: Option<ExplorerCluster>,
    pub allowed_delegates: BTreeSet<Address>,
    pub max_accounts: usize,
    pub max_findings: usize,
    pub max_response_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    UnknownKey,
    MissingRpcUrl,
    InvalidRpcUrl,
    MissingOwner,
    InvalidOwner,
    MissingGenesisHash,
    InvalidGenesisHash,
    InvalidExplorerCluster,
    InvalidAllowedDelegate,
    DuplicateAllowedDelegate,
    TooManyAllowedDelegates,
    InvalidMaxAccounts,
    InvalidMaxFindings,
    InvalidMaxResponseBytes,
}

impl ConfigError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnknownKey => "CONFIG_UNKNOWN_KEY",
            Self::MissingRpcUrl => "CONFIG_RPC_URL_REQUIRED",
            Self::InvalidRpcUrl => "CONFIG_RPC_URL_INVALID",
            Self::MissingOwner => "CONFIG_OWNER_REQUIRED",
            Self::InvalidOwner => "CONFIG_OWNER_INVALID",
            Self::MissingGenesisHash => "CONFIG_EXPECTED_GENESIS_HASH_REQUIRED",
            Self::InvalidGenesisHash => "CONFIG_EXPECTED_GENESIS_HASH_INVALID",
            Self::InvalidExplorerCluster => "CONFIG_EXPLORER_CLUSTER_INVALID",
            Self::InvalidAllowedDelegate => "CONFIG_ALLOWED_DELEGATE_INVALID",
            Self::DuplicateAllowedDelegate => "CONFIG_ALLOWED_DELEGATE_DUPLICATE",
            Self::TooManyAllowedDelegates => "CONFIG_ALLOWED_DELEGATES_TOO_MANY",
            Self::InvalidMaxAccounts => "CONFIG_MAX_ACCOUNTS_INVALID",
            Self::InvalidMaxFindings => "CONFIG_MAX_FINDINGS_INVALID",
            Self::InvalidMaxResponseBytes => "CONFIG_MAX_RESPONSE_BYTES_INVALID",
        }
    }
}

impl SentinelConfig {
    pub fn from_section(values: &HashMap<String, String>) -> Result<Self, ConfigError> {
        const ALLOWED_KEYS: [&str; 8] = [
            "rpc_url",
            "owner",
            "expected_genesis_hash",
            "explorer_cluster",
            "allowed_delegates",
            "max_accounts",
            "max_findings",
            "max_response_bytes",
        ];
        if values
            .keys()
            .any(|key| !ALLOWED_KEYS.contains(&key.as_str()))
        {
            return Err(ConfigError::UnknownKey);
        }

        let rpc_url = values
            .get("rpc_url")
            .ok_or(ConfigError::MissingRpcUrl)?
            .trim();
        validate_rpc_url(rpc_url)?;

        let owner = parse_required_address(
            values,
            "owner",
            ConfigError::MissingOwner,
            ConfigError::InvalidOwner,
        )?;
        let expected_genesis_hash = parse_required_address(
            values,
            "expected_genesis_hash",
            ConfigError::MissingGenesisHash,
            ConfigError::InvalidGenesisHash,
        )?;
        let explorer_cluster = values
            .get("explorer_cluster")
            .map(String::as_str)
            .map(ExplorerCluster::parse)
            .transpose()?;

        let mut allowed_delegates = BTreeSet::new();
        if let Some(list) = values.get("allowed_delegates") {
            for item in list
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                if allowed_delegates.len() >= 128 {
                    return Err(ConfigError::TooManyAllowedDelegates);
                }
                let address =
                    Address::parse(item).map_err(|_| ConfigError::InvalidAllowedDelegate)?;
                if !allowed_delegates.insert(address) {
                    return Err(ConfigError::DuplicateAllowedDelegate);
                }
            }
        }

        let max_accounts = parse_bounded_usize(
            values.get("max_accounts"),
            DEFAULT_MAX_ACCOUNTS,
            1,
            MAX_ACCOUNTS_LIMIT,
            ConfigError::InvalidMaxAccounts,
        )?;
        let max_findings = parse_bounded_usize(
            values.get("max_findings"),
            DEFAULT_MAX_FINDINGS,
            1,
            MAX_FINDINGS_LIMIT,
            ConfigError::InvalidMaxFindings,
        )?;
        let max_response_bytes = parse_bounded_usize(
            values.get("max_response_bytes"),
            DEFAULT_MAX_RESPONSE_BYTES,
            1024,
            MAX_RESPONSE_BYTES_LIMIT,
            ConfigError::InvalidMaxResponseBytes,
        )?;

        Ok(Self {
            rpc_url: rpc_url.to_string(),
            owner,
            expected_genesis_hash,
            explorer_cluster,
            allowed_delegates,
            max_accounts,
            max_findings,
            max_response_bytes,
        })
    }
}

fn parse_required_address(
    values: &HashMap<String, String>,
    key: &str,
    missing: ConfigError,
    invalid: ConfigError,
) -> Result<Address, ConfigError> {
    let value = values.get(key).ok_or(missing)?.trim();
    Address::parse(value).map_err(|_| invalid)
}

fn parse_bounded_usize(
    value: Option<&String>,
    default: usize,
    min: usize,
    max: usize,
    error: ConfigError,
) -> Result<usize, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(error);
    }
    let parsed = value.parse::<usize>().map_err(|_| error)?;
    if !(min..=max).contains(&parsed) {
        return Err(error);
    }
    Ok(parsed)
}

fn validate_rpc_url(value: &str) -> Result<(), ConfigError> {
    if value.len() > 2048
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains('#')
    {
        return Err(ConfigError::InvalidRpcUrl);
    }
    let uri = value
        .parse::<http::Uri>()
        .map_err(|_| ConfigError::InvalidRpcUrl)?;
    let authority = uri.authority().ok_or(ConfigError::InvalidRpcUrl)?;
    if uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || authority.host().is_empty()
        || invalid_authority_port(authority.as_str())
    {
        return Err(ConfigError::InvalidRpcUrl);
    }
    Ok(())
}

fn invalid_authority_port(authority: &str) -> bool {
    let suffix = if authority.starts_with('[') {
        let Some(bracket) = authority.find(']') else {
            return true;
        };
        &authority[bracket + 1..]
    } else {
        authority.rfind(':').map_or("", |colon| &authority[colon..])
    };
    if suffix.is_empty() {
        return false;
    }
    let Some(port) = suffix.strip_prefix(':') else {
        return true;
    };
    port.is_empty() || port.parse::<u16>().map_or(true, |port| port == 0)
}
