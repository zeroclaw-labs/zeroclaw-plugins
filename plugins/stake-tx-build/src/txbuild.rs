//! Pure core of the `stake_tx_build` tool: config parsing and the byte-level
//! assembly of unsigned legacy Solana transactions for stake delegation and
//! stake deactivation. No wasm and no I/O in here, so the whole module runs
//! under a plain host `cargo test`.
//!
//! The instruction-level byte facts come from `solana-program`: discriminants
//! and account order from `stake::instruction` and
//! `system_instruction::advance_nonce_account`, message layout and compact-u16
//! from the `solana-sdk` `short_vec` encoding. A live mainnet delegate
//! transaction, signature
//! `5yaZiJMVnN5fM5K4rHQFrntaprKQJJbuLqiVGWh7Dkg1MqtswUno83BTozmzN8xAfLZTtFTZiwhTUZsmNoa5kVRA`,
//! is kept in `tests/fixtures` and checked byte for byte. The builder produces
//! transactions only; it never sees a private key and it cannot sign or submit
//! anything.

use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Every key this plugin reads out of its own config section.
///
/// Since the host began validating typed instance config, the guest no longer
/// polices unknown keys: `additionalProperties = false` in `manifest.toml`
/// rejects an undeclared key before the component starts. What this array is
/// for now is the test that reads `manifest.toml` and asserts the schema
/// declares exactly these keys, so a key added here and forgotten there fails
/// the build rather than the operator's first run.
pub const CONFIG_KEYS: [&str; 8] = [
    "stake_accounts",
    "authority",
    "rpc_url",
    "cluster",
    "allowed_vote_accounts",
    "nonce_account",
    "nonce_authority",
    "timeout_secs",
];

/// Stake program id, confirmed by the mainnet delegate fixture
/// (`accountKeys[4]` of the transaction in `tests/fixtures`).
pub const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";

/// System program id; owner of nonce accounts and home of
/// AdvanceNonceAccount (`solana-program::system_instruction`).
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// Clock sysvar, account 2 of DelegateStake and account 1 of Deactivate
/// (`solana-program::stake::instruction`).
pub const SYSVAR_CLOCK_ID: &str = "SysvarC1ock11111111111111111111111111111111";

/// Stake history sysvar, account 3 of DelegateStake
/// (`solana-program::stake::instruction`). Deactivate does not take it.
pub const SYSVAR_STAKE_HISTORY_ID: &str = "SysvarStakeHistory1111111111111111111111111";

/// Stake config account, account 4 of DelegateStake. Semantically dead but
/// positionally required for compatibility; the address comes from
/// `declare_deprecated_id!` in the `solana-program` stake `config` module.
pub const STAKE_CONFIG_ID: &str = "StakeConfig11111111111111111111111111111111";

/// RecentBlockhashes sysvar, account 1 of AdvanceNonceAccount. Deprecated
/// but still mandatory in the instruction
/// (`solana-program::system_instruction::advance_nonce_account`).
pub const SYSVAR_RECENT_BLOCKHASHES_ID: &str = "SysvarRecentB1ockHashes11111111111111111111";

/// Genesis hash of Solana mainnet-beta, the cluster identity this builder
/// pins by default. Source: `getGenesisHash` on the public mainnet endpoint
/// <https://api.mainnet-beta.solana.com>, the same value the Solana cluster
/// documentation lists for mainnet-beta.
pub const MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/// Genesis hash of devnet. Source: `getGenesisHash` on
/// <https://api.devnet.solana.com>.
pub const DEVNET_GENESIS_HASH: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

/// Genesis hash of testnet. Source: `getGenesisHash` on
/// <https://api.testnet.solana.com>.
pub const TESTNET_GENESIS_HASH: &str = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";

// ---------------------------------------------------------------------------
// Cluster identity
// ---------------------------------------------------------------------------

/// The cluster an operator pins `rpc_url` to. A URL proves nothing about the
/// chain behind it, so the builder asks the endpoint for its genesis hash and
/// compares it against the pinned value before it assembles anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cluster {
    MainnetBeta,
    Devnet,
    Testnet,
}

/// Every cluster the `cluster` config key accepts, in the order the error
/// message lists them.
const CLUSTERS: [Cluster; 3] = [Cluster::MainnetBeta, Cluster::Devnet, Cluster::Testnet];

impl Cluster {
    pub fn as_str(self) -> &'static str {
        match self {
            Cluster::MainnetBeta => "mainnet-beta",
            Cluster::Devnet => "devnet",
            Cluster::Testnet => "testnet",
        }
    }

    /// The genesis hash an endpoint on this cluster must report.
    pub fn genesis_hash(self) -> &'static str {
        match self {
            Cluster::MainnetBeta => MAINNET_GENESIS_HASH,
            Cluster::Devnet => DEVNET_GENESIS_HASH,
            Cluster::Testnet => TESTNET_GENESIS_HASH,
        }
    }
}

/// Parses the `cluster` config value. Fail-closed: an unrecognized name is an
/// error, never a skipped check and never a fallback to mainnet.
pub fn parse_cluster(raw: &str) -> Result<Cluster, String> {
    let q = raw.trim();
    CLUSTERS
        .iter()
        .copied()
        .find(|c| c.as_str() == q)
        .ok_or_else(|| {
            format!(
                "cluster must be one of: {}; got `{q}`",
                CLUSTERS
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

/// Compares the genesis hash an endpoint reported against the pinned cluster.
/// An error here means `rpc_url` is not the chain the operator pinned, and
/// the caller must refuse to build rather than sign off on the wrong chain.
pub fn verify_cluster(cluster: Cluster, reported: &str) -> Result<(), String> {
    if reported == cluster.genesis_hash() {
        return Ok(());
    }
    Err(format!(
        "cluster mismatch: rpc_url reports genesis `{reported}`, not {} `{}`",
        cluster.as_str(),
        cluster.genesis_hash()
    ))
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeAccountRef {
    pub label: String,
    pub pubkey: String,
}

#[derive(Debug, Clone)]
pub struct NoncePair {
    pub account: String,
    pub authority: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub accounts: Vec<StakeAccountRef>,
    pub authority: String,
    pub rpc_url: String,
    pub cluster: Cluster,
    pub allowed_vote_accounts: Vec<String>,
    pub nonce: Option<NoncePair>,
    pub timeout_secs: u64,
}

/// The shape of this plugin's config section as the host now hands it over.
///
/// Since zeroclaw-labs/zeroclaw#9126 the host validates the operator's values
/// against `[config_schema]` in `manifest.toml` and injects a *typed* JSON
/// object, so the two allowlists arrive as arrays and the timeout as an
/// integer, and there is no string splitting left for the guest to do.
///
/// Deliberately not `deny_unknown_fields`: `additionalProperties = false` in
/// the manifest already refuses an undeclared key before the component starts,
/// so guest-side strictness would add no protection and would turn a
/// forward-compatible schema addition into a hard failure.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawConfig {
    stake_accounts: Option<Vec<String>>,
    authority: Option<String>,
    rpc_url: Option<String>,
    cluster: Option<String>,
    allowed_vote_accounts: Option<Vec<String>>,
    nonce_account: Option<String>,
    nonce_authority: Option<String>,
    timeout_secs: Option<u64>,
}

/// Describes a config deserialization failure without quoting the value that
/// caused it.
///
/// `serde_json::Error`'s `Display` embeds the offending value. Every config
/// value here is a pubkey or the operator's own RPC endpoint, which the host
/// stores secret-marked and encrypted at rest, so echoing one into a
/// `ToolResult` would hand it straight back to the model. This matters more in
/// this plugin than in the two readers: the authority pubkey is the account a
/// transaction built here would be signed by.
fn describe_error(error: &serde_json::Error) -> String {
    format!(
        "config does not match the declared schema: {:?} error at line {} column {}",
        error.classify(),
        error.line(),
        error.column()
    )
}

impl Config {
    /// Parses the typed `__config` object the host injects.
    ///
    /// The three keys this plugin cannot run without are `required` in the
    /// schema, so a schema-enforcing host never reaches the missing-key
    /// branches. They stay because host-side `cargo test` runs with no schema
    /// validation at all, and because a builder without an authority has
    /// nothing to name as the signer.
    pub fn from_json(config: &Value) -> Result<Self, String> {
        let raw: RawConfig = if config.is_null() {
            RawConfig::default()
        } else {
            serde_json::from_value(config.clone()).map_err(|error| describe_error(&error))?
        };

        let accounts = parse_accounts(raw.stake_accounts.as_deref().ok_or(
            "config key `stake_accounts` is required: an allowlist array like [\"main:<pubkey>\"] or bare pubkeys",
        )?)?;

        let authority = raw
            .authority
            .as_deref()
            .ok_or("config key `authority` is required: the fee payer and stake authority pubkey (never a private key)")?
            .trim()
            .to_string();
        validate_pubkey(&authority, "config key `authority`")?;

        let rpc_url = raw
            .rpc_url
            .as_deref()
            .ok_or("config key `rpc_url` is required")?
            .trim()
            .trim_end_matches('/')
            .to_string();
        if !rpc_url.starts_with("https://") {
            return Err(format!("rpc_url must be an https:// URL, got `{rpc_url}`"));
        }

        // Unset means mainnet-beta: the default is the strictest reading of
        // an operator who never said which chain they meant.
        let cluster = match raw.cluster.as_deref() {
            Some(name) => parse_cluster(name)?,
            None => Cluster::MainnetBeta,
        };

        let allowed_vote_accounts = match raw.allowed_vote_accounts.as_deref() {
            Some(entries) => parse_vote_allowlist(entries)?,
            None => Vec::new(),
        };

        let nonce = match (raw.nonce_account.as_deref(), raw.nonce_authority.as_deref()) {
            (None, None) => None,
            (Some(account), Some(authority)) => {
                let account = account.trim().to_string();
                let authority = authority.trim().to_string();
                validate_pubkey(&account, "config key `nonce_account`")?;
                validate_pubkey(&authority, "config key `nonce_authority`")?;
                Some(NoncePair { account, authority })
            }
            _ => {
                return Err(
                    "config keys `nonce_account` and `nonce_authority` must be set together or not at all"
                        .to_string(),
                )
            }
        };

        let timeout_secs = raw.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if timeout_secs == 0 || timeout_secs > 60 {
            return Err(format!(
                "timeout_secs must be between 1 and 60, got {timeout_secs}"
            ));
        }

        Ok(Config {
            accounts,
            authority,
            rpc_url,
            cluster,
            allowed_vote_accounts,
            nonce,
            timeout_secs,
        })
    }

    /// Resolves the `stake_account` argument against the allowlist. The
    /// model can only pick a configured account, never introduce a new one.
    pub fn resolve_stake(&self, requested: &str) -> Result<&StakeAccountRef, String> {
        let q = requested.trim();
        reject_invisible(q, "requested stake account")?;
        self.accounts
            .iter()
            .find(|a| a.label == q || a.pubkey == q)
            .ok_or_else(|| {
                format!(
                    "stake account `{q}` is not in the configured allowlist; known labels: {}",
                    self.accounts
                        .iter()
                        .map(|a| a.label.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }
}

fn parse_accounts(entries: &[String]) -> Result<Vec<StakeAccountRef>, String> {
    let mut out = Vec::new();
    for (i, entry) in entries
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        let (label, pubkey) = match entry.split_once(':') {
            Some((l, p)) => (l.trim().to_string(), p.trim().to_string()),
            None => (format!("stake{}", i + 1), entry.to_string()),
        };
        reject_invisible(&label, "stake account label")?;
        validate_pubkey(&pubkey, &format!("stake_accounts entry `{label}`"))?;
        // `resolve_stake` accepts a label or a pubkey in one namespace, so a
        // label that is itself a valid address would shadow the entry that
        // actually holds that address: asking for the shadowed account would
        // silently build against a different one. Refusing the ambiguity at
        // parse time keeps the lookup unambiguous by construction.
        if validate_pubkey(&label, "label").is_ok() {
            return Err(format!(
                "stake account label `{label}` is itself a valid pubkey, which would shadow the entry holding that address; use a name instead"
            ));
        }
        if out.iter().any(|a: &StakeAccountRef| a.label == label) {
            return Err(format!("duplicate stake account label `{label}`"));
        }
        out.push(StakeAccountRef { label, pubkey });
    }
    if out.is_empty() {
        return Err("config key `stake_accounts` must contain at least one entry".to_string());
    }
    Ok(out)
}

fn parse_vote_allowlist(entries: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for entry in entries.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        validate_pubkey(entry, "allowed_vote_accounts entry")?;
        if out.iter().any(|v| v == entry) {
            return Err(format!(
                "duplicate vote account `{entry}` in allowed_vote_accounts"
            ));
        }
        out.push(entry.to_string());
    }
    Ok(out)
}

/// Rejects values carrying characters that leave no visible trace: control
/// codes, zero-width marks, the soft hyphen and the BOM.
///
/// Without this check `main` and a `main` with a trailing zero-width space
/// render identically, so a refusal reads "`main` is not in the allowlist;
/// known labels: main" and the operator has no way to see the difference
/// between the value they typed and the one that was accepted. The worst case
/// is an invisible byte inside the config itself, where the label can never be
/// typed to match and the plugin is stuck for good. `trim` does not help: NBSP
/// it removes, these it does not.
fn reject_invisible(value: &str, what: &str) -> Result<(), String> {
    for (i, ch) in value.char_indices() {
        let invisible = ch.is_control()
            || matches!(
                ch,
                '\u{00ad}' | '\u{200b}'..='\u{200f}' | '\u{2060}' | '\u{feff}'
            );
        if invisible {
            return Err(format!(
                "{what} contains an invisible character (U+{:04X}) at byte {i}, so it would look identical to a clean value; retype it without hidden formatting",
                ch as u32
            ));
        }
    }
    Ok(())
}

pub fn validate_pubkey(candidate: &str, what: &str) -> Result<(), String> {
    // `what` names the config key or entry under inspection. Without it an
    // empty or malformed value produced "`` is not a valid Solana pubkey",
    // leaving the operator to guess which of the several pubkey-bearing keys
    // was the broken one.
    if candidate.is_empty() {
        return Err(format!("{what} is empty; expected a base58 Solana pubkey"));
    }
    let bytes = bs58::decode(candidate)
        .into_vec()
        .map_err(|_| format!("{what}: `{candidate}` is not valid base58"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{what}: `{candidate}` is not a valid Solana pubkey (decoded {} bytes, expected 32)",
            bytes.len()
        ));
    }
    Ok(())
}

pub fn decode_pubkey(candidate: &str) -> Result<[u8; 32], String> {
    let bytes = bs58::decode(candidate)
        .into_vec()
        .map_err(|_| format!("`{candidate}` is not valid base58"))?;
    bytes
        .try_into()
        .map_err(|_| format!("`{candidate}` is not a valid Solana pubkey"))
}

/// Decodes a well-known base58 constant defined in this module. Only called
/// with the program and sysvar ids above, all of which are covered by tests.
fn known_key(constant: &str) -> [u8; 32] {
    decode_pubkey(constant).expect("static base58 constant must decode")
}

// ---------------------------------------------------------------------------
// Action and argument validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Delegate,
    Deactivate,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Delegate => "delegate",
            Action::Deactivate => "deactivate",
        }
    }
}

pub fn parse_action(raw: &str) -> Result<Action, String> {
    match raw.trim() {
        "delegate" => Ok(Action::Delegate),
        "deactivate" => Ok(Action::Deactivate),
        other => Err(format!(
            "action must be `delegate` or `deactivate`, got `{other}`"
        )),
    }
}

/// Validates the `vote_account` argument against the action and the
/// configured allowlist. Delegate without an allowlist is refused outright:
/// the operator has to opt in to every delegation target.
pub fn validate_vote(
    cfg: &Config,
    action: Action,
    vote_arg: Option<&str>,
) -> Result<Option<String>, String> {
    match action {
        Action::Deactivate => {
            if vote_arg.is_some() {
                return Err("`vote_account` is only valid for the delegate action".to_string());
            }
            Ok(None)
        }
        Action::Delegate => {
            let vote = vote_arg
                .ok_or("delegate requires a `vote_account` argument")?
                .trim()
                .to_string();
            if cfg.allowed_vote_accounts.is_empty() {
                return Err(
                    "delegate is disabled: config key `allowed_vote_accounts` is empty or unset; list at least one vote account to enable it"
                        .to_string(),
                );
            }
            if !cfg.allowed_vote_accounts.iter().any(|v| v == &vote) {
                // The format is named in the refusal itself. Without it a model
                // relaying this error to the operator invents a shape, and the
                // one it reaches for is a bare TOML array, which the host rejects:
                // operator storage is a string map, so the value is a quoted string
                // holding a JSON array.
                return Err(format!(
                    "vote account `{vote}` is not in the configured allowed_vote_accounts allowlist \
                     (a quoted string holding a JSON array of vote account pubkeys, \
                     not a bare TOML array)"
                ));
            }
            Ok(Some(vote))
        }
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC request bodies and response parsing
// ---------------------------------------------------------------------------

pub fn latest_blockhash_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash", "params": []
    })
    .to_string()
}

pub fn genesis_hash_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getGenesisHash", "params": []
    })
    .to_string()
}

pub fn nonce_account_body(pubkey: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
        "params": [pubkey, { "encoding": "base64" }]
    })
    .to_string()
}

/// One vote account, filtered server-side so the reply stays small instead of
/// carrying the whole validator roster.
///
/// `keepUnstakedDelinquents` is not optional here, despite the name suggesting
/// a nicety. By default the RPC omits delinquent validators that hold no active
/// stake, and on mainnet that is the overwhelming majority of them: a census
/// during review found 6136 of 6148 delinquents hidden behind the default. A
/// validator that stopped voting long enough to lose its stake is exactly the
/// one an operator must not delegate to, and without this flag it comes back
/// looking like an address the chain has never heard of.
pub fn vote_account_body(vote_pubkey: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getVoteAccounts",
        "params": [{ "votePubkey": vote_pubkey, "keepUnstakedDelinquents": true }]
    })
    .to_string()
}

/// Where the chain currently files a delegation target.
///
/// The allowlist is the enforcement boundary and it stays that way: an operator
/// decided, once, which validators they are willing to back. What the allowlist
/// cannot do is age. A validator entered months ago can stop voting tomorrow,
/// and the allowlist keeps saying yes. Solana's own CLI refuses the delegation
/// outright in that state (`Unable to delegate. Vote account appears
/// delinquent`), so an operator who has used the CLI expects the subject to come
/// up. This builder reports the standing in the summary and leaves the decision
/// where it belongs, because the operator may be delegating to a validator they
/// know is coming back, and a hard refusal here would strand them with no way
/// through short of editing config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoterStanding {
    /// The RPC lists the vote account among current voters.
    Current,
    /// The RPC lists it among delinquent voters: it has stopped voting.
    Delinquent,
    /// The roster came back without this vote account in either list.
    Absent,
    /// The standing could not be read. A failed lookup is not evidence of
    /// health, and it is rendered as its own case rather than folded into
    /// `Current`, which would turn a network problem into a clean bill.
    Unread,
}

/// Where the chain currently files the stake account a `deactivate` would act
/// on.
///
/// The allowlist says this account belongs to the operator. It cannot say
/// whether deactivating it means anything today. A stake that already finished
/// cooling down is a normal, healthy state, and asking the Stake program to
/// deactivate it again is rejected with `AlreadyDeactivated`. Without this
/// check the operator gets well-formed bytes, signs them in their wallet, pays
/// the fee, and learns the answer from a failed transaction. Found exactly that
/// way on devnet during a live rehearsal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeStanding {
    /// Delegated to a validator with no deactivation requested.
    Delegated,
    /// A deactivation is already recorded, so the stake is cooling down or done.
    AlreadyDeactivating,
    /// The account carries no delegation record at all.
    NotDelegated,
    /// The chain holds no stake account at this address: either nothing lives
    /// there, or what lives there belongs to another program. This is an
    /// established fact rather than a failure to look, so it stays distinct from
    /// `Unread`. Folding it into `Unread` would soften "this cannot work" into
    /// "we did not check".
    Missing,
    /// The state could not be read. Rendered as its own case, never folded into
    /// `Delegated`, which would turn a network problem into a green light.
    Unread,
}

/// One account, parsed by the RPC so the layout stays the node's problem.
pub fn stake_account_body(pubkey: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
        "params": [pubkey, { "encoding": "jsonParsed" }]
    })
    .to_string()
}

/// Reads the delegation lifecycle out of a `jsonParsed` stake account.
///
/// The numeric delegation fields arrive as decimal strings, and an active stake
/// carries `deactivationEpoch` equal to `u64::MAX` rendered as a string. So the
/// question "has a deactivation already been requested" is answered by that one
/// field, without needing the current epoch and a second round trip: any value
/// other than the sentinel means the operator, or someone holding the
/// authority, already asked for this.
pub fn parse_stake_standing(body: &str) -> Result<StakeStanding, String> {
    let r = rpc_result(body)?;
    let value = r.get("value").ok_or("getAccountInfo reply has no value")?;
    if value.is_null() {
        return Ok(StakeStanding::Missing);
    }
    // Establish that this is a stake account before saying anything about its
    // delegation. Without the owner gate every address answered "carries no
    // delegation, so there is nothing to deactivate", including an ordinary
    // wallet and an SPL token account, which is a claim about the chain the code
    // never checked. `stake-monitor` already gates on the same two fields.
    let owner = value.get("owner").and_then(Value::as_str).unwrap_or("");
    let program = value
        .get("data")
        .and_then(|d| d.get("program"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if owner != STAKE_PROGRAM_ID || program != "stake" {
        return Ok(StakeStanding::Missing);
    }

    let delegation = value
        .get("data")
        .and_then(|d| d.get("parsed"))
        .and_then(|p| p.get("info"))
        .and_then(|i| i.get("stake"))
        .and_then(|s| s.get("delegation"));

    let Some(delegation) = delegation else {
        return Ok(StakeStanding::NotDelegated);
    };
    let deactivation_epoch = delegation
        .get("deactivationEpoch")
        .and_then(Value::as_str)
        .ok_or("delegation carries no deactivationEpoch")?
        .parse::<u64>()
        .map_err(|_| "deactivationEpoch is not a number".to_string())?;

    if deactivation_epoch == u64::MAX {
        Ok(StakeStanding::Delegated)
    } else {
        Ok(StakeStanding::AlreadyDeactivating)
    }
}

/// Reads a `getVoteAccounts` reply filtered by `votePubkey`.
///
/// Only the standing is taken. Commission and vote lag belong to the monitoring
/// tool, which reads them for accounts the operator already holds; repeating
/// them in a pre-signing summary would pad the one line a human has to read.
pub fn parse_voter_standing(body: &str, voter: &str) -> Result<VoterStanding, String> {
    let r = rpc_result(body)?;
    // Both rosters must be present and must be arrays before absence means
    // anything. Without this gate a reply of `{}`, `[]`, `null` or a bare string
    // fell through to `Absent`, and the operator read "the chain does not know
    // this validator at all" about an address the code never looked up. An
    // unreadable answer is an unread answer, and the caller renders that
    // honestly.
    let roster = |list: &str| -> Option<&Vec<Value>> { r.get(list).and_then(Value::as_array) };
    let (Some(current), Some(delinquent)) = (roster("current"), roster("delinquent")) else {
        return Err("getVoteAccounts reply carries no current/delinquent rosters".to_string());
    };
    let holds = |entries: &Vec<Value>| -> bool {
        entries
            .iter()
            .any(|v| v.get("votePubkey").and_then(Value::as_str) == Some(voter))
    };
    // Current is checked first: a validator that resumed voting can briefly
    // appear in both lists, and the recovering case is the truthful one.
    if holds(current) {
        return Ok(VoterStanding::Current);
    }
    if holds(delinquent) {
        return Ok(VoterStanding::Delinquent);
    }
    Ok(VoterStanding::Absent)
}
/// Longest upstream error text the report will carry.
const MAX_UPSTREAM_MSG: usize = 160;

/// Renders a message chosen by the RPC endpoint as an explicit quotation.
///
/// The `error.message` field of a JSON-RPC reply is written by whoever runs that
/// endpoint, and it lands in text an LLM reads. An endpoint that is hostile,
/// compromised, or sitting behind an interception proxy can put a sentence there
/// and have it relayed into the agent's context verbatim. Marking the text as a
/// quotation, stripping control characters that would break the report's line
/// structure, and capping the length leaves the diagnostic value intact while
/// denying the foothold.
fn quote_upstream(msg: &str) -> String {
    // The double quote is folded to a single one: the text is wrapped in
    // quotation marks, and a quote inside it would close that wrapper early and
    // let the rest of an upstream-chosen sentence read as our own words.
    let cleaned: String = msg
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '\"' { '\'' } else { c })
        .take(MAX_UPSTREAM_MSG)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "upstream sent an empty message".to_string()
    } else {
        format!("upstream said: \"{trimmed}\"")
    }
}

fn rpc_result(body: &str) -> Result<Value, String> {
    let root: Value =
        serde_json::from_str(body).map_err(|e| format!("RPC reply is not JSON: {e}"))?;
    // A null `error` beside a valid result is the JSON-RPC 1.0 success
    // convention, and proxies in front of Solana endpoints still emit it.
    // `get` answers `Some(Null)` there, so an unfiltered guard read that
    // success as a failure and threw away the result it was carrying, turning
    // a good reply into "RPC error, upstream sent an empty message".
    if let Some(err) = root.get("error").filter(|e| !e.is_null()) {
        let msg = err.get("message").and_then(Value::as_str).unwrap_or("?");
        return Err(format!("RPC error, {}", quote_upstream(msg)));
    }
    root.get("result")
        .cloned()
        .ok_or_else(|| "RPC reply has no result".to_string())
}

/// Extracts the cluster genesis hash from a `getGenesisHash` reply, whose
/// result is the bare base58 hash. A missing, null, or malformed result is an
/// error rather than a skipped check, so an endpoint that answers with
/// anything unexpected fails the gate instead of passing it.
pub fn parse_genesis_hash(body: &str) -> Result<String, String> {
    let r = rpc_result(body)?;
    let hash = r.as_str().ok_or("getGenesisHash reply has no hash")?.trim();
    // The rejected string is endpoint-chosen text on the one read that runs
    // before every build, and it reaches the model through `fail` in lib.rs.
    // It used to be interpolated raw, so an endpoint could push newlines and an
    // unbounded body into the agent's context on this path while `error.message`
    // right beside it was quoted, stripped and capped.
    validate_pubkey(hash, "genesis hash").map_err(|_| {
        format!(
            "genesis hash is not 32 bytes of base58, {}",
            quote_upstream(hash)
        )
    })?;
    Ok(hash.to_string())
}

pub fn parse_latest_blockhash(body: &str) -> Result<[u8; 32], String> {
    let r = rpc_result(body)?;
    let hash = r
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(Value::as_str)
        .ok_or("getLatestBlockhash reply has no blockhash")?;
    // Same trust boundary as the genesis path: the `result` field is written by
    // whoever runs the endpoint, so a malformed blockhash is quoted rather than
    // echoed verbatim.
    decode_pubkey(hash).map_err(|_| {
        format!(
            "blockhash is not 32 bytes of base58, {}",
            quote_upstream(hash)
        )
    })
}

/// Layout of a nonce account, per `NonceAccountLayout` in solana-web3.js and
/// `nonce::state` in solana-sdk: version tag `u32` at 0..4, state tag `u32` at
/// 4..8, authority at 8..40, the durable nonce at 40..72, and the fee calculator
/// at 72..80.
const NONCE_ACCOUNT_LEN: usize = 80;
/// `Versions::Current`. `Versions::Legacy` is tag 0, and solana-sdk's
/// `verify_recent_blockhash` refuses it outright: "Legacy durable nonces are
/// invalid and should not allow durable transactions."
const NONCE_VERSION_CURRENT: u32 = 1;
/// `State::Initialized`. Tag 0 is `State::Uninitialized`, which the runtime also
/// refuses, and whose nonce field is 32 zero bytes.
const NONCE_STATE_INITIALIZED: u32 = 1;

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Extracts the durable blockhash from a nonce account read with
/// `getAccountInfo` (encoding base64), and checks the account against the
/// authority the operator configured.
///
/// Both tags are checked before the nonce field is trusted. An account that was
/// allocated and assigned to the System program but never initialized carries
/// state tag 0 and a nonce field of 32 zero bytes; reading it blindly produces a
/// transaction that no validator will ever accept, and the failure surfaces only
/// after a human has signed. A legacy-version account is refused for the same
/// reason the runtime refuses it.
///
/// The authority at 8..40 is compared with `expected_authority` because
/// `AdvanceNonceAccount` is authorized by the key the chain records, while the
/// instruction this builder emits names the key the config carries. When those
/// two disagree the transaction cannot land, so building it would spend an
/// operator's approval on bytes that were dead before they were signed.
pub fn parse_nonce_blockhash(body: &str, expected_authority: &str) -> Result<[u8; 32], String> {
    let expected = decode_pubkey(expected_authority)?;
    let r = rpc_result(body)?;
    let value = r
        .get("value")
        .filter(|v| !v.is_null())
        .ok_or("nonce account not found on chain")?;
    let owner = value.get("owner").and_then(Value::as_str).unwrap_or("");
    if owner != SYSTEM_PROGRAM_ID {
        // A genuine reply always carries a base58 pubkey here, so naming the
        // real program id keeps the diagnostic whole. Anything else is
        // endpoint-chosen text that used to be interpolated raw and uncapped
        // into an error the model reads, the same foothold `quote_upstream`
        // already denies on the `error.message` route.
        let shown = match validate_pubkey(owner, "owner") {
            Ok(()) => format!("`{owner}`"),
            Err(_) => "a value that is not a pubkey".to_string(),
        };
        return Err(format!(
            "nonce account is owned by {shown}; expected the System program"
        ));
    }
    let b64 = value
        .get("data")
        .and_then(Value::as_array)
        .and_then(|d| d.first())
        .and_then(Value::as_str)
        .ok_or("nonce account data is not base64-encoded")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("nonce account data is not valid base64: {e}"))?;
    if bytes.len() < NONCE_ACCOUNT_LEN {
        return Err(format!(
            "nonce account data is {} bytes, expected at least {NONCE_ACCOUNT_LEN}: this is not a nonce account",
            bytes.len()
        ));
    }
    let version = le_u32(&bytes[0..4]);
    if version != NONCE_VERSION_CURRENT {
        return Err(format!(
            "nonce account carries version tag {version}, expected {NONCE_VERSION_CURRENT}: a legacy nonce cannot authorize a durable transaction"
        ));
    }
    let state = le_u32(&bytes[4..8]);
    if state != NONCE_STATE_INITIALIZED {
        return Err(format!(
            "nonce account is not initialized (state tag {state}): run InitializeNonceAccount before using it as a durable nonce"
        ));
    }
    if bytes[8..40] != expected {
        return Err(format!(
            "nonce account is controlled by `{}`, but config key `nonce_authority` says `{expected_authority}`; AdvanceNonceAccount would be signed by the wrong key and the transaction could not land",
            bs58::encode(&bytes[8..40]).into_string()
        ));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[40..72]);
    // An initialized account cannot hold a zeroed nonce, so this is a
    // belt-and-braces refusal against a shape the tags said was valid.
    if hash == [0u8; 32] {
        return Err(
            "nonce account reports initialized but holds an all-zero nonce; refusing to build a transaction that cannot land".to_string(),
        );
    }
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// DelegateStake. Discriminant 2 as u32 little-endian, no payload; account
/// order and flags exactly as in `solana-program::stake::instruction`
/// (`delegate_stake`), confirmed byte for byte against the mainnet fixture.
/// Account 4 is the deprecated stake config: unused by the program but
/// positionally required.
pub fn delegate_stake_instruction(
    stake: [u8; 32],
    authority: [u8; 32],
    vote: [u8; 32],
) -> Instruction {
    Instruction {
        program_id: known_key(STAKE_PROGRAM_ID),
        accounts: vec![
            AccountMeta {
                pubkey: stake,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: vote,
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: known_key(SYSVAR_CLOCK_ID),
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: known_key(SYSVAR_STAKE_HISTORY_ID),
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: known_key(STAKE_CONFIG_ID),
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data: vec![2, 0, 0, 0],
    }
}

/// Deactivate. Discriminant 5 as u32 little-endian, no payload; account
/// order and flags exactly as in `solana-program::stake::instruction`
/// (`deactivate_stake`). Takes neither stake history nor stake config.
pub fn deactivate_instruction(stake: [u8; 32], authority: [u8; 32]) -> Instruction {
    Instruction {
        program_id: known_key(STAKE_PROGRAM_ID),
        accounts: vec![
            AccountMeta {
                pubkey: stake,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: known_key(SYSVAR_CLOCK_ID),
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data: vec![5, 0, 0, 0],
    }
}

/// AdvanceNonceAccount. System program discriminant 4 as u32 little-endian,
/// no payload; account order and flags exactly as in
/// `solana-program::system_instruction::advance_nonce_account`. The
/// deprecated RecentBlockhashes sysvar is still mandatory in the instruction.
pub fn advance_nonce_instruction(nonce: [u8; 32], nonce_authority: [u8; 32]) -> Instruction {
    Instruction {
        program_id: known_key(SYSTEM_PROGRAM_ID),
        accounts: vec![
            AccountMeta {
                pubkey: nonce,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: known_key(SYSVAR_RECENT_BLOCKHASHES_ID),
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: nonce_authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data: vec![4, 0, 0, 0],
    }
}

// ---------------------------------------------------------------------------
// compact-u16
// ---------------------------------------------------------------------------

/// Encodes a value as compact-u16 (1 to 3 bytes), matching `ShortU16` in the
/// `solana-sdk` `short_vec` module: 7 payload bits per byte, high bit set on
/// every byte that has a continuation.
pub fn encode_compact_u16(value: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    let mut rem = u32::from(value);
    loop {
        let byte = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Decodes a compact-u16 prefix, returning the value and the number of
/// bytes consumed. The inverse of [`encode_compact_u16`]; tests use it to
/// walk serialized messages.
pub fn decode_compact_u16(bytes: &[u8]) -> Option<(u16, usize)> {
    let mut value: u32 = 0;
    let mut consumed = 0usize;
    loop {
        let byte = u32::from(*bytes.get(consumed)?);
        value |= (byte & 0x7f) << (7 * consumed as u32);
        consumed += 1;
        if byte & 0x80 == 0 {
            break;
        }
        if consumed == 3 {
            return None;
        }
    }
    if value > u32::from(u16::MAX) {
        return None;
    }
    Some((value as u16, consumed))
}

// ---------------------------------------------------------------------------
// Message compilation and serialization
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub account_indices: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CompiledMessage {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    pub account_keys: Vec<[u8; 32]>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

struct KeyMeta {
    key: [u8; 32],
    signer: bool,
    writable: bool,
}

fn upsert(metas: &mut Vec<KeyMeta>, key: [u8; 32], signer: bool, writable: bool) {
    match metas.iter_mut().find(|m| m.key == key) {
        Some(m) => {
            m.signer |= signer;
            m.writable |= writable;
        }
        None => metas.push(KeyMeta {
            key,
            signer,
            writable,
        }),
    }
}

/// Deduplicates account keys and partitions them into the four groups the
/// legacy message header implies: signer writable first, then signer
/// read-only, then non-signer writable, then non-signer read-only. Within a
/// group the order is first appearance, with the fee payer always in front
/// and program ids appended after all instruction accounts (an
/// implementation choice; the wire format only fixes the group order, and
/// header bytes partition the array without per-account flags).
pub fn compile_message(
    fee_payer: [u8; 32],
    instructions: &[Instruction],
    recent_blockhash: [u8; 32],
) -> Result<CompiledMessage, String> {
    let mut metas: Vec<KeyMeta> = vec![KeyMeta {
        key: fee_payer,
        signer: true,
        writable: true,
    }];
    for ix in instructions {
        for a in &ix.accounts {
            upsert(&mut metas, a.pubkey, a.is_signer, a.is_writable);
        }
    }
    for ix in instructions {
        upsert(&mut metas, ix.program_id, false, false);
    }

    let mut ordered: Vec<&KeyMeta> = Vec::with_capacity(metas.len());
    for (signer, writable) in [(true, true), (true, false), (false, true), (false, false)] {
        ordered.extend(
            metas
                .iter()
                .filter(|m| m.signer == signer && m.writable == writable),
        );
    }
    if ordered.len() > u8::MAX as usize {
        return Err(format!("too many account keys: {}", ordered.len()));
    }

    let signers = ordered.iter().filter(|m| m.signer).count();
    let readonly_signed = ordered.iter().filter(|m| m.signer && !m.writable).count();
    let readonly_unsigned = ordered.iter().filter(|m| !m.signer && !m.writable).count();
    let account_keys: Vec<[u8; 32]> = ordered.iter().map(|m| m.key).collect();

    let index_of = |key: [u8; 32]| -> Result<u8, String> {
        account_keys
            .iter()
            .position(|k| *k == key)
            .map(|i| i as u8)
            .ok_or_else(|| "internal: account key vanished during compilation".to_string())
    };

    let mut compiled = Vec::with_capacity(instructions.len());
    for ix in instructions {
        let account_indices = ix
            .accounts
            .iter()
            .map(|a| index_of(a.pubkey))
            .collect::<Result<Vec<u8>, String>>()?;
        compiled.push(CompiledInstruction {
            program_id_index: index_of(ix.program_id)?,
            account_indices,
            data: ix.data.clone(),
        });
    }

    Ok(CompiledMessage {
        num_required_signatures: signers as u8,
        num_readonly_signed: readonly_signed as u8,
        num_readonly_unsigned: readonly_unsigned as u8,
        account_keys,
        recent_blockhash,
        instructions: compiled,
    })
}

/// Serializes a legacy message in the wire order of the `solana-sdk` legacy
/// `Message`: three header bytes, compact-u16 key count, the 32-byte keys,
/// the recent blockhash, compact-u16 instruction count, then each compiled
/// instruction as program index, compact-u16 account count, account
/// indices, compact-u16 data length, data.
pub fn serialize_message(msg: &CompiledMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 32 * msg.account_keys.len() + 64);
    out.push(msg.num_required_signatures);
    out.push(msg.num_readonly_signed);
    out.push(msg.num_readonly_unsigned);
    out.extend_from_slice(&encode_compact_u16(msg.account_keys.len() as u16));
    for key in &msg.account_keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&msg.recent_blockhash);
    out.extend_from_slice(&encode_compact_u16(msg.instructions.len() as u16));
    for ix in &msg.instructions {
        out.push(ix.program_id_index);
        out.extend_from_slice(&encode_compact_u16(ix.account_indices.len() as u16));
        out.extend_from_slice(&ix.account_indices);
        out.extend_from_slice(&encode_compact_u16(ix.data.len() as u16));
        out.extend_from_slice(&ix.data);
    }
    out
}

/// Serializes the full wire transaction the `solana-sdk` legacy `Transaction`
/// describes: compact-u16 signature count, then the signatures, then the
/// message. For an unsigned transaction the signature count still equals
/// num_required_signatures and each slot holds 64 zero bytes; the wallet
/// replaces the placeholders when it signs. The tool hands back this
/// whole-transaction form and no separate message blob.
pub fn serialize_transaction(num_required_signatures: u8, message: &[u8]) -> Vec<u8> {
    let sig_bytes = 64 * num_required_signatures as usize;
    let mut out = Vec::with_capacity(3 + sig_bytes + message.len());
    out.extend_from_slice(&encode_compact_u16(u16::from(num_required_signatures)));
    out.resize(out.len() + sig_bytes, 0);
    out.extend_from_slice(message);
    out
}

// ---------------------------------------------------------------------------
// Top-level build
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Built {
    pub summary: String,
    pub tx_base64: String,
}

impl Built {
    /// Two-line tool output: a human summary for the approval gate, then
    /// the base64 payload on its own labeled line.
    pub fn output(&self) -> String {
        format!("{}\nunsigned_tx_base64: {}", self.summary, self.tx_base64)
    }
}

/// Assembles the unsigned transaction. When the config carries a nonce
/// pair, an AdvanceNonceAccount instruction goes first and `blockhash` must
/// be the durable value read from the nonce account, which keeps the
/// transaction valid while it waits for operator approval. Without a nonce
/// the caller passes a fresh blockhash and the summary warns about the
/// short validity window. The staked amount is deliberately absent from
/// the summary: this builder never reads it and must not guess.
pub fn build_transaction(
    cfg: &Config,
    action: Action,
    stake: &StakeAccountRef,
    vote: Option<&str>,
    blockhash: [u8; 32],
    standing: Option<VoterStanding>,
    stake_standing: Option<StakeStanding>,
) -> Result<Built, String> {
    let authority = decode_pubkey(&cfg.authority)?;
    let stake_key = decode_pubkey(&stake.pubkey)?;

    let mut instructions = Vec::with_capacity(2);
    if let Some(nonce) = &cfg.nonce {
        instructions.push(advance_nonce_instruction(
            decode_pubkey(&nonce.account)?,
            decode_pubkey(&nonce.authority)?,
        ));
    }
    let voter = match (action, vote) {
        (Action::Delegate, Some(v)) => {
            let vote_key = decode_pubkey(v)?;
            instructions.push(delegate_stake_instruction(stake_key, authority, vote_key));
            Some(v.to_string())
        }
        (Action::Deactivate, None) => {
            instructions.push(deactivate_instruction(stake_key, authority));
            None
        }
        _ => return Err("internal: action and vote_account mismatch".to_string()),
    };

    let message = compile_message(authority, &instructions, blockhash)?;
    let message_bytes = serialize_message(&message);
    let tx_bytes = serialize_transaction(message.num_required_signatures, &message_bytes);
    let tx_base64 = base64::engine::general_purpose::STANDARD.encode(tx_bytes);

    // The summary is what a human reads before signing, so it names the
    // addresses that are actually encoded in the bytes above. Naming only the
    // config label would ask the operator to approve `main` while the signature
    // covers whatever pubkey that label happens to point at: a mislabeled entry
    // would then be confirmed, not caught. Addresses are given in full because
    // the operator's job here is to compare them against what they expect, and a
    // truncated address can be ground out to collide on its visible ends.
    // Kept to a single line: `output()` puts the summary on line one and the
    // base64 on line two, and callers split on that.
    // The instruction against shortening is addressed at whatever relays this
    // line to the operator. A chat agent will happily render
    // `6ySLT...Gifp` for readability, and that undoes the reason the addresses
    // are here: an attacker can grind a keypair whose address shares the
    // visible head and tail, so an operator checking only the ends approves the
    // wrong account. Observed live on 2026-07-28, where the model truncated both
    // addresses in its own retelling.
    // `compile_message` counts the signers from the account metas, so a nonce
    // authority held on a different key makes this a two-signature transaction.
    // Calling the fee payer the sole signer there would tell the operator the
    // approval ends with them, while the bytes still wait on a key they may not
    // hold. The count comes from the message that was actually serialized.
    let signer_phrase = if message.num_required_signatures <= 1 {
        format!("fee payer and sole signer {}", cfg.authority)
    } else {
        format!(
            "fee payer {} (this transaction carries {} required signatures)",
            cfg.authority, message.num_required_signatures
        )
    };
    let mut summary = format!(
        "Unsigned {} transaction. Verify each address below in full before signing, and do not abbreviate them when relaying: a shortened address can be ground to match on its visible ends. Stake account {} (config label `{}`), {}",
        action.as_str(),
        stake.pubkey,
        stake.label,
        signer_phrase,
    );
    if let Some(v) = &voter {
        summary.push_str(&format!(", vote account {v}"));
        // The standing goes next to the address it describes, so an operator
        // scanning the line meets the warning before the lifetime clause and
        // the base64. Nothing is said when the validator is currently voting:
        // a summary that comments on every healthy case teaches the reader to
        // skip the sentence that matters.
        match standing {
            Some(VoterStanding::Delinquent) => summary.push_str(
                " (WARNING: this vote account is currently listed as DELINQUENT, meaning it has stopped voting; stake delegated to it earns nothing until it recovers, and the official Solana CLI rejects this delegation)",
            ),
            Some(VoterStanding::Absent) => summary.push_str(
                " (WARNING: this vote account appears in neither the current nor the delinquent validator list, so the chain does not know it as a voting validator at all)",
            ),
            Some(VoterStanding::Unread) => summary.push_str(
                " (note: the validator's standing could not be read, so this transaction was built without confirming the target is still voting)",
            ),
            Some(VoterStanding::Current) | None => {}
        }
    }
    // The mirror of the voter check, on the other action. A delegate asks
    // whether the target still votes; a deactivate asks whether there is
    // anything to deactivate. Same boundary, same reason: the allowlist is a
    // statement about ownership, not about what the chain holds right now.
    // Silence on the healthy case for the same reason as above.
    if action == Action::Deactivate {
        match stake_standing {
            Some(StakeStanding::AlreadyDeactivating) => summary.push_str(
                " (WARNING: this stake already has a deactivation recorded on chain, so it is cooling down or already inactive; the Stake program rejects a second deactivation with AlreadyDeactivated, and signing this would cost a fee for a transaction that cannot land)",
            ),
            Some(StakeStanding::NotDelegated) => summary.push_str(
                " (WARNING: this stake account carries no delegation, so there is nothing to deactivate)",
            ),
            Some(StakeStanding::Missing) => summary.push_str(
                " (WARNING: the configured cluster holds no stake account at this address, so this transaction cannot land; check the address in config and check that rpc_url points at the cluster you meant)",
            ),
            Some(StakeStanding::Unread) => summary.push_str(
                " (note: the stake's on-chain state could not be read, so this transaction was built without confirming there is an active delegation to deactivate)",
            ),
            Some(StakeStanding::Delegated) | None => {}
        }
    }
    if let Some(nonce) = &cfg.nonce {
        summary.push_str(&format!(
            ", nonce account {} (authority {}{})",
            nonce.account,
            nonce.authority,
            if nonce.authority == cfg.authority {
                ""
            } else {
                ", a separate key that must sign this transaction too"
            }
        ));
    }
    summary.push_str(if cfg.nonce.is_some() {
        "; lifetime: durable nonce, stays valid until the nonce advances, so it can wait in an approval queue"
    } else {
        "; lifetime: fresh blockhash, sign and submit within roughly 60 to 90 seconds"
    });
    summary.push_str("; amount: not read by this builder.");

    Ok(Built { summary, tx_base64 })
}
