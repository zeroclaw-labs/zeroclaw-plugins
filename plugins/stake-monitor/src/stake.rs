//! Pure core of the `stake_monitor` tool: config parsing, JSON-RPC request
//! construction, response parsing, status derivation, and report rendering.
//! No wasm and no I/O in here, so the whole module runs under a plain host
//! `cargo test`.
//!
//! Response shapes were verified against live mainnet RPC calls on
//! 2026-07-18: `getEpochInfo`, `getVoteAccounts` (with the `votePubkey`
//! filter), `getAccountInfo` (jsonParsed), and `getInflationReward`.
//! Numeric delegation fields arrive as decimal strings; an active stake has
//! `deactivationEpoch` equal to u64::MAX rendered as a string. Vote lag and
//! epoch progress are derived from fields those same replies already carry,
//! so neither reading costs an extra call.

use serde::Deserialize;
use serde_json::Value;

/// Hard cap for the delivered payload, in characters: the rendered report and
/// the data-issues line together. Keeps the tool output around 200 tokens so a
/// scheduled briefing never floods the agent context.
pub const REPORT_CHAR_CAP: usize = 900;

/// Share of [`REPORT_CHAR_CAP`] the data-issues line may claim. The account
/// rows are what the briefing is for, so a run that collected a long list of
/// failed reads still leaves two thirds of the payload to them.
const ISSUE_CHAR_BUDGET: usize = REPORT_CHAR_CAP / 3;

/// Bounds an error string to [`REPORT_CHAR_CAP`] before it is handed back to the
/// agent.
///
/// The report path has been capped since the beginning; the failure path was
/// not, and several failure messages interpolate a value the model chose. A call
/// carrying a multi-kilobyte argument got that argument back in full, so the
/// bound the threat model claims held on one path and not the other. Truncation
/// is on a character boundary, because the interpolated value can carry
/// multi-byte text and a byte-sliced string is not a string.
pub fn cap_failure(message: String) -> String {
    if message.chars().count() <= REPORT_CHAR_CAP {
        return message;
    }
    const MARKER: &str = "… (truncated)";
    let keep = REPORT_CHAR_CAP.saturating_sub(MARKER.chars().count());
    let mut out: String = message.chars().take(keep).collect();
    out.push_str(MARKER);
    out
}

const ISSUE_PREFIX: &str = "\nData issues: ";

const ISSUE_SEPARATOR: &str = "; ";

pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Every key this plugin reads out of its own config section.
///
/// Since the host began validating typed instance config, the guest no longer
/// polices unknown keys: `additionalProperties = false` in `manifest.toml`
/// rejects an undeclared key before the component starts. What this array is
/// for now is the test that reads `manifest.toml` and asserts the schema
/// declares exactly these keys, so a key added here and forgotten there fails
/// the build rather than the operator's first run.
pub const CONFIG_KEYS: [&str; 4] = [
    "stake_accounts",
    "rpc_url",
    "vote_lag_warn_slots",
    "timeout_secs",
];

const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

/// Average slot time used only for the human "epoch ends in ~N h" hint.
const SECONDS_PER_SLOT: f64 = 0.4;

/// Slots behind the chain tip at which `getVoteAccounts` already reports a
/// vote account as delinquent: the `delinquentSlotDistance` default the RPC
/// applies when the call leaves that parameter out. A warn threshold above it
/// could only fire after the verdict it is meant to precede, so it is the
/// upper bound for `vote_lag_warn_slots`.
pub const DELINQUENT_SLOT_DISTANCE: u64 = 128;

/// Default vote lag, in slots, past which a still-voting validator is called
/// out as drifting. A quarter of [`DELINQUENT_SLOT_DISTANCE`] is roughly 13
/// seconds of missed voting: early enough to act on, and far enough above
/// normal jitter to stay quiet on a healthy node. Operators who want a
/// different balance set the `vote_lag_warn_slots` config key.
pub const DEFAULT_VOTE_LAG_WARN_SLOTS: u64 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeAccountRef {
    pub label: String,
    pub pubkey: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub accounts: Vec<StakeAccountRef>,
    pub rpc_url: String,
    pub vote_lag_warn_slots: u64,
    pub timeout_secs: u64,
}

/// The shape of this plugin's config section as the host now hands it over.
///
/// Since zeroclaw-labs/zeroclaw#9126 the host validates the operator's values
/// against `[config_schema]` in `manifest.toml` and injects a *typed* JSON
/// object, so the allowlist arrives as an array and the thresholds as integers,
/// and there is no string splitting left for the guest to do.
///
/// Deliberately not `deny_unknown_fields`: `additionalProperties = false` in
/// the manifest already refuses an undeclared key before the component starts,
/// so guest-side strictness would add no protection and would turn a
/// forward-compatible schema addition into a hard failure.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawConfig {
    stake_accounts: Option<Vec<String>>,
    rpc_url: Option<String>,
    vote_lag_warn_slots: Option<u64>,
    timeout_secs: Option<u64>,
}

/// Describes a config deserialization failure without quoting the value that
/// caused it.
///
/// `serde_json::Error`'s `Display` embeds the offending value. Config values
/// here are stake pubkeys and the operator's own RPC endpoint, which the host
/// stores secret-marked and encrypted at rest, so echoing one into a
/// `ToolResult` would hand it straight back to the model.
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
    /// Both `stake_accounts` and `rpc_url` are `required` in the schema, so a
    /// schema-enforcing host never reaches the missing-key branches. They stay
    /// because host-side `cargo test` runs with no schema validation at all,
    /// and because a reader with no allowlist has nothing it is permitted to
    /// read.
    pub fn from_json(config: &Value) -> Result<Self, String> {
        let raw: RawConfig = if config.is_null() {
            RawConfig::default()
        } else {
            serde_json::from_value(config.clone()).map_err(|error| describe_error(&error))?
        };

        let accounts = parse_accounts(raw.stake_accounts.as_deref().ok_or(
            "config key `stake_accounts` is required: an allowlist array like [\"main:<pubkey>\"] or bare pubkeys",
        )?)?;

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

        let vote_lag_warn_slots = raw
            .vote_lag_warn_slots
            .unwrap_or(DEFAULT_VOTE_LAG_WARN_SLOTS);
        if vote_lag_warn_slots == 0 || vote_lag_warn_slots > DELINQUENT_SLOT_DISTANCE {
            return Err(format!(
                "vote_lag_warn_slots must be between 1 and {DELINQUENT_SLOT_DISTANCE}, got {vote_lag_warn_slots}"
            ));
        }

        let timeout_secs = raw.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if timeout_secs == 0 || timeout_secs > 60 {
            return Err(format!(
                "timeout_secs must be between 1 and 60, got {timeout_secs}"
            ));
        }

        Ok(Config {
            accounts,
            rpc_url,
            vote_lag_warn_slots,
            timeout_secs,
        })
    }

    /// Resolves the optional `account` argument against the allowlist. The
    /// model can only pick a configured account, never introduce a new one.
    pub fn resolve_account(
        &self,
        requested: Option<&str>,
    ) -> Result<Vec<&StakeAccountRef>, String> {
        match requested {
            None => Ok(self.accounts.iter().collect()),
            Some(query) => {
                let q = query.trim();
                reject_invisible(q, "requested stake account")?;
                let hit: Vec<&StakeAccountRef> = self
                    .accounts
                    .iter()
                    .filter(|a| a.label == q || a.pubkey == q)
                    .collect();
                if hit.is_empty() {
                    Err(format!(
                        "stake account `{q}` is not in the configured allowlist; known labels: {}",
                        self.accounts
                            .iter()
                            .map(|a| a.label.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                } else {
                    Ok(hit)
                }
            }
        }
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

// ---------------------------------------------------------------------------
// JSON-RPC request bodies
// ---------------------------------------------------------------------------

pub fn epoch_info_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getEpochInfo", "params": []
    })
    .to_string()
}

pub fn stake_account_body(pubkey: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
        "params": [pubkey, { "encoding": "jsonParsed" }]
    })
    .to_string()
}

/// One vote account, filtered server-side so the response stays tiny instead
/// of the full 700-validator roster.
///
/// `keepUnstakedDelinquents` is not optional here, despite the name suggesting
/// a nicety. By default the RPC omits delinquent validators that hold no active
/// stake, and on mainnet that is the overwhelming majority of them: a census
/// during review found 6136 of 6148 delinquents hidden behind the default. A
/// validator that stopped voting long enough to lose its stake is exactly the
/// one an operator needs told about, and without this flag it came back in
/// neither roster, mapped to [`ValidatorStatus::Unknown`], and rendered as
/// `status unknown` while the report raised no DELINQUENT flag at all. The
/// sibling plugin `stake-tx-build` passes the flag for the same reason.
pub fn vote_account_body(vote_pubkey: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getVoteAccounts",
        "params": [{ "votePubkey": vote_pubkey, "keepUnstakedDelinquents": true }]
    })
    .to_string()
}

pub fn inflation_reward_body(pubkeys: &[String], epoch: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getInflationReward",
        "params": [pubkeys, { "epoch": epoch }]
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------
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
    // A literal `"error": null` beside a good result is the JSON-RPC 1.0 success
    // convention, and proxies in front of Solana endpoints still emit it.
    // `get` answers `Some(Null)` there, so the unfiltered guard used to throw the
    // result away and report an upstream failure that never happened. The same
    // null filter already guards the `value` key below.
    if let Some(err) = root.get("error").filter(|e| !e.is_null()) {
        let msg = err.get("message").and_then(Value::as_str).unwrap_or("?");
        return Err(format!("RPC error, {}", quote_upstream(msg)));
    }
    root.get("result")
        .cloned()
        .ok_or_else(|| "RPC reply has no result".to_string())
}

/// Slot counters that describe a real epoch. The fields are private and the
/// only way in is [`EpochProgress::new`], so every reading below rests on the
/// invariant it checks: a non-zero epoch length with an index inside it.
#[derive(Debug, Clone, Copy)]
pub struct EpochProgress {
    slot_index: u64,
    slots_in_epoch: u64,
}

impl EpochProgress {
    /// `None` when the counters cannot describe an epoch: a zero-length one,
    /// or an index past its end. Both would poison the progress figure and
    /// the "hours left" hint, so they yield no reading at all.
    pub fn new(slot_index: u64, slots_in_epoch: u64) -> Option<Self> {
        if slots_in_epoch == 0 || slot_index > slots_in_epoch {
            return None;
        }
        Some(EpochProgress {
            slot_index,
            slots_in_epoch,
        })
    }

    pub fn hours_to_end(&self) -> u64 {
        let slots_left = self.slots_in_epoch - self.slot_index;
        (slots_left as f64 * SECONDS_PER_SLOT / 3600.0).round() as u64
    }

    /// How far the network has moved into the current epoch, in whole
    /// percent. Widened to u128 so a hostile pair of counters cannot overflow
    /// the multiplication; the constructor's invariant already caps the
    /// result at 100.
    pub fn pct(&self) -> u64 {
        (self.slot_index as u128 * 100 / self.slots_in_epoch as u128) as u64
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EpochInfo {
    pub epoch: u64,
    /// Network head at the time of the reply, and the reference point for
    /// every validator's vote lag. `None` when the reply carried no
    /// `absoluteSlot`, in which case lag reads as unknown rather than being
    /// measured against an invented head.
    pub absolute_slot: Option<u64>,
    /// `None` when the reply carried no usable slot counters, which costs the
    /// progress figure and nothing else.
    pub progress: Option<EpochProgress>,
}

/// Reads a `getEpochInfo` reply. Only the epoch number is load-bearing, since
/// the delegation lifecycle is derived from it. The head slot and the slot
/// counters degrade on their own: a reply missing `absoluteSlot`, or carrying
/// counters that cannot describe a real epoch, costs the vote-lag reading and
/// the progress figure while every other line of the report still renders.
pub fn parse_epoch_info(body: &str) -> Result<EpochInfo, String> {
    let r = rpc_result(body)?;
    let epoch = r
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or("epoch missing")?;
    let progress = match (
        r.get("slotIndex").and_then(Value::as_u64),
        r.get("slotsInEpoch").and_then(Value::as_u64),
    ) {
        (Some(index), Some(len)) => EpochProgress::new(index, len),
        _ => None,
    };
    Ok(EpochInfo {
        epoch,
        absolute_slot: r.get("absoluteSlot").and_then(Value::as_u64),
        progress,
    })
}

#[derive(Debug, Clone)]
pub struct Delegation {
    pub voter: String,
    pub stake_lamports: u64,
    pub activation_epoch: u64,
    pub deactivation_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct StakeState {
    pub lamports: u64,
    pub delegation: Option<Delegation>,
}

/// Delegation numbers arrive as decimal strings (u64 as string), with
/// u64::MAX meaning "no deactivation scheduled".
fn str_u64(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => s.trim().parse::<u64>().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

pub fn parse_stake_account(body: &str) -> Result<StakeState, String> {
    let r = rpc_result(body)?;
    let value = r
        .get("value")
        .filter(|v| !v.is_null())
        .ok_or("stake account not found on chain")?;
    let lamports = value
        .get("lamports")
        .and_then(Value::as_u64)
        .ok_or("lamports missing")?;
    let parsed = value
        .get("data")
        .and_then(|d| d.get("parsed"))
        .ok_or("account is not jsonParsed; is this a stake account?")?;
    let program = value
        .get("data")
        .and_then(|d| d.get("program"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if program != "stake" {
        // `program` comes from the RPC reply, so it is third-party text landing
        // in an error an LLM reads. It is quoted through the same path as any
        // other upstream string: control characters stripped, length capped,
        // inner quotes folded so the wrapper cannot be closed early.
        let program = quote_upstream(program);
        return Err(format!(
            "account is not owned by the stake program ({program})"
        ));
    }

    let delegation = parsed
        .get("info")
        .and_then(|i| i.get("stake"))
        .filter(|s| !s.is_null())
        .and_then(|s| s.get("delegation"))
        .and_then(|d| {
            Some(Delegation {
                voter: d.get("voter")?.as_str()?.to_string(),
                stake_lamports: str_u64(d.get("stake")?)?,
                activation_epoch: str_u64(d.get("activationEpoch")?)?,
                deactivation_epoch: str_u64(d.get("deactivationEpoch")?)?,
            })
        });

    Ok(StakeState {
        lamports,
        delegation,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorStatus {
    Ok {
        /// `None` when the reply carried neither `inflationRewardsCommissionBps`
        /// nor a numeric `commission`. Rendering an unread commission as 0.0%
        /// would put it beside genuine 0% validators with nothing to tell them
        /// apart, and 0% is the most favourable reading available.
        commission_bps: Option<u64>,
        last_vote_slot: Option<u64>,
    },
    Delinquent {
        commission_bps: Option<u64>,
        last_vote_slot: Option<u64>,
    },
    Unknown,
}

impl ValidatorStatus {
    /// Slots between the network head and this validator's last vote. `None`
    /// when the epoch reply carried no head slot, when the vote record
    /// carried no usable `lastVote`, or when the validator was not found at
    /// all, so an unread number never renders as a healthy zero.
    pub fn vote_lag(&self, absolute_slot: Option<u64>) -> Option<u64> {
        let head = absolute_slot?;
        match self {
            ValidatorStatus::Ok { last_vote_slot, .. }
            | ValidatorStatus::Delinquent { last_vote_slot, .. } => {
                last_vote_slot.map(|slot| head.saturating_sub(slot))
            }
            ValidatorStatus::Unknown => None,
        }
    }

    /// True when the validator still counts as current but its votes are
    /// drifting past `warn_slots`, the operator's `vote_lag_warn_slots`. This
    /// is the pre-delinquency signal; a validator the RPC already calls
    /// delinquent is reported as delinquent and is not double-flagged here.
    pub fn is_behind(&self, absolute_slot: Option<u64>, warn_slots: u64) -> bool {
        matches!(self, ValidatorStatus::Ok { .. })
            && self
                .vote_lag(absolute_slot)
                .is_some_and(|lag| lag > warn_slots)
    }
}

/// Renders a commission for a report line. An unread one says so; rendering it
/// as `0.0%` would be indistinguishable from a genuine zero-fee validator, and
/// the published reports carry both kinds of row side by side.
fn fmt_commission(commission_bps: Option<u64>) -> String {
    match commission_bps {
        Some(bps) => format!("fee {:.1}%", bps as f64 / 100.0),
        None => "fee unknown".to_string(),
    }
}

/// Reads a `getVoteAccounts` reply that was filtered by `votePubkey`.
/// Commission is taken from `inflationRewardsCommissionBps` when present,
/// with the legacy percentage `commission` as the fallback, because the
/// modern field is authoritative and the legacy one can lag. `lastVote` is
/// kept for the vote-lag reading; the RPC reports `0` for a vote account
/// that has never voted, which is an absent vote rather than a lag of the
/// whole chain history, so it is read as unknown.
pub fn parse_vote_status(body: &str, voter: &str) -> Result<ValidatorStatus, String> {
    let r = rpc_result(body)?;
    let pick = |list: &str| -> Option<(Option<u64>, Option<u64>)> {
        r.get(list)?
            .as_array()?
            .iter()
            .find(|v| v.get("votePubkey").and_then(Value::as_str) == Some(voter))
            .map(|v| {
                // A commission nobody could read must not render as 0.0%, the
                // most favourable value there is, beside genuine 0% validators
                // in the same report. `saturating_mul` because the legacy
                // percentage arrives from the endpoint and 100 * u64::MAX is
                // not a commission.
                let commission_bps = v
                    .get("inflationRewardsCommissionBps")
                    .and_then(Value::as_u64)
                    .or_else(|| {
                        v.get("commission")
                            .and_then(Value::as_u64)
                            .map(|pct| pct.saturating_mul(100))
                    });
                let last_vote_slot = v
                    .get("lastVote")
                    .and_then(Value::as_u64)
                    .filter(|slot| *slot > 0);
                (commission_bps, last_vote_slot)
            })
    };
    if let Some((commission_bps, last_vote_slot)) = pick("current") {
        return Ok(ValidatorStatus::Ok {
            commission_bps,
            last_vote_slot,
        });
    }
    if let Some((commission_bps, last_vote_slot)) = pick("delinquent") {
        return Ok(ValidatorStatus::Delinquent {
            commission_bps,
            last_vote_slot,
        });
    }
    Ok(ValidatorStatus::Unknown)
}

#[derive(Debug, Clone, Copy)]
pub struct Reward {
    pub amount_lamports: u64,
    pub commission_bps: Option<u64>,
}

/// Reads a `getInflationReward` reply: one entry per requested address,
/// null when the address earned nothing that epoch. The modern field is
/// `commissionBps`; the legacy `commission` can be null even when a reward
/// exists, so it is only a fallback.
pub fn parse_inflation_rewards(body: &str, expected: usize) -> Result<Vec<Option<Reward>>, String> {
    let r = rpc_result(body)?;
    let arr = r
        .as_array()
        .ok_or("getInflationReward result is not an array")?;
    if arr.len() != expected {
        return Err(format!(
            "getInflationReward returned {} entries, expected {expected}",
            arr.len()
        ));
    }
    Ok(arr
        .iter()
        .map(|v| {
            if v.is_null() {
                return None;
            }
            Some(Reward {
                amount_lamports: v.get("amount").and_then(Value::as_u64)?,
                commission_bps: v
                    .get("commissionBps")
                    .and_then(Value::as_u64)
                    .or_else(|| v.get("commission").and_then(Value::as_u64).map(|c| c * 100)),
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Status derivation and rendering
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeStatus {
    NotDelegated,
    Activating,
    Active,
    Deactivating,
    Inactive,
}

impl StakeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StakeStatus::NotDelegated => "not delegated",
            StakeStatus::Activating => "activating",
            StakeStatus::Active => "active",
            StakeStatus::Deactivating => "deactivating",
            StakeStatus::Inactive => "inactive",
        }
    }
}

pub fn derive_status(delegation: Option<&Delegation>, current_epoch: u64) -> StakeStatus {
    match delegation {
        None => StakeStatus::NotDelegated,
        Some(d) => {
            if d.deactivation_epoch == u64::MAX {
                if current_epoch <= d.activation_epoch {
                    StakeStatus::Activating
                } else {
                    StakeStatus::Active
                }
            } else if current_epoch <= d.deactivation_epoch {
                StakeStatus::Deactivating
            } else {
                StakeStatus::Inactive
            }
        }
    }
}

/// One fully assembled report row.
#[derive(Debug, Clone)]
pub struct Entry {
    pub label: String,
    pub state: StakeState,
    pub status: StakeStatus,
    pub validator: Option<ValidatorStatus>,
    /// Three states, the same honesty the validator reading already carries.
    /// `None` means the reward was never read: the `getInflationReward` call
    /// failed, or the run was too early in chain history to have a previous
    /// epoch to ask about. `Some(None)` means the reply carried `null` for this
    /// address, which is the epoch having genuinely paid nothing. Collapsing
    /// the two used to print "no reward last epoch" as a fact on every active
    /// row whenever the reward read failed.
    pub reward: Option<Option<Reward>>,
}

fn fmt_sol(lamports: u64) -> String {
    let sol = lamports as f64 / LAMPORTS_PER_SOL;
    if sol >= 100.0 {
        format!("{sol:.0}")
    } else {
        format!("{sol:.3}")
    }
}

/// One short vote-lag field. An unreadable `lastVote`, or an epoch reply that
/// carried no head slot to measure against, prints `unknown` instead of a
/// fabricated slot count.
fn fmt_vote_lag(validator: &ValidatorStatus, epoch: &EpochInfo, warn_slots: u64) -> String {
    match validator.vote_lag(epoch.absolute_slot) {
        Some(lag) if validator.is_behind(epoch.absolute_slot, warn_slots) => {
            format!("vote lag {lag} slot(s) BEHIND")
        }
        Some(lag) => format!("vote lag {lag} slot(s)"),
        None => "vote lag unknown".to_string(),
    }
}

/// The payload the tool delivers: the report, plus one trailing line naming
/// the reads that failed. The suffix is measured before the rows are rendered
/// and its room comes out of the rendering budget, so [`REPORT_CHAR_CAP`]
/// bounds everything the agent receives instead of only the part above the
/// suffix. The suffix itself never claims more than [`ISSUE_CHAR_BUDGET`], so
/// a run where every account failed still delivers a readable report.
pub fn render_payload(
    entries: &[Entry],
    epoch: &EpochInfo,
    cfg: &Config,
    issues: &[String],
) -> String {
    let suffix = render_issues(issues);
    let report = render_within(
        entries,
        epoch,
        cfg,
        REPORT_CHAR_CAP.saturating_sub(suffix.len()),
    );
    format!("{report}{suffix}")
}

/// Error text for a run where every stake account read failed, so there is no
/// report to deliver. The detail is the issue list rendered under
/// [`ISSUE_CHAR_BUDGET`], the bound the success path applies as well, since the
/// strings inside it were written by whatever server answered the RPC.
pub fn render_total_failure(issues: &[String]) -> String {
    let listed = render_issues(issues);
    // `render_issues` writes the trailing line of a report: a leading newline,
    // then a `Data issues: ` label. Neither belongs in a one-sentence error, so
    // both come off before the detail behind them is reused.
    let detail = listed
        .trim_start_matches('\n')
        .trim_start_matches("Data issues: ");
    format!("every stake account read failed: {detail}")
}

/// One line naming the reads that failed, empty when the run hit no trouble.
/// Issues past the budget are counted rather than spelled out, so a pile of
/// long RPC errors cannot push the payload past the cap.
fn render_issues(issues: &[String]) -> String {
    if issues.is_empty() {
        return String::new();
    }
    // No issue is dropped for free: whatever the budget pushes out is counted
    // in a marker whose room is reserved up front, at the widest count it
    // could carry.
    let reserve = ISSUE_SEPARATOR.len() + omitted_issues(issues.len()).len();
    let mut kept: Vec<&str> = Vec::new();
    let mut used = ISSUE_PREFIX.len();
    for issue in issues {
        let cost = issue.len()
            + if kept.is_empty() {
                0
            } else {
                ISSUE_SEPARATOR.len()
            };
        if used + cost > ISSUE_CHAR_BUDGET.saturating_sub(reserve) {
            break;
        }
        used += cost;
        kept.push(issue.as_str());
    }
    let omitted = issues.len() - kept.len();
    let mut line = format!("{ISSUE_PREFIX}{}", kept.join(ISSUE_SEPARATOR));
    if omitted > 0 {
        if !kept.is_empty() {
            line.push_str(ISSUE_SEPARATOR);
        }
        line.push_str(&omitted_issues(omitted));
    }
    line
}

fn omitted_issues(count: usize) -> String {
    format!("(+{count} more)")
}

fn omitted_lines(count: usize) -> String {
    format!("(+{count} more line(s) omitted)")
}

/// The account rows on their own, at the full [`REPORT_CHAR_CAP`] budget. A
/// run that also has failed reads to report goes through [`render_payload`],
/// which shares the same budget between the rows and the data-issues line.
pub fn render_report(entries: &[Entry], epoch: &EpochInfo, cfg: &Config) -> String {
    render_within(entries, epoch, cfg, REPORT_CHAR_CAP)
}

/// Renders the account rows within `budget` characters. Lowest lines drop
/// first, since the header carries the summary the operator reads before
/// anything else.
fn render_within(entries: &[Entry], epoch: &EpochInfo, cfg: &Config, budget: usize) -> String {
    if entries.is_empty() {
        return "No stake accounts to report.".to_string();
    }

    // A cooled-down account keeps its delegation record on chain, with the
    // deactivation epoch already behind us, so summing every record that exists
    // reports stake as delegated after it has stopped being delegated. Observed
    // on devnet on 2026-08-01: one active account of 1.099 SOL beside one the
    // CLI called undelegated produced a header claiming 2.107 SOL delegated.
    // Only the three states in which lamports are still committed to a
    // validator count here.
    let total: u64 = entries
        .iter()
        .filter(|e| {
            matches!(
                e.status,
                StakeStatus::Activating | StakeStatus::Active | StakeStatus::Deactivating
            )
        })
        .map(|e| e.state.delegation.as_ref().map_or(0, |d| d.stake_lamports))
        // Saturating, because the lamport values come from the endpoint and the
        // release profile turns overflow checks off, so a wrapped sum would
        // print a small confident number for an absurd input. The neighbouring
        // epoch percentage already widens to u128 against the same threat.
        .fold(0u64, u64::saturating_add);
    let delinquent = entries
        .iter()
        .filter(|e| matches!(e.validator, Some(ValidatorStatus::Delinquent { .. })))
        .count();
    let behind = entries
        .iter()
        .filter(|e| {
            e.validator
                .as_ref()
                .is_some_and(|v| v.is_behind(epoch.absolute_slot, cfg.vote_lag_warn_slots))
        })
        .count();

    // A degraded epoch reply costs the progress figure and says so, rather
    // than printing a percentage nothing supports.
    let epoch_part = match &epoch.progress {
        Some(p) => format!(
            "epoch {} at {}% (~{} h left)",
            epoch.epoch,
            p.pct(),
            p.hours_to_end()
        ),
        None => format!("epoch {} (progress unknown)", epoch.epoch),
    };

    let mut lines = vec![format!(
        "Stake: {} account(s), {} SOL delegated, {epoch_part}.{}{}",
        entries.len(),
        fmt_sol(total),
        if delinquent > 0 {
            format!(" {delinquent} validator(s) DELINQUENT.")
        } else {
            String::new()
        },
        if behind > 0 {
            format!(" {behind} validator(s) BEHIND.")
        } else {
            String::new()
        }
    )];

    for e in entries {
        let mut parts = vec![format!(
            "[{}] {}: {} SOL",
            e.status.as_str(),
            e.label,
            fmt_sol(
                e.state
                    .delegation
                    .as_ref()
                    .map_or(e.state.lamports, |d| d.stake_lamports)
            )
        )];
        if let Some(d) = &e.state.delegation {
            // The voter comes off the RPC reply, so whoever answers `rpc_url`
            // controls these bytes. Four characters cannot carry an
            // instruction, and they can carry a newline: this report is
            // line-structured, so one smuggled break forges a row. Narrowing to
            // the base58 alphabet is the same guard `short_pubkey` applies in
            // lending-health; until 2026-08-03 this site took the four
            // characters raw.
            let voter_short: String = d
                .voter
                .chars()
                .take(4)
                .map(|c| {
                    if c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l') {
                        c
                    } else {
                        '.'
                    }
                })
                .collect();
            let vstat = match &e.validator {
                Some(v @ ValidatorStatus::Ok { commission_bps, .. }) => {
                    format!(
                        "validator {voter_short}.. ok, {}, {}",
                        fmt_vote_lag(v, epoch, cfg.vote_lag_warn_slots),
                        fmt_commission(*commission_bps)
                    )
                }
                Some(v @ ValidatorStatus::Delinquent { .. }) => {
                    format!(
                        "validator {voter_short}.. DELINQUENT, {}",
                        fmt_vote_lag(v, epoch, cfg.vote_lag_warn_slots)
                    )
                }
                // `Unknown` covers two different situations: the roster came
                // back and the vote account was in neither list, or the read
                // failed and there is no roster to speak of. Saying "not found"
                // asserts a fact about the chain in the second case, which the
                // code never established. The wording states the absence of a
                // reading, and the data-issues line carries the reason whenever
                // there was one.
                Some(ValidatorStatus::Unknown) => {
                    format!("validator {voter_short}.. status unknown")
                }
                None => format!("validator {voter_short}.."),
            };
            parts.push(vstat);
        }
        // A reward that was never read is not a reward of zero. The failed-read
        // case used to fall into the same arm as an explicit null and print
        // "no reward last epoch" on every active row, stating as a fact about
        // the epoch something the run never established. The reason for the
        // failure rides the data-issues line, as with every other failed read.
        match &e.reward {
            Some(Some(r)) => parts.push(format!("last reward {} SOL", fmt_sol(r.amount_lamports))),
            Some(None) => {
                if e.status == StakeStatus::Active {
                    parts.push("no reward last epoch".to_string());
                }
            }
            None => {
                if e.status == StakeStatus::Active {
                    parts.push("reward unknown".to_string());
                }
            }
        }
        lines.push(parts.join(", "));
    }

    let mut report = lines.join("\n");
    if report.len() > budget {
        // Room for the marker is reserved at the widest count it could carry,
        // so the truncated report is provably inside the budget.
        let reserve = omitted_lines(lines.len()).len();
        let mut kept = Vec::new();
        let mut used = 0usize;
        for line in &lines {
            if used + line.len() + 1 > budget.saturating_sub(reserve) {
                break;
            }
            used += line.len() + 1;
            kept.push(line.clone());
        }
        let omitted = lines.len() - kept.len();
        kept.push(omitted_lines(omitted));
        report = kept.join("\n");
    }
    report
}
