//! Pure sports-settlement receipt core. This module has no WIT or WASI
//! dependency, so proof parsing, Borsh encoding, PDA derivation, predicate
//! evaluation, configuration gates, and receipt hashing run in host tests.

use std::collections::HashMap;
use std::fmt;

use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

pub const PROGRAM_ID: &str = "6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J";
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
pub const DEFAULT_TXLINE_BASE_URL: &str = "https://txline-dev.txodds.com";
pub const VALIDATE_STAT_PATH: &str = "/api/scores/stat-validation";
pub const COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
pub const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024;
pub const MAX_PROOF_NODES_PER_VECTOR: usize = 64;
pub const MAX_TOTAL_PROOF_NODES: usize = 192;
pub const VALIDATE_STAT_DISCRIMINATOR: [u8; 8] = [107, 197, 232, 90, 191, 136, 105, 185];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreError(pub &'static str);

impl CoreError {
    pub fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CoreError {}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecuteArgs {
    pub fixture_id: u64,
    pub sequence: u64,
    pub market: MarketInput,
    pub attestation_signature: String,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MarketInput {
    MatchWinner { selection: MatchSelection },
    TotalGoals { side: TotalGoalsSide, line_x2: i32 },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchSelection {
    Home,
    Draw,
    Away,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TotalGoalsSide {
    Over,
    Under,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginConfig {
    pub txline_base_url: String,
    pub txline_api_token: String,
    pub txline_session_jwt: String,
    pub rpc_urls: Vec<String>,
}

impl PluginConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, CoreError> {
        const ALLOWED: [&str; 6] = [
            "txline_base_url",
            "txline_api_token",
            "txline_session_jwt",
            "rpc_url_1",
            "rpc_url_2",
            "rpc_url_3",
        ];
        if section.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
            return Err(CoreError("INVALID_CONFIG_KEY"));
        }

        let required = |key: &'static str| {
            section
                .get(key)
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or(CoreError("MISSING_CONFIG"))
        };
        let txline_base_url = section
            .get("txline_base_url")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_TXLINE_BASE_URL)
            .to_string();
        validate_txline_base_url(&txline_base_url)?;
        let mut rpc_urls = vec![required("rpc_url_1")?, required("rpc_url_2")?];
        if let Some(value) = section
            .get("rpc_url_3")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            rpc_urls.push(value.to_string());
        }
        let mut provider_hosts = Vec::with_capacity(rpc_urls.len());
        for rpc_url in &rpc_urls {
            validate_rpc_url(rpc_url)?;
            let parsed = Url::parse(rpc_url).map_err(|_| CoreError("INVALID_RPC_URL"))?;
            let host = parsed
                .host_str()
                .ok_or(CoreError("INVALID_RPC_URL"))?
                .to_ascii_lowercase();
            if provider_hosts.contains(&host) {
                return Err(CoreError("DUPLICATE_RPC_PROVIDER"));
            }
            provider_hosts.push(host);
        }

        Ok(Self {
            txline_base_url,
            txline_api_token: required("txline_api_token")?,
            txline_session_jwt: required("txline_session_jwt")?,
            rpc_urls,
        })
    }
}

pub fn parse_execute_args(input: &str) -> Result<ExecuteArgs, CoreError> {
    let args: ExecuteArgs =
        serde_json::from_str(input).map_err(|_| CoreError("INVALID_EXECUTE_ARGS"))?;
    if args.fixture_id == 0 || args.fixture_id > i64::MAX as u64 {
        return Err(CoreError("INVALID_FIXTURE_ID"));
    }
    if args.sequence == 0 || args.sequence > i64::MAX as u64 {
        return Err(CoreError("INVALID_SEQUENCE"));
    }
    compile_market(&args.market)?;
    validate_attestation_signature(&args.attestation_signature)?;
    Ok(args)
}

pub fn validate_attestation_signature(signature: &str) -> Result<(), CoreError> {
    if !(64..=88).contains(&signature.len())
        || !signature.is_ascii()
        || signature.trim() != signature
    {
        return Err(CoreError("INVALID_TRANSACTION_SIGNATURE"));
    }
    let decoded = bs58::decode(signature)
        .into_vec()
        .map_err(|_| CoreError("INVALID_TRANSACTION_SIGNATURE"))?;
    if decoded.len() != 64 {
        return Err(CoreError("INVALID_TRANSACTION_SIGNATURE"));
    }
    Ok(())
}

pub fn parameters_schema() -> String {
    json!({
        "type": "object",
        "properties": {
            "fixture_id": {
                "type": "integer",
                "minimum": 1,
                "description": "TxLINE soccer fixture ID."
            },
            "sequence": {
                "type": "integer",
                "minimum": 1,
                "description": "Observed game_finalised score sequence (statusId=100, period=100)."
            },
            "market": {
                "oneOf": [
                    {
                        "type": "object",
                        "properties": {
                            "kind": {"const": "match_winner"},
                            "selection": {"enum": ["home", "draw", "away"]}
                        },
                        "required": ["kind", "selection"],
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "properties": {
                            "kind": {"const": "total_goals"},
                            "side": {"enum": ["over", "under"]},
                            "line_x2": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 25,
                                "description": "Half-goal line multiplied by two; odd values only (5 means 2.5)."
                            }
                        },
                        "required": ["kind", "side", "line_x2"],
                        "additionalProperties": false
                    }
                ]
            },
            "attestation_signature": {
                "type": "string",
                "minLength": 64,
                "maxLength": 88,
                "pattern": "^[1-9A-HJ-NP-Za-km-z]+$",
                "description": "Existing Solana transaction signature for the finalized SettleTrace attestation."
            }
        },
        "required": ["fixture_id", "sequence", "market", "attestation_signature"],
        "additionalProperties": false
    })
    .to_string()
}

pub fn validate_txline_base_url(endpoint: &str) -> Result<(), CoreError> {
    let url = Url::parse(endpoint).map_err(|_| CoreError("INVALID_TXLINE_URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || (url.path() != "/" && !url.path().is_empty())
    {
        return Err(CoreError("INVALID_TXLINE_URL"));
    }
    Ok(())
}

pub fn validate_rpc_url(endpoint: &str) -> Result<(), CoreError> {
    let url = Url::parse(endpoint).map_err(|_| CoreError("INVALID_RPC_URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(CoreError("INVALID_RPC_URL"));
    }
    if let Some(query) = url.query() {
        let pairs: Vec<_> = url.query_pairs().collect();
        if pairs.len() != 1
            || pairs[0].0 != "api-key"
            || pairs[0].1.is_empty()
            || !pairs[0]
                .1
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            || query.len() > 256
        {
            return Err(CoreError("INVALID_RPC_URL"));
        }
    }
    Ok(())
}

pub fn stat_validation_url(
    base: &str,
    fixture_id: u64,
    sequence: u64,
) -> Result<String, CoreError> {
    validate_txline_base_url(base)?;
    if fixture_id == 0 || sequence == 0 {
        return Err(CoreError("INVALID_REQUEST_ID"));
    }
    let mut url = Url::parse(base).map_err(|_| CoreError("INVALID_TXLINE_URL"))?;
    url.set_path(VALIDATE_STAT_PATH);
    url.query_pairs_mut()
        .append_pair("fixtureId", &fixture_id.to_string())
        .append_pair("seq", &sequence.to_string())
        .append_pair("statKey", "1")
        .append_pair("statKey2", "2");
    Ok(url.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    GreaterThan = 0,
    LessThan = 1,
    EqualTo = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryExpression {
    Add = 0,
    Subtract = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledMarket {
    pub threshold: i32,
    pub comparison: Comparison,
    pub operation: BinaryExpression,
    pub description: String,
    pub compact: String,
    pub public_value: Value,
}

pub fn compile_market(market: &MarketInput) -> Result<CompiledMarket, CoreError> {
    match market {
        MarketInput::MatchWinner { selection } => {
            let (comparison, symbol) = match selection {
                MatchSelection::Home => (Comparison::GreaterThan, ">"),
                MatchSelection::Draw => (Comparison::EqualTo, "="),
                MatchSelection::Away => (Comparison::LessThan, "<"),
            };
            Ok(CompiledMarket {
                threshold: 0,
                comparison,
                operation: BinaryExpression::Subtract,
                description: format!("stat[1] - stat[2] {symbol} 0"),
                compact: format!("stat[1]-stat[2]{symbol}0"),
                public_value: serde_json::to_value(market)
                    .map_err(|_| CoreError("MARKET_SERIALIZATION_ERROR"))?,
            })
        }
        MarketInput::TotalGoals { side, line_x2 } => {
            if !(1..=25).contains(line_x2) || line_x2 % 2 == 0 {
                return Err(CoreError("INVALID_HALF_GOAL_LINE"));
            }
            let floor = line_x2 / 2;
            let (threshold, comparison, symbol) = match side {
                TotalGoalsSide::Over => (floor, Comparison::GreaterThan, ">"),
                TotalGoalsSide::Under => (floor + 1, Comparison::LessThan, "<"),
            };
            Ok(CompiledMarket {
                threshold,
                comparison,
                operation: BinaryExpression::Add,
                description: format!("stat[1] + stat[2] {symbol} {threshold}"),
                compact: format!("stat[1]+stat[2]{symbol}{threshold}"),
                public_value: serde_json::to_value(market)
                    .map_err(|_| CoreError("MARKET_SERIALIZATION_ERROR"))?,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofNode {
    pub hash: [u8; 32],
    pub is_right_sibling: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScoreStat {
    pub key: u32,
    pub value: i32,
    pub period: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateStats {
    pub update_count: i32,
    pub min_timestamp: i64,
    pub max_timestamp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProof {
    pub fixture_id: i64,
    pub update_stats: UpdateStats,
    pub events_sub_tree_root: [u8; 32],
    pub fixture_proof: Vec<ProofNode>,
    pub main_tree_proof: Vec<ProofNode>,
    pub stat_a: ScoreStat,
    pub stat_b: ScoreStat,
    pub event_stat_root: [u8; 32],
    pub stat_a_proof: Vec<ProofNode>,
    pub stat_b_proof: Vec<ProofNode>,
    pub payload_sha256: String,
    pub tree_nodes: usize,
}

pub fn parse_stat_validation_response(
    body: &str,
    expected_fixture_id: u64,
) -> Result<ParsedProof, CoreError> {
    if body.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(CoreError("RESPONSE_TOO_LARGE"));
    }
    let value: Value =
        serde_json::from_str(body).map_err(|_| CoreError("MALFORMED_PROOF_RESPONSE"))?;
    let root = object(&value, "MALFORMED_PROOF_RESPONSE")?;
    let summary = object(
        root.get("summary")
            .ok_or(CoreError("MISSING_PROOF_SUMMARY"))?,
        "MALFORMED_PROOF_SUMMARY",
    )?;
    let fixture_id = integer(summary.get("fixtureId"), "INVALID_PROOF_FIXTURE")?;
    if fixture_id < 1 || fixture_id as u64 != expected_fixture_id {
        return Err(CoreError("PROOF_FIXTURE_MISMATCH"));
    }
    let update = object(
        summary
            .get("updateStats")
            .ok_or(CoreError("MISSING_UPDATE_STATS"))?,
        "MALFORMED_UPDATE_STATS",
    )?;
    let update_count = i32_value(update.get("updateCount"), "INVALID_UPDATE_COUNT")?;
    let min_timestamp = integer(update.get("minTimestamp"), "INVALID_PROOF_TIMESTAMP")?;
    let max_timestamp = integer(update.get("maxTimestamp"), "INVALID_PROOF_TIMESTAMP")?;
    if update_count < 1 || min_timestamp < 1 || max_timestamp < min_timestamp {
        return Err(CoreError("INVALID_UPDATE_STATS"));
    }
    let epoch_day = min_timestamp / 86_400_000;
    if !(0..=u16::MAX as i64).contains(&epoch_day) {
        return Err(CoreError("INVALID_PROOF_EPOCH_DAY"));
    }

    let events_sub_tree_root = bytes32(
        summary.get("eventStatsSubTreeRoot"),
        "INVALID_EVENTS_SUB_TREE_ROOT",
    )?;
    let fixture_proof = proof_nodes(root.get("subTreeProof"), "INVALID_FIXTURE_PROOF")?;
    let main_tree_proof = proof_nodes(root.get("mainTreeProof"), "INVALID_MAIN_TREE_PROOF")?;
    let stat_a = score_stat(root.get("statToProve"), "INVALID_FIRST_STAT")?;
    let stat_b = score_stat(root.get("statToProve2"), "INVALID_SECOND_STAT")?;
    if stat_a.key != 1 || stat_b.key != 2 {
        return Err(CoreError("STAT_KEY_MISMATCH"));
    }
    if stat_a.value < 0 || stat_b.value < 0 || stat_a.value > 100 || stat_b.value > 100 {
        return Err(CoreError("INVALID_SCORE_VALUE"));
    }
    if stat_a.period != 100 || stat_b.period != 100 {
        return Err(CoreError("PERIOD_NOT_FINAL"));
    }
    let event_stat_root = bytes32(root.get("eventStatRoot"), "INVALID_EVENT_STAT_ROOT")?;
    let stat_a_proof = proof_nodes(root.get("statProof"), "INVALID_FIRST_STAT_PROOF")?;
    let stat_b_proof = proof_nodes(root.get("statProof2"), "INVALID_SECOND_STAT_PROOF")?;
    let tree_nodes = fixture_proof
        .len()
        .checked_add(main_tree_proof.len())
        .and_then(|value| value.checked_add(stat_a_proof.len()))
        .and_then(|value| value.checked_add(stat_b_proof.len()))
        .ok_or(CoreError("PROOF_TOO_LARGE"))?;
    if tree_nodes > MAX_TOTAL_PROOF_NODES {
        return Err(CoreError("PROOF_TOO_LARGE"));
    }
    let payload_sha256 = hash_canonical_json(&value)?;

    Ok(ParsedProof {
        fixture_id,
        update_stats: UpdateStats {
            update_count,
            min_timestamp,
            max_timestamp,
        },
        events_sub_tree_root,
        fixture_proof,
        main_tree_proof,
        stat_a,
        stat_b,
        event_stat_root,
        stat_a_proof,
        stat_b_proof,
        payload_sha256,
        tree_nodes,
    })
}

fn object<'a>(
    value: &'a Value,
    code: &'static str,
) -> Result<&'a serde_json::Map<String, Value>, CoreError> {
    value.as_object().ok_or(CoreError(code))
}

fn integer(value: Option<&Value>, code: &'static str) -> Result<i64, CoreError> {
    value.and_then(Value::as_i64).ok_or(CoreError(code))
}

fn i32_value(value: Option<&Value>, code: &'static str) -> Result<i32, CoreError> {
    i32::try_from(integer(value, code)?).map_err(|_| CoreError(code))
}

fn u32_value(value: Option<&Value>, code: &'static str) -> Result<u32, CoreError> {
    u32::try_from(integer(value, code)?).map_err(|_| CoreError(code))
}

fn bytes32(value: Option<&Value>, code: &'static str) -> Result<[u8; 32], CoreError> {
    let array = value.and_then(Value::as_array).ok_or(CoreError(code))?;
    if array.len() != 32 {
        return Err(CoreError(code));
    }
    let mut out = [0u8; 32];
    for (index, item) in array.iter().enumerate() {
        let byte = item
            .as_u64()
            .filter(|byte| *byte <= 255)
            .ok_or(CoreError(code))?;
        out[index] = byte as u8;
    }
    Ok(out)
}

fn proof_nodes(value: Option<&Value>, code: &'static str) -> Result<Vec<ProofNode>, CoreError> {
    let array = value.and_then(Value::as_array).ok_or(CoreError(code))?;
    if array.len() > MAX_PROOF_NODES_PER_VECTOR {
        return Err(CoreError("PROOF_TOO_LARGE"));
    }
    array
        .iter()
        .map(|entry| {
            let node = object(entry, code)?;
            let hash = bytes32(node.get("hash"), code)?;
            let is_right_sibling = node
                .get("isRightSibling")
                .and_then(Value::as_bool)
                .ok_or(CoreError(code))?;
            Ok(ProofNode {
                hash,
                is_right_sibling,
            })
        })
        .collect()
}

fn score_stat(value: Option<&Value>, code: &'static str) -> Result<ScoreStat, CoreError> {
    let stat = object(value.ok_or(CoreError(code))?, code)?;
    Ok(ScoreStat {
        key: u32_value(stat.get("key"), code)?,
        value: i32_value(stat.get("value"), code)?,
        period: i32_value(stat.get("period"), code)?,
    })
}

pub fn build_validate_stat_instruction(
    proof: &ParsedProof,
    market: &CompiledMarket,
) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::with_capacity(768);
    out.extend_from_slice(&VALIDATE_STAT_DISCRIMINATOR);
    put_i64(&mut out, proof.update_stats.min_timestamp);
    put_i64(&mut out, proof.fixture_id);
    put_i32(&mut out, proof.update_stats.update_count);
    put_i64(&mut out, proof.update_stats.min_timestamp);
    put_i64(&mut out, proof.update_stats.max_timestamp);
    out.extend_from_slice(&proof.events_sub_tree_root);
    put_proof_nodes(&mut out, &proof.fixture_proof)?;
    put_proof_nodes(&mut out, &proof.main_tree_proof)?;
    put_i32(&mut out, market.threshold);
    out.push(market.comparison as u8);
    put_stat_term(
        &mut out,
        &proof.stat_a,
        &proof.event_stat_root,
        &proof.stat_a_proof,
    )?;
    out.push(1); // Option<StatTerm>::Some
    put_stat_term(
        &mut out,
        &proof.stat_b,
        &proof.event_stat_root,
        &proof.stat_b_proof,
    )?;
    out.push(1); // Option<BinaryExpression>::Some
    out.push(market.operation as u8);
    if out.len() > 1024 {
        return Err(CoreError("INSTRUCTION_TOO_LARGE"));
    }
    Ok(out)
}

fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_proof_nodes(out: &mut Vec<u8>, nodes: &[ProofNode]) -> Result<(), CoreError> {
    let len = u32::try_from(nodes.len()).map_err(|_| CoreError("PROOF_TOO_LARGE"))?;
    put_u32(out, len);
    for node in nodes {
        out.extend_from_slice(&node.hash);
        out.push(u8::from(node.is_right_sibling));
    }
    Ok(())
}

fn put_stat_term(
    out: &mut Vec<u8>,
    stat: &ScoreStat,
    root: &[u8; 32],
    proof: &[ProofNode],
) -> Result<(), CoreError> {
    put_u32(out, stat.key);
    put_i32(out, stat.value);
    put_i32(out, stat.period);
    out.extend_from_slice(root);
    put_proof_nodes(out, proof)
}

pub fn derive_daily_scores_pda(min_timestamp: i64) -> Result<([u8; 32], u8), CoreError> {
    if min_timestamp < 1 {
        return Err(CoreError("INVALID_PROOF_TIMESTAMP"));
    }
    let epoch_day = min_timestamp / 86_400_000;
    let epoch_day = u16::try_from(epoch_day).map_err(|_| CoreError("INVALID_PROOF_EPOCH_DAY"))?;
    let program_id = decode_pubkey(PROGRAM_ID).map_err(|_| CoreError("INVALID_PROGRAM_ID"))?;
    let day = epoch_day.to_le_bytes();
    for bump in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        hasher.update(b"daily_scores_roots");
        hasher.update(day);
        hasher.update([bump]);
        hasher.update(program_id);
        hasher.update(b"ProgramDerivedAddress");
        let candidate: [u8; 32] = hasher.finalize().into();
        if CompressedEdwardsY(candidate).decompress().is_none() {
            return Ok((candidate, bump));
        }
    }
    Err(CoreError("PDA_DERIVATION_FAILED"))
}

pub fn decode_pubkey(value: &str) -> Result<[u8; 32], CoreError> {
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|_| CoreError("INVALID_PUBLIC_KEY"))?;
    bytes
        .try_into()
        .map_err(|_| CoreError("INVALID_PUBLIC_KEY"))
}

pub fn encode_pubkey(value: &[u8; 32]) -> String {
    bs58::encode(value).into_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPlan {
    pub daily_scores_pda: String,
    pub daily_scores_pda_bytes: [u8; 32],
    pub pda_bump: u8,
    pub instruction: Vec<u8>,
    pub instruction_sha256: String,
    pub instruction_len: usize,
    pub predicate_result: bool,
    pub predicate_compact: String,
}

pub fn build_attestation_plan(
    proof: &ParsedProof,
    market: &CompiledMarket,
) -> Result<AttestationPlan, CoreError> {
    let (daily_pda, pda_bump) = derive_daily_scores_pda(proof.update_stats.min_timestamp)?;
    let instruction = build_validate_stat_instruction(proof, market)?;
    let instruction_sha256 = sha256_hex(&instruction);
    let predicate_result = evaluate_market(market, proof.stat_a.value, proof.stat_b.value)?;

    Ok(AttestationPlan {
        daily_scores_pda: encode_pubkey(&daily_pda),
        daily_scores_pda_bytes: daily_pda,
        pda_bump,
        instruction_len: instruction.len(),
        instruction,
        instruction_sha256,
        predicate_result,
        predicate_compact: market.compact.clone(),
    })
}

pub fn evaluate_market(
    market: &CompiledMarket,
    home_goals: i32,
    away_goals: i32,
) -> Result<bool, CoreError> {
    if !(0..=100).contains(&home_goals) || !(0..=100).contains(&away_goals) {
        return Err(CoreError("INVALID_SCORE_VALUE"));
    }
    let value = match market.operation {
        BinaryExpression::Add => home_goals
            .checked_add(away_goals)
            .ok_or(CoreError("SCORE_ARITHMETIC_OVERFLOW"))?,
        BinaryExpression::Subtract => home_goals
            .checked_sub(away_goals)
            .ok_or(CoreError("SCORE_ARITHMETIC_OVERFLOW"))?,
    };
    Ok(match market.comparison {
        Comparison::GreaterThan => value > market.threshold,
        Comparison::LessThan => value < market.threshold,
        Comparison::EqualTo => value == market.threshold,
    })
}

pub struct VerifiedAttestation<'a> {
    pub signature: &'a str,
    pub finalized_slot: u64,
    pub transaction_sha256: &'a str,
    pub memo_receipt_sha256: &'a str,
    pub quorum: &'a Value,
}

pub fn verified_report(
    fixture_id: u64,
    sequence: u64,
    proof: &ParsedProof,
    market: &CompiledMarket,
    plan: &AttestationPlan,
    attestation: &VerifiedAttestation<'_>,
) -> Result<String, CoreError> {
    let outcome = if plan.predicate_result { "win" } else { "lose" };
    let predicate_reason = if plan.predicate_result {
        "PREDICATE_MATCHED"
    } else {
        "PREDICATE_NOT_MATCHED"
    };
    let receipt_body = json!({
        "version": "sports-settlement-receipt-v1",
        "fixture_id": fixture_id,
        "sequence": sequence,
        "market": market.public_value,
        "score": {
            "home": proof.stat_a.value,
            "away": proof.stat_b.value,
            "period": 100
        },
        "predicate_result": plan.predicate_result,
        "outcome": outcome,
        "proof_payload_sha256": proof.payload_sha256,
        "instruction_sha256": plan.instruction_sha256,
        "daily_scores_pda": plan.daily_scores_pda,
        "attestation_signature": attestation.signature,
        "finalized_slot": attestation.finalized_slot,
        "transaction_sha256": attestation.transaction_sha256,
        "memo_receipt_sha256": attestation.memo_receipt_sha256
    });
    let receipt_sha256 = hash_canonical_json(&receipt_body)?;
    let report = json!({
        "version": "sports-settlement-receipt-v1",
        "verdict": "verified",
        "settlement_ready": true,
        "fixture_id": fixture_id,
        "sequence": sequence,
        "market": market.public_value,
        "predicate": market.description,
        "outcome": outcome,
        "score": {
            "home": proof.stat_a.value,
            "away": proof.stat_b.value,
            "period": 100
        },
        "proof": {
            "stat_keys": [1, 2],
            "proof_timestamp": proof.update_stats.min_timestamp,
            "tree_nodes": proof.tree_nodes,
            "payload_sha256": proof.payload_sha256
        },
        "onchain": {
            "network": "solana-devnet",
            "program_id": PROGRAM_ID,
            "daily_scores_pda": plan.daily_scores_pda,
            "pda_bump": plan.pda_bump,
            "instruction_bytes": plan.instruction_len,
            "instruction_sha256": plan.instruction_sha256,
            "attestation_signature": attestation.signature,
            "finalized_slot": attestation.finalized_slot,
            "transaction_sha256": attestation.transaction_sha256,
            "memo_receipt_sha256": attestation.memo_receipt_sha256,
            "predicate_result": plan.predicate_result,
            "attestation_transaction_finalized": true,
            "transaction_submitted_by_plugin": false
        },
        "quorum": attestation.quorum,
        "receipt": {
            "hash_algorithm": "SHA-256",
            "canonicalization": "recursive-key-sort-v1",
            "receipt_sha256": receipt_sha256,
            "body": receipt_body
        },
        "reason_codes": [
            "FIXTURE_BOUND",
            "SEQUENCE_BOUND_TO_REQUEST",
            "STAT_KEYS_BOUND",
            "PERIOD_100_CONFIRMED",
            "FINALIZED_ATTESTATION_BOUND",
            "TWO_PROVIDER_QUORUM_REACHED",
            predicate_reason
        ],
        "limitations": [
            "TXLINE_AND_RPC_PROVIDERS_REMAIN_TRUST_BOUNDARIES",
            "SEQUENCE_IS_BOUND_BY_THE_AUTHENTICATED_REQUEST_PATH",
            "ACTION_AND_STATUS_ID_ARE_NOT_ECHOED_BY_STAT_VALIDATION",
            "PLUGIN_DID_NOT_SUBMIT_THE_ATTESTATION_TRANSACTION",
            "NOT_A_BET_OR_PAYOUT"
        ]
    });
    let serialized =
        serde_json::to_string(&report).map_err(|_| CoreError("OUTPUT_SERIALIZATION_ERROR"))?;
    if serialized.len() > MAX_OUTPUT_BYTES {
        return Err(CoreError("OUTPUT_TOO_LARGE"));
    }
    Ok(serialized)
}

pub fn unknown_report(code: &str, fixture_id: Option<u64>, sequence: Option<u64>) -> String {
    json!({
        "version": "sports-settlement-receipt-v1",
        "verdict": "unknown",
        "settlement_ready": false,
        "fixture_id": fixture_id,
        "sequence": sequence,
        "reason_codes": [code],
        "transaction_submitted_by_plugin": false
    })
    .to_string()
}

pub fn hash_canonical_json(value: &Value) -> Result<String, CoreError> {
    let mut out = String::new();
    write_canonical_json(value, &mut out)?;
    Ok(sha256_hex(out.as_bytes()))
}

fn write_canonical_json(value: &Value, out: &mut String) -> Result<(), CoreError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(value) => out.push_str(
            &serde_json::to_string(value).map_err(|_| CoreError("CANONICAL_JSON_ERROR"))?,
        ),
        Value::Array(values) => {
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                write_canonical_json(value, out)?;
            }
            out.push(']');
        }
        Value::Object(values) => {
            out.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(key).map_err(|_| CoreError("CANONICAL_JSON_ERROR"))?,
                );
                out.push(':');
                write_canonical_json(&values[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(bytes.as_ref());
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
