//! Fail-closed transaction policy engine.
//!
//! The caller supplies only serialized transaction bytes. Security policy is
//! read from the operator-owned ZeroClaw config section, never from the model's
//! arguments. The engine proves a narrow payment-safe instruction set and
//! denies everything it cannot fully explain.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::programs::{
    analyze_instructions, Operation, ASSOCIATED_TOKEN_PROGRAM, COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM, MEMO_V1_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
};
use crate::rpc::RpcClient;
use crate::transaction::{parse_transaction, ParsedTransaction};

const MAX_VIOLATIONS: usize = 6;
const MAX_RETURNED_TRANSFERS: usize = 3;

#[derive(Clone, Debug, Serialize)]
pub struct Policy {
    pub allowed_fee_payers: BTreeSet<String>,
    pub allowed_signers: BTreeSet<String>,
    pub allowed_programs: BTreeSet<String>,
    pub allowed_recipients: BTreeSet<String>,
    pub allowed_mints: BTreeSet<String>,
    pub max_sol_lamports: u64,
    pub max_token_amounts: BTreeMap<String, u64>,
    pub max_priority_fee_lamports: u64,
    pub max_instructions: usize,
    pub max_writable_accounts: usize,
    pub allow_ata_creation: bool,
    pub require_unsigned: bool,
    pub require_simulation: bool,
    pub require_value_transfer: bool,
}

impl Policy {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        const KEYS: [&str; 14] = [
            "rpc_url",
            "allowed_fee_payers",
            "allowed_signers",
            "allowed_programs",
            "allowed_recipients",
            "allowed_mints",
            "max_sol_lamports",
            "max_token_amounts",
            "max_priority_fee_lamports",
            "max_instructions",
            "max_writable_accounts",
            "allow_ata_creation",
            "require_unsigned",
            "require_simulation",
        ];
        const OPTIONAL_EXTRA_KEY: &str = "require_value_transfer";

        let unknown = section
            .keys()
            .filter(|key| !KEYS.contains(&key.as_str()) && key.as_str() != OPTIONAL_EXTRA_KEY)
            .cloned()
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            return Err(format!(
                "unknown policy keys: {}; refusing ambiguous configuration",
                unknown.join(", ")
            ));
        }
        let rpc_url = section
            .get("rpc_url")
            .map(|value| value.trim())
            .unwrap_or_default();
        if rpc_url.is_empty() {
            return Err("rpc_url is required".to_string());
        }
        if !rpc_url.starts_with("https://") {
            return Err("rpc_url must use https".to_string());
        }

        let allowed_fee_payers = parse_pubkey_set(section, "allowed_fee_payers", true)?;
        let allowed_signers = match section.get("allowed_signers") {
            Some(_) => parse_pubkey_set(section, "allowed_signers", true)?,
            None => allowed_fee_payers.clone(),
        };
        let allowed_programs = parse_program_set(section)?;
        let allowed_recipients = parse_pubkey_set(section, "allowed_recipients", true)?;
        let allowed_mints = parse_pubkey_set(section, "allowed_mints", false)?;
        let max_token_amounts = parse_token_limits(section.get("max_token_amounts"))?;

        for mint in max_token_amounts.keys() {
            if !allowed_mints.contains(mint) {
                return Err(format!(
                    "max_token_amounts contains mint {mint} which is not in allowed_mints"
                ));
            }
        }

        Ok(Self {
            allowed_fee_payers,
            allowed_signers,
            allowed_programs,
            allowed_recipients,
            allowed_mints,
            max_sol_lamports: parse_u64(section, "max_sol_lamports", 0)?,
            max_token_amounts,
            max_priority_fee_lamports: parse_u64(section, "max_priority_fee_lamports", 0)?,
            max_instructions: parse_usize(section, "max_instructions", 8, 64)?,
            max_writable_accounts: parse_usize(section, "max_writable_accounts", 8, 64)?,
            allow_ata_creation: parse_bool(section, "allow_ata_creation", false)?,
            require_unsigned: parse_bool(section, "require_unsigned", true)?,
            require_simulation: parse_bool(section, "require_simulation", true)?,
            require_value_transfer: parse_bool(section, "require_value_transfer", true)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Violation {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TransferReceipt {
    pub asset: String,
    pub amount_raw: String,
    pub recipient: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SimulationReceipt {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units_consumed: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DecisionReceipt {
    pub verdict: String,
    pub risk: String,
    pub transaction_hash: String,
    pub policy_hash: String,
    pub receipt_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<String>,
    pub instructions: usize,
    pub writable_accounts: usize,
    pub summary: String,
    pub transfers: Vec<TransferReceipt>,
    pub simulation: SimulationReceipt,
    pub violations: Vec<Violation>,
}

impl DecisionReceipt {
    pub fn allowed(&self) -> bool {
        self.verdict == "ALLOW"
    }
}

pub fn evaluate(
    transaction_base64: &str,
    section: &HashMap<String, String>,
    rpc: &mut dyn RpcClient,
) -> DecisionReceipt {
    let transaction_bytes =
        match base64::engine::general_purpose::STANDARD.decode(transaction_base64.trim()) {
            Ok(bytes) => bytes,
            Err(error) => {
                return unparsed_denial(
                    hash_bytes(transaction_base64.as_bytes()),
                    "invalid_base64",
                    &format!("transaction_base64 could not be decoded: {error}"),
                )
            }
        };
    let transaction_hash = hash_bytes(&transaction_bytes);
    let policy = match Policy::from_section(section) {
        Ok(policy) => policy,
        Err(error) => {
            return unparsed_denial(transaction_hash, "invalid_policy_configuration", &error)
        }
    };
    let policy_hash = hash_json(&policy);
    let parsed = match parse_transaction(&transaction_bytes, rpc) {
        Ok(transaction) => transaction,
        Err(error) => {
            return denial_for_parse(transaction_hash, policy_hash, &error);
        }
    };

    evaluate_parsed(
        transaction_base64,
        transaction_hash,
        policy_hash,
        parsed,
        &policy,
        rpc,
    )
}

fn evaluate_parsed(
    transaction_base64: &str,
    transaction_hash: String,
    policy_hash: String,
    transaction: ParsedTransaction,
    policy: &Policy,
    rpc: &mut dyn RpcClient,
) -> DecisionReceipt {
    let mut violations = Vec::new();

    if policy.require_unsigned && transaction.nonzero_signatures > 0 {
        add_violation(
            &mut violations,
            "transaction_already_signed",
            "pre-sign policy requires every signature slot to be zero",
        );
    }
    if !policy.allowed_fee_payers.contains(&transaction.fee_payer) {
        add_violation(
            &mut violations,
            "fee_payer_not_allowed",
            &format!(
                "fee payer {} is not operator-approved",
                transaction.fee_payer
            ),
        );
    }
    for signer in &transaction.signers {
        if !policy.allowed_signers.contains(signer) {
            add_violation(
                &mut violations,
                "signer_not_allowed",
                &format!("required signer {signer} is not operator-approved"),
            );
        }
    }
    if transaction.instructions.len() > policy.max_instructions {
        add_violation(
            &mut violations,
            "instruction_limit_exceeded",
            &format!(
                "{} instructions exceed policy maximum {}",
                transaction.instructions.len(),
                policy.max_instructions
            ),
        );
    }
    if transaction.writable_account_count() > policy.max_writable_accounts {
        add_violation(
            &mut violations,
            "writable_account_limit_exceeded",
            &format!(
                "{} writable accounts exceed policy maximum {}",
                transaction.writable_account_count(),
                policy.max_writable_accounts
            ),
        );
    }
    for instruction in &transaction.instructions {
        if !policy.allowed_programs.contains(&instruction.program_id) {
            add_violation(
                &mut violations,
                "program_not_allowed",
                &format!(
                    "program {} is not operator-approved",
                    instruction.program_id
                ),
            );
        }
    }

    let operations = match analyze_instructions(&transaction, rpc) {
        Ok(operations) => operations,
        Err(error) => {
            add_violation(&mut violations, "instruction_analysis_failed", &error);
            Vec::new()
        }
    };

    let mut sol_total = 0u64;
    let mut token_totals = BTreeMap::<String, u64>::new();
    let mut transfers = Vec::new();
    let mut transfer_count = 0usize;
    let mut compute_unit_limit = None;
    let mut compute_unit_price = None;

    for operation in operations {
        match operation {
            Operation::SolTransfer {
                source,
                recipient,
                lamports,
            } => {
                transfer_count += 1;
                if !transaction.signers.contains(&source) {
                    add_violation(
                        &mut violations,
                        "transfer_source_not_signer",
                        &format!("SOL source {source} is not a required signer"),
                    );
                }
                if !policy.allowed_recipients.contains(&recipient) {
                    add_violation(
                        &mut violations,
                        "recipient_not_allowed",
                        &format!("SOL recipient {recipient} is not operator-approved"),
                    );
                }
                match sol_total.checked_add(lamports) {
                    Some(total) => sol_total = total,
                    None => add_violation(
                        &mut violations,
                        "amount_overflow",
                        "aggregate SOL amount overflowed u64",
                    ),
                }
                push_transfer(
                    &mut transfers,
                    TransferReceipt {
                        asset: "SOL".to_string(),
                        amount_raw: lamports.to_string(),
                        recipient,
                    },
                );
            }
            Operation::TokenTransfer {
                recipient_owner,
                authority,
                mint,
                amount,
                ..
            } => {
                transfer_count += 1;
                if !transaction.signers.contains(&authority) {
                    add_violation(
                        &mut violations,
                        "token_authority_not_signer",
                        &format!("token authority {authority} is not a required signer"),
                    );
                }
                if !policy.allowed_recipients.contains(&recipient_owner) {
                    add_violation(
                        &mut violations,
                        "recipient_not_allowed",
                        &format!(
                            "token destination owner {recipient_owner} is not operator-approved"
                        ),
                    );
                }
                if !policy.allowed_mints.contains(&mint) {
                    add_violation(
                        &mut violations,
                        "mint_not_allowed",
                        &format!("token mint {mint} is not operator-approved"),
                    );
                }
                let total = token_totals.entry(mint.clone()).or_default();
                match total.checked_add(amount) {
                    Some(value) => *total = value,
                    None => add_violation(
                        &mut violations,
                        "amount_overflow",
                        "aggregate token amount overflowed u64",
                    ),
                }
                push_transfer(
                    &mut transfers,
                    TransferReceipt {
                        asset: mint,
                        amount_raw: amount.to_string(),
                        recipient: recipient_owner,
                    },
                );
            }
            Operation::CreateAssociatedTokenAccount {
                recipient_owner,
                mint,
                ..
            } => {
                if !policy.allow_ata_creation {
                    add_violation(
                        &mut violations,
                        "ata_creation_not_allowed",
                        "associated token account creation is disabled by policy",
                    );
                }
                if !policy.allowed_recipients.contains(&recipient_owner) {
                    add_violation(
                        &mut violations,
                        "ata_owner_not_allowed",
                        &format!("ATA owner {recipient_owner} is not operator-approved"),
                    );
                }
                if !policy.allowed_mints.contains(&mint) {
                    add_violation(
                        &mut violations,
                        "ata_mint_not_allowed",
                        &format!("ATA mint {mint} is not operator-approved"),
                    );
                }
            }
            Operation::ComputeUnitLimit(limit) => {
                if compute_unit_limit.replace(limit).is_some() {
                    add_violation(
                        &mut violations,
                        "duplicate_compute_unit_limit",
                        "multiple compute unit limit instructions are ambiguous",
                    );
                }
            }
            Operation::ComputeUnitPrice(price) => {
                if compute_unit_price.replace(price).is_some() {
                    add_violation(
                        &mut violations,
                        "duplicate_compute_unit_price",
                        "multiple compute unit price instructions are ambiguous",
                    );
                }
            }
            Operation::Memo => {}
            Operation::Dangerous { code, detail } => {
                add_violation(&mut violations, code, &detail);
            }
            Operation::Opaque { program_id, detail } => {
                add_violation(
                    &mut violations,
                    "opaque_program",
                    &format!("{program_id}: {detail}"),
                );
            }
        }
    }

    if sol_total > policy.max_sol_lamports {
        add_violation(
            &mut violations,
            "sol_limit_exceeded",
            &format!(
                "aggregate SOL transfer {sol_total} exceeds {} lamports",
                policy.max_sol_lamports
            ),
        );
    }
    for (mint, amount) in &token_totals {
        match policy.max_token_amounts.get(mint) {
            Some(limit) if amount <= limit => {}
            Some(limit) => add_violation(
                &mut violations,
                "token_limit_exceeded",
                &format!("mint {mint} amount {amount} exceeds raw limit {limit}"),
            ),
            None => add_violation(
                &mut violations,
                "token_limit_missing",
                &format!("mint {mint} has no configured raw amount limit"),
            ),
        }
    }
    if policy.require_value_transfer && transfer_count == 0 {
        add_violation(
            &mut violations,
            "value_transfer_required",
            "transaction contains no proven SOL or SPL transfer",
        );
    }

    let unit_limit = compute_unit_limit.unwrap_or(1_400_000) as u128;
    let unit_price = compute_unit_price.unwrap_or(0) as u128;
    let priority_fee = unit_limit
        .saturating_mul(unit_price)
        .saturating_add(999_999)
        / 1_000_000;
    if priority_fee > policy.max_priority_fee_lamports as u128 {
        add_violation(
            &mut violations,
            "priority_fee_limit_exceeded",
            &format!(
                "worst-case priority fee {priority_fee} exceeds {} lamports",
                policy.max_priority_fee_lamports
            ),
        );
    }

    let mut simulation = SimulationReceipt {
        status: if policy.require_simulation {
            "skipped-policy-denied".to_string()
        } else {
            "not-required".to_string()
        },
        units_consumed: None,
    };
    if violations.is_empty() && policy.require_simulation {
        match rpc.simulate_transaction(transaction_base64) {
            Ok(result) => {
                simulation.units_consumed = result.units_consumed;
                match result.error {
                    Some(error) => {
                        simulation.status = "failed".to_string();
                        add_violation(
                            &mut violations,
                            "simulation_failed",
                            &format!("Solana simulation returned {error}"),
                        );
                    }
                    None => simulation.status = "passed".to_string(),
                }
            }
            Err(error) => {
                simulation.status = "unavailable".to_string();
                add_violation(
                    &mut violations,
                    "simulation_unavailable",
                    &format!("Solana simulation could not be completed: {error}"),
                );
            }
        }
    }

    let verdict = if violations.is_empty() {
        "ALLOW"
    } else {
        "DENY"
    };
    let risk = risk_level(&violations, verdict);
    let summary = format!(
        "{} instruction(s), {} proven transfer(s), {} lookup table(s)",
        transaction.instructions.len(),
        transfer_count,
        transaction.lookup_table_count
    );
    let instruction_count = transaction.instructions.len();
    let writable_account_count = transaction.writable_account_count();
    finalize_receipt(DecisionReceipt {
        verdict: verdict.to_string(),
        risk,
        transaction_hash,
        policy_hash,
        receipt_hash: String::new(),
        version: Some(transaction.version.as_str().to_string()),
        fee_payer: Some(transaction.fee_payer),
        instructions: instruction_count,
        writable_accounts: writable_account_count,
        summary,
        transfers,
        simulation,
        violations,
    })
}

fn unparsed_denial(transaction_hash: String, code: &str, detail: &str) -> DecisionReceipt {
    finalize_receipt(DecisionReceipt {
        verdict: "DENY".to_string(),
        risk: "critical".to_string(),
        transaction_hash,
        policy_hash: "0".repeat(64),
        receipt_hash: String::new(),
        version: None,
        fee_payer: None,
        instructions: 0,
        writable_accounts: 0,
        summary: "transaction was not eligible for policy evaluation".to_string(),
        transfers: Vec::new(),
        simulation: SimulationReceipt {
            status: "not-run".to_string(),
            units_consumed: None,
        },
        violations: vec![Violation {
            code: code.to_string(),
            detail: truncate(detail, 160),
        }],
    })
}

fn denial_for_parse(
    transaction_hash: String,
    policy_hash: String,
    detail: &str,
) -> DecisionReceipt {
    let mut receipt = unparsed_denial(transaction_hash, "transaction_parse_failed", detail);
    receipt.policy_hash = policy_hash;
    finalize_receipt(receipt)
}

fn finalize_receipt(mut receipt: DecisionReceipt) -> DecisionReceipt {
    receipt.receipt_hash.clear();
    receipt.receipt_hash = hash_json(&receipt);
    receipt
}

fn risk_level(violations: &[Violation], verdict: &str) -> String {
    if verdict == "ALLOW" {
        return "low".to_string();
    }
    if violations.iter().any(|violation| {
        violation.code.contains("authority")
            || violation.code.contains("delegate")
            || violation.code.contains("mint")
            || violation.code.contains("burn")
            || violation.code.contains("close")
            || violation.code.contains("token_2022")
            || violation.code == "opaque_program"
            || violation.code == "transaction_already_signed"
    }) {
        "critical".to_string()
    } else {
        "high".to_string()
    }
}

fn add_violation(violations: &mut Vec<Violation>, code: &str, detail: &str) {
    if violations.len() >= MAX_VIOLATIONS {
        return;
    }
    let candidate = Violation {
        code: code.to_string(),
        detail: truncate(detail, 160),
    };
    if !violations.contains(&candidate) {
        violations.push(candidate);
    }
}

fn push_transfer(transfers: &mut Vec<TransferReceipt>, transfer: TransferReceipt) {
    if transfers.len() < MAX_RETURNED_TRANSFERS {
        transfers.push(transfer);
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_json<T: Serialize>(value: &T) -> String {
    match serde_json::to_vec(value) {
        Ok(bytes) => hash_bytes(&bytes),
        Err(_) => "0".repeat(64),
    }
}

fn parse_pubkey_set(
    section: &HashMap<String, String>,
    key: &str,
    required: bool,
) -> Result<BTreeSet<String>, String> {
    let values = csv(section.get(key));
    if required && values.is_empty() {
        return Err(format!("{key} must contain at least one pubkey"));
    }
    for value in &values {
        validate_pubkey(value).map_err(|error| format!("{key}: {error}"))?;
    }
    Ok(values)
}

fn parse_program_set(section: &HashMap<String, String>) -> Result<BTreeSet<String>, String> {
    let raw = csv(section.get("allowed_programs"));
    if raw.is_empty() {
        return Err("allowed_programs must contain at least one program".to_string());
    }
    raw.into_iter()
        .map(|program| {
            let expanded = match program.as_str() {
                "system" => SYSTEM_PROGRAM.to_string(),
                "token" => TOKEN_PROGRAM.to_string(),
                "token-2022" => TOKEN_2022_PROGRAM.to_string(),
                "associated-token" => ASSOCIATED_TOKEN_PROGRAM.to_string(),
                "compute-budget" => COMPUTE_BUDGET_PROGRAM.to_string(),
                "memo" => MEMO_PROGRAM.to_string(),
                "memo-v1" => MEMO_V1_PROGRAM.to_string(),
                _ => program,
            };
            validate_pubkey(&expanded).map_err(|error| format!("allowed_programs: {error}"))?;
            Ok(expanded)
        })
        .collect()
}

fn parse_token_limits(value: Option<&String>) -> Result<BTreeMap<String, u64>, String> {
    let mut limits = BTreeMap::new();
    for pair in csv(value) {
        let (mint, amount) = pair
            .split_once('=')
            .ok_or_else(|| format!("max_token_amounts entry {pair:?} must be mint=raw_amount"))?;
        validate_pubkey(mint).map_err(|error| format!("max_token_amounts: {error}"))?;
        let amount = amount
            .parse::<u64>()
            .map_err(|_| format!("max_token_amounts value {amount:?} is not a u64"))?;
        if limits.insert(mint.to_string(), amount).is_some() {
            return Err(format!("max_token_amounts repeats mint {mint}"));
        }
    }
    Ok(limits)
}

fn csv(value: Option<&String>) -> BTreeSet<String> {
    value
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn validate_pubkey(value: &str) -> Result<(), String> {
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| format!("{value:?} is not base58"))?;
    if decoded.len() != 32 {
        return Err(format!("{value:?} does not decode to 32 bytes"));
    }
    Ok(())
}

fn parse_u64(section: &HashMap<String, String>, key: &str, default: u64) -> Result<u64, String> {
    match section.get(key) {
        Some(value) => value
            .parse::<u64>()
            .map_err(|_| format!("{key} must be a non-negative integer")),
        None => Ok(default),
    }
}

fn parse_usize(
    section: &HashMap<String, String>,
    key: &str,
    default: usize,
    maximum: usize,
) -> Result<usize, String> {
    let value = match section.get(key) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| format!("{key} must be a non-negative integer"))?,
        None => default,
    };
    if value > maximum {
        return Err(format!("{key} {value} exceeds supported maximum {maximum}"));
    }
    Ok(value)
}

fn parse_bool(section: &HashMap<String, String>, key: &str, default: bool) -> Result<bool, String> {
    match section.get(key).map(|value| value.as_str()) {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(format!("{key} must be exactly true or false")),
    }
}
