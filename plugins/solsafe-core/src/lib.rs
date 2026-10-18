use std::collections::{BTreeSet, HashMap, HashSet};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EP5HmajShw2c8rzz4M8";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
pub const MEMO_LEGACY_PROGRAM: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";
pub const ADDRESS_LOOKUP_TABLE_PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";
pub const JUPITER_V6_PROGRAM: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

const MAX_FINDINGS_HARD: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolSafeError {
    Input(String),
    Config(String),
    Decode(String),
    Policy(String),
    Rpc(String),
    Jupiter(String),
    Output(String),
}

impl std::fmt::Display for SolSafeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(s) => write!(f, "InputError: {s}"),
            Self::Config(s) => write!(f, "ConfigError: {s}"),
            Self::Decode(s) => write!(f, "DecodeError: {s}"),
            Self::Policy(s) => write!(f, "PolicyError: {s}"),
            Self::Rpc(s) => write!(f, "RpcError: {s}"),
            Self::Jupiter(s) => write!(f, "JupiterError: {s}"),
            Self::Output(s) => write!(f, "OutputLimitError: {s}"),
        }
    }
}

impl std::error::Error for SolSafeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Green,
    Amber,
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: String,
    pub message: String,
}

impl Finding {
    pub fn critical(code: &str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Critical,
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn warning(code: &str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn info(code: &str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            code: code.to_string(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProgramSummary {
    pub program_id: String,
    pub label: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpirySummary {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_valid_block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_block_heights: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationSummary {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units_consumed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub verdict: Verdict,
    pub custody_tier: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_action: Option<String>,
    pub actual_actions: Vec<String>,
    pub findings: Vec<Finding>,
    pub programs: Vec<ProgramSummary>,
    pub required_signers: Vec<String>,
    pub expiry: ExpirySummary,
    pub simulation: SimulationSummary,
    pub approval_text: String,
}

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DeclaredIntent {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub input_mint: Option<String>,
    #[serde(default)]
    pub output_mint: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub max_amount: Option<String>,
    #[serde(default)]
    pub expected_recipient: Option<String>,
    #[serde(default)]
    pub expected_programs: Vec<String>,
    #[serde(default)]
    pub expected_signer: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AuditOptions {
    #[serde(default = "default_true")]
    pub simulate: bool,
    #[serde(default = "default_true")]
    pub strict: bool,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            simulate: true,
            strict: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct AuditInput {
    transaction_base64: String,
    #[serde(default)]
    declared_intent: DeclaredIntent,
    #[serde(default)]
    options: AuditOptions,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

#[derive(Clone)]
pub struct AuditPolicy {
    pub rpc_url: Option<String>,
    pub strict_mode: bool,
    pub simulation_required: bool,
    pub reject_unknown_programs: bool,
    pub allow_short_approval_window: bool,
    pub allowed_program_ids: HashSet<String>,
    pub allowed_recipient_addresses: HashSet<String>,
    pub allowed_mints: HashSet<String>,
    pub max_sol_transfer_lamports: Option<u64>,
    pub max_token_transfer_raw_amount: Option<u128>,
    pub minimum_remaining_block_height: u64,
    pub max_transaction_bytes: usize,
    pub max_input_chars: usize,
    pub max_output_chars: usize,
    pub max_findings: usize,
    pub max_programs_in_output: usize,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        let mut allowed_program_ids = HashSet::new();
        for id in [
            SYSTEM_PROGRAM,
            SPL_TOKEN_PROGRAM,
            TOKEN_2022_PROGRAM,
            ATA_PROGRAM,
            COMPUTE_BUDGET_PROGRAM,
            MEMO_PROGRAM,
            MEMO_LEGACY_PROGRAM,
            ADDRESS_LOOKUP_TABLE_PROGRAM,
            JUPITER_V6_PROGRAM,
        ] {
            allowed_program_ids.insert(id.to_string());
        }
        Self {
            rpc_url: None,
            strict_mode: true,
            simulation_required: false,
            reject_unknown_programs: true,
            allow_short_approval_window: false,
            allowed_program_ids,
            allowed_recipient_addresses: HashSet::new(),
            allowed_mints: HashSet::new(),
            max_sol_transfer_lamports: None,
            max_token_transfer_raw_amount: None,
            minimum_remaining_block_height: 20,
            max_transaction_bytes: 1232,
            max_input_chars: 10000,
            max_output_chars: 2400,
            max_findings: 20,
            max_programs_in_output: 20,
        }
    }
}

impl AuditPolicy {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, SolSafeError> {
        let mut p = Self::default();
        if let Some(v) = nonempty(section, "rpc_url") {
            p.rpc_url = Some(v.to_string());
        }
        p.strict_mode = bool_key(section, "strict_mode", p.strict_mode);
        p.simulation_required = bool_key(section, "simulation_required", p.simulation_required);
        p.reject_unknown_programs = bool_key(
            section,
            "reject_unknown_programs",
            p.reject_unknown_programs,
        );
        p.allow_short_approval_window = bool_key(
            section,
            "allow_short_approval_window",
            p.allow_short_approval_window,
        );
        extend_addresses(section, "allowed_program_ids", &mut p.allowed_program_ids)?;
        p.allowed_recipient_addresses =
            parse_address_set(section.get("allowed_recipient_addresses"))?;
        p.allowed_mints = parse_address_set(section.get("allowed_mints"))?;
        p.max_sol_transfer_lamports = parse_u64_opt(section, "max_sol_transfer_lamports")?;
        p.max_token_transfer_raw_amount = parse_u128_opt(section, "max_token_transfer_raw_amount")?;
        p.minimum_remaining_block_height = parse_u64_key(
            section,
            "minimum_remaining_block_height",
            p.minimum_remaining_block_height,
        )?;
        p.max_transaction_bytes =
            parse_usize_key(section, "max_transaction_bytes", p.max_transaction_bytes)?;
        p.max_input_chars = parse_usize_key(section, "max_input_chars", p.max_input_chars)?;
        p.max_output_chars = parse_usize_key(section, "max_output_chars", p.max_output_chars)?;
        p.max_findings =
            parse_usize_key(section, "max_findings", p.max_findings)?.min(MAX_FINDINGS_HARD);
        p.max_programs_in_output =
            parse_usize_key(section, "max_programs_in_output", p.max_programs_in_output)?;
        Ok(p)
    }
}

pub trait RpcClient {
    fn call(&self, method: &str, params: Value) -> Result<Value, SolSafeError>;
}

#[derive(Debug, Clone)]
struct ParsedTransaction {
    version: String,
    required_signers: Vec<String>,
    instructions: Vec<CompiledInstruction>,
    has_address_table_lookups: bool,
}

#[derive(Debug, Clone)]
struct CompiledInstruction {
    program_id: String,
    accounts: Vec<String>,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DecodedInstruction {
    action: String,
    finding: Option<Finding>,
    transfer: Option<TransferInfo>,
    program: ProgramSummary,
}

#[derive(Debug, Clone)]
struct TransferInfo {
    amount: u128,
    recipient: Option<String>,
    is_sol: bool,
}

pub fn audit_json(args: &str, rpc: Option<&dyn RpcClient>) -> Result<String, SolSafeError> {
    if args.chars().count() > AuditPolicy::default().max_input_chars {
        return Err(SolSafeError::Input(
            "arguments exceed maximum size".to_string(),
        ));
    }
    let input: AuditInput = serde_json::from_str(args)
        .map_err(|e| SolSafeError::Input(format!("invalid JSON: {e}")))?;
    let mut policy = AuditPolicy::from_section(&input.config)?;
    if args.chars().count() > policy.max_input_chars {
        return Err(SolSafeError::Input(
            "arguments exceed configured maximum size".to_string(),
        ));
    }
    validate_intent(&input.declared_intent)?;
    let strict = policy.strict_mode || input.options.strict;
    if input.options.simulate && !policy.simulation_required {
        policy.simulation_required = false;
    }
    let report = audit_transaction(
        &input.transaction_base64,
        &input.declared_intent,
        &input.options,
        &policy,
        strict,
        rpc,
    );
    let out = bounded_report(
        report,
        policy.max_output_chars,
        policy.max_findings,
        policy.max_programs_in_output,
    )?;
    serde_json::to_string(&out).map_err(|e| SolSafeError::Output(e.to_string()))
}

pub fn audit_transaction(
    tx_base64: &str,
    declared: &DeclaredIntent,
    options: &AuditOptions,
    policy: &AuditPolicy,
    strict: bool,
    rpc: Option<&dyn RpcClient>,
) -> AuditReport {
    let mut findings = Vec::new();
    let mut actual_actions = Vec::new();
    let mut programs = Vec::new();
    let mut required_signers = Vec::new();
    let mut expiry = ExpirySummary {
        status: "unknown".to_string(),
        current_block_height: None,
        last_valid_block_height: None,
        remaining_block_heights: None,
    };
    let mut simulation = SimulationSummary {
        status: "not_requested".to_string(),
        units_consumed: None,
        error: None,
    };

    let parsed = match decode_transaction(tx_base64, policy.max_transaction_bytes) {
        Ok(p) => p,
        Err(e) => {
            findings.push(Finding::critical("MALFORMED_TRANSACTION", e.to_string()));
            return finish_report(
                declared,
                actual_actions,
                findings,
                programs,
                required_signers,
                expiry,
                simulation,
            );
        }
    };

    required_signers = parsed.required_signers.clone();
    if parsed.has_address_table_lookups {
        match rpc {
            Some(client) => match client.call("getMultipleAccounts", json!([])) {
                Ok(_) => findings.push(Finding::warning(
                    "ADDRESS_LOOKUP_TABLE_PRESENT",
                    "Address lookup table references were present; static audit treats unresolved dynamic keys as requiring human attention.",
                )),
                Err(e) => findings.push(Finding::critical(
                    "UNRESOLVED_ADDRESS_LOOKUP_TABLE",
                    format!("Address lookup table resolution failed: {e}"),
                )),
            },
            None => findings.push(Finding::critical(
                "UNRESOLVED_ADDRESS_LOOKUP_TABLE",
                "Address lookup table references require configured RPC resolution.",
            )),
        }
    }

    if let Some(expected) = &declared.expected_signer {
        if !required_signers.iter().any(|s| s == expected) {
            findings.push(Finding::critical(
                "UNEXPECTED_SIGNER",
                "The required signer set does not include the declared expected signer.",
            ));
        }
    }

    let mut transfers = Vec::new();
    let mut seen_programs = BTreeSet::new();
    for ix in &parsed.instructions {
        let decoded = decode_instruction(ix, &policy.allowed_program_ids);
        if seen_programs.insert(decoded.program.program_id.clone()) {
            programs.push(decoded.program.clone());
        }
        if !policy.allowed_program_ids.contains(&ix.program_id) {
            findings.push(Finding::critical(
                "FORBIDDEN_PROGRAM",
                format!("Program {} is not allowed by policy.", ix.program_id),
            ));
        }
        if decoded.program.status == "unknown" && (strict || policy.reject_unknown_programs) {
            findings.push(Finding::critical(
                "UNKNOWN_PROGRAM",
                format!("Program {} is unknown or not configured.", ix.program_id),
            ));
        }
        if decoded.action.starts_with("Unknown") && strict {
            findings.push(Finding::critical(
                "UNKNOWN_CRITICAL_INSTRUCTION",
                format!(
                    "Security-critical instruction could not be decoded for {}.",
                    ix.program_id
                ),
            ));
        }
        if let Some(f) = decoded.finding {
            findings.push(f);
        }
        if let Some(t) = decoded.transfer {
            transfers.push(t);
        }
        actual_actions.push(decoded.action);
    }

    compare_intent(
        declared,
        policy,
        &transfers,
        &required_signers,
        &mut findings,
    );
    if actual_actions.is_empty() {
        findings.push(Finding::critical(
            "NO_INSTRUCTIONS",
            "Transaction contains no decoded instructions.",
        ));
    }
    if parsed.version == "v0" {
        findings.push(Finding::info(
            "VERSIONED_TRANSACTION",
            "Versioned v0 transaction decoded.",
        ));
    }

    if policy.simulation_required || options.simulate {
        simulation = simulate(tx_base64, policy, rpc, &mut findings);
    }
    expiry = check_expiry(policy, rpc, &mut findings);

    finish_report(
        declared,
        actual_actions,
        findings,
        programs,
        required_signers,
        expiry,
        simulation,
    )
}

fn finish_report(
    declared: &DeclaredIntent,
    actual_actions: Vec<String>,
    findings: Vec<Finding>,
    programs: Vec<ProgramSummary>,
    required_signers: Vec<String>,
    expiry: ExpirySummary,
    simulation: SimulationSummary,
) -> AuditReport {
    let verdict = if findings.iter().any(|f| f.severity == Severity::Critical) {
        Verdict::Red
    } else if findings.iter().any(|f| f.severity == Severity::Warning) {
        Verdict::Amber
    } else {
        Verdict::Green
    };
    let summary = match verdict {
        Verdict::Green => "Transaction accepted by static policy checks.".to_string(),
        Verdict::Amber => "Transaction requires human attention before approval.".to_string(),
        Verdict::Red => findings
            .iter()
            .find(|f| f.severity == Severity::Critical)
            .map(|f| format!("Transaction rejected: {}", f.message))
            .unwrap_or_else(|| "Transaction rejected by policy.".to_string()),
    };
    let approval_text = match verdict {
        Verdict::Green => "APPROVED FOR HUMAN REVIEW: unsigned transaction passed SolSafe checks.",
        Verdict::Amber => "REVIEW REQUIRED: unsigned transaction has non-critical warnings.",
        Verdict::Red => "REJECTED: unsigned transaction failed SolSafe checks.",
    }
    .to_string();
    AuditReport {
        verdict,
        custody_tier: "T0".to_string(),
        summary,
        declared_action: declared.action.clone(),
        actual_actions,
        findings,
        programs,
        required_signers,
        expiry,
        simulation,
        approval_text,
    }
}

fn bounded_report(
    mut r: AuditReport,
    max_chars: usize,
    max_findings: usize,
    max_programs: usize,
) -> Result<AuditReport, SolSafeError> {
    r.findings.sort_by_key(|f| match f.severity {
        Severity::Critical => 0,
        Severity::Warning => 1,
        Severity::Info => 2,
    });
    r.findings.truncate(max_findings.max(1));
    r.programs.truncate(max_programs.max(1));
    r.actual_actions.truncate(20);
    let mut encoded = serde_json::to_string(&r).map_err(|e| SolSafeError::Output(e.to_string()))?;
    while encoded.chars().count() > max_chars && r.actual_actions.len() > 1 {
        r.actual_actions.pop();
        encoded = serde_json::to_string(&r).map_err(|e| SolSafeError::Output(e.to_string()))?;
    }
    while encoded.chars().count() > max_chars && r.findings.len() > 1 {
        let last_is_critical = r
            .findings
            .last()
            .map(|f| f.severity == Severity::Critical)
            .unwrap_or(false);
        if last_is_critical {
            break;
        }
        r.findings.pop();
        encoded = serde_json::to_string(&r).map_err(|e| SolSafeError::Output(e.to_string()))?;
    }
    if encoded.chars().count() > max_chars {
        r.summary.truncate(max_chars.min(160));
        r.approval_text.truncate(max_chars.min(160));
    }
    Ok(r)
}

fn decode_transaction(
    tx_base64: &str,
    max_bytes: usize,
) -> Result<ParsedTransaction, SolSafeError> {
    if tx_base64.is_empty() || tx_base64.len() > max_bytes.saturating_mul(2) {
        return Err(SolSafeError::Input(
            "base64 transaction size is invalid".to_string(),
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(tx_base64)
        .map_err(|_| SolSafeError::Input("malformed base64 transaction".to_string()))?;
    if bytes.len() > max_bytes {
        return Err(SolSafeError::Input(
            "transaction exceeds configured byte limit".to_string(),
        ));
    }
    let mut c = Cursor::new(&bytes);
    let sig_count = c.compact_len()?;
    let sig_bytes = sig_count
        .checked_mul(64)
        .ok_or_else(|| SolSafeError::Decode("signature length overflow".to_string()))?;
    c.take(sig_bytes)?;
    let first = c.u8()?;
    let versioned = (first & 0x80) != 0;
    let (version, header_first) = if versioned {
        let version = first & 0x7f;
        if version != 0 {
            return Err(SolSafeError::Decode(
                "unsupported transaction version".to_string(),
            ));
        }
        ("v0".to_string(), c.u8()?)
    } else {
        ("legacy".to_string(), first)
    };
    let required_signatures = header_first as usize;
    let _readonly_signed = c.u8()?;
    let _readonly_unsigned = c.u8()?;
    let account_count = c.compact_len()?;
    if account_count > 256 {
        return Err(SolSafeError::Decode("too many account keys".to_string()));
    }
    let mut account_keys = Vec::with_capacity(account_count);
    for _ in 0..account_count {
        account_keys.push(bs58::encode(c.take(32)?).into_string());
    }
    c.take(32)?;
    let ix_count = c.compact_len()?;
    if ix_count > 256 {
        return Err(SolSafeError::Decode("too many instructions".to_string()));
    }
    let mut instructions = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        let program_idx = c.u8()? as usize;
        let program_id = account_keys
            .get(program_idx)
            .cloned()
            .ok_or_else(|| SolSafeError::Decode("program account index is invalid".to_string()))?;
        let acct_len = c.compact_len()?;
        if acct_len > 64 {
            return Err(SolSafeError::Decode(
                "too many instruction accounts".to_string(),
            ));
        }
        let mut accounts = Vec::with_capacity(acct_len);
        for _ in 0..acct_len {
            let idx = c.u8()? as usize;
            accounts.push(account_keys.get(idx).cloned().ok_or_else(|| {
                SolSafeError::Decode("instruction account index is invalid".to_string())
            })?);
        }
        let data_len = c.compact_len()?;
        if data_len > 1024 {
            return Err(SolSafeError::Decode(
                "instruction data is too large".to_string(),
            ));
        }
        let data = c.take(data_len)?.to_vec();
        instructions.push(CompiledInstruction {
            program_id,
            accounts,
            data,
        });
    }
    let mut has_address_table_lookups = false;
    if version == "v0" {
        let lookup_count = c.compact_len()?;
        has_address_table_lookups = lookup_count > 0;
        for _ in 0..lookup_count {
            c.take(32)?;
            let writable = c.compact_len()?;
            c.take(writable)?;
            let readonly = c.compact_len()?;
            c.take(readonly)?;
        }
    }
    if !c.done() {
        return Err(SolSafeError::Decode(
            "unexpected trailing bytes".to_string(),
        ));
    }
    let required_signers = account_keys
        .iter()
        .take(required_signatures.min(account_keys.len()))
        .cloned()
        .collect();
    Ok(ParsedTransaction {
        version,
        required_signers,
        instructions,
        has_address_table_lookups,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8, SolSafeError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or_else(|| SolSafeError::Decode("truncated payload".to_string()))?)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SolSafeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| SolSafeError::Decode("length overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(SolSafeError::Decode("truncated payload".to_string()));
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn compact_len(&mut self) -> Result<usize, SolSafeError> {
        let mut value: u32 = 0;
        let mut shift = 0u32;
        for i in 0..3 {
            let byte = self.u8()? as u32;
            value |= (byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return usize::try_from(value)
                    .map_err(|_| SolSafeError::Decode("compact length overflow".to_string()));
            }
            if i == 2 {
                return Err(SolSafeError::Decode(
                    "invalid compact-u16 length".to_string(),
                ));
            }
            shift += 7;
        }
        Err(SolSafeError::Decode(
            "invalid compact-u16 length".to_string(),
        ))
    }

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn decode_instruction(ix: &CompiledInstruction, allowed: &HashSet<String>) -> DecodedInstruction {
    let (label, known) = program_label(&ix.program_id, allowed);
    let program = ProgramSummary {
        program_id: ix.program_id.clone(),
        label: label.to_string(),
        status: if known { "known" } else { "unknown" }.to_string(),
    };
    if ix.program_id == SYSTEM_PROGRAM {
        return decode_system(ix, program);
    }
    if ix.program_id == SPL_TOKEN_PROGRAM || ix.program_id == TOKEN_2022_PROGRAM {
        return decode_token(ix, program, ix.program_id == TOKEN_2022_PROGRAM);
    }
    if ix.program_id == ATA_PROGRAM {
        return DecodedInstruction {
            action: "Create associated token account".to_string(),
            finding: Some(Finding::warning(
                "ATA_CREATION",
                "Associated token account creation requires approval attention.",
            )),
            transfer: None,
            program,
        };
    }
    if ix.program_id == COMPUTE_BUDGET_PROGRAM {
        return DecodedInstruction {
            action: "Set compute budget".to_string(),
            finding: None,
            transfer: None,
            program,
        };
    }
    if ix.program_id == MEMO_PROGRAM || ix.program_id == MEMO_LEGACY_PROGRAM {
        return DecodedInstruction {
            action: "Attach memo".to_string(),
            finding: None,
            transfer: None,
            program,
        };
    }
    if ix.program_id == ADDRESS_LOOKUP_TABLE_PROGRAM {
        return DecodedInstruction {
            action: "Address lookup table operation".to_string(),
            finding: Some(Finding::warning(
                "ADDRESS_LOOKUP_TABLE_OPERATION",
                "Address lookup table instruction appears in transaction.",
            )),
            transfer: None,
            program,
        };
    }
    if ix.program_id == JUPITER_V6_PROGRAM || ix.program_id.starts_with("JUP") {
        return DecodedInstruction {
            action: "Jupiter swap route instruction".to_string(),
            finding: None,
            transfer: None,
            program,
        };
    }
    DecodedInstruction {
        action: format!("Unknown instruction for {}", ix.program_id),
        finding: None,
        transfer: None,
        program,
    }
}

fn decode_system(ix: &CompiledInstruction, program: ProgramSummary) -> DecodedInstruction {
    let op = read_u32_le(&ix.data, 0);
    match op {
        Some(2) => {
            let lamports = read_u64_le(&ix.data, 4).unwrap_or(0);
            let recipient = ix.accounts.get(1).cloned();
            DecodedInstruction {
                action: format!("Transfer {lamports} lamports"),
                finding: None,
                transfer: Some(TransferInfo {
                    amount: lamports as u128,
                    recipient,
                    is_sol: true,
                }),
                program,
            }
        }
        Some(0) => DecodedInstruction {
            action: "Create system account".to_string(),
            finding: Some(Finding::warning(
                "ACCOUNT_CREATE",
                "System account creation detected.",
            )),
            transfer: None,
            program,
        },
        Some(1) => DecodedInstruction {
            action: "Assign system account owner".to_string(),
            finding: Some(Finding::critical(
                "ACCOUNT_ASSIGN",
                "System account ownership assignment detected.",
            )),
            transfer: None,
            program,
        },
        _ => DecodedInstruction {
            action: "Unknown System Program instruction".to_string(),
            finding: None,
            transfer: None,
            program,
        },
    }
}

fn decode_token(
    ix: &CompiledInstruction,
    program: ProgramSummary,
    token_2022: bool,
) -> DecodedInstruction {
    let tag = ix.data.first().copied();
    let prefix = if token_2022 {
        "Token-2022"
    } else {
        "SPL Token"
    };
    match tag {
        Some(3) | Some(12) => {
            let amount = read_u64_le(&ix.data, 1).unwrap_or(0) as u128;
            let recipient = ix.accounts.get(1).cloned();
            DecodedInstruction {
                action: format!("{prefix} transfer {amount} raw units"),
                finding: token_2022.then(|| {
                    Finding::warning(
                        "TOKEN_2022_TRANSFER_SIGNAL",
                        "Token-2022 transfer may involve extensions such as fees or hooks.",
                    )
                }),
                transfer: Some(TransferInfo {
                    amount,
                    recipient,
                    is_sol: false,
                }),
                program,
            }
        }
        Some(4) | Some(13) => DecodedInstruction {
            action: format!("{prefix} approve delegate"),
            finding: Some(Finding::critical(
                "DELEGATE_APPROVAL",
                "Token delegate approval detected.",
            )),
            transfer: None,
            program,
        },
        Some(5) => DecodedInstruction {
            action: format!("{prefix} revoke delegate"),
            finding: Some(Finding::warning(
                "DELEGATE_REVOKE",
                "Token delegate revoke detected.",
            )),
            transfer: None,
            program,
        },
        Some(6) => DecodedInstruction {
            action: format!("{prefix} set authority"),
            finding: Some(Finding::critical(
                "AUTHORITY_CHANGE",
                "Token authority change detected.",
            )),
            transfer: None,
            program,
        },
        Some(7) | Some(14) => DecodedInstruction {
            action: format!("{prefix} mint tokens"),
            finding: Some(Finding::critical(
                "MINT_TO",
                "Token mint instruction detected.",
            )),
            transfer: None,
            program,
        },
        Some(8) | Some(15) => DecodedInstruction {
            action: format!("{prefix} burn tokens"),
            finding: Some(Finding::critical(
                "BURN",
                "Token burn instruction detected.",
            )),
            transfer: None,
            program,
        },
        Some(9) => DecodedInstruction {
            action: format!("{prefix} close account"),
            finding: Some(Finding::critical(
                "TOKEN_ACCOUNT_CLOSE",
                "Token account close instruction detected.",
            )),
            transfer: None,
            program,
        },
        Some(10) | Some(16) => DecodedInstruction {
            action: format!("{prefix} freeze account"),
            finding: Some(Finding::critical(
                "FREEZE_ACCOUNT",
                "Token account freeze detected.",
            )),
            transfer: None,
            program,
        },
        Some(11) | Some(17) => DecodedInstruction {
            action: format!("{prefix} thaw account"),
            finding: Some(Finding::warning(
                "THAW_ACCOUNT",
                "Token account thaw detected.",
            )),
            transfer: None,
            program,
        },
        Some(18) => DecodedInstruction {
            action: format!("{prefix} sync native"),
            finding: None,
            transfer: None,
            program,
        },
        _ => DecodedInstruction {
            action: format!("Unknown {prefix} instruction"),
            finding: token_2022.then(|| {
                Finding::critical(
                    "TOKEN_2022_UNKNOWN_EXTENSION_BEHAVIOR",
                    "Token-2022 instruction or extension behavior is unresolved.",
                )
            }),
            transfer: None,
            program,
        },
    }
}

fn compare_intent(
    declared: &DeclaredIntent,
    policy: &AuditPolicy,
    transfers: &[TransferInfo],
    required_signers: &[String],
    findings: &mut Vec<Finding>,
) {
    if let Some(signer) = &declared.expected_signer {
        if !required_signers.iter().any(|s| s == signer) {
            findings.push(Finding::critical(
                "EXPECTED_SIGNER_MISSING",
                "Expected signer is not required by the transaction.",
            ));
        }
    }
    let transfer_declared = matches!(declared.action.as_deref(), Some("transfer"));
    let swap_declared = matches!(declared.action.as_deref(), Some("swap"));
    for t in transfers {
        if t.is_sol {
            if let Some(max) = policy.max_sol_transfer_lamports {
                if t.amount > max as u128 {
                    findings.push(Finding::critical(
                        "SOL_TRANSFER_ABOVE_LIMIT",
                        "SOL transfer exceeds configured maximum.",
                    ));
                }
            }
        } else if let Some(max) = policy.max_token_transfer_raw_amount {
            if t.amount > max {
                findings.push(Finding::critical(
                    "TOKEN_TRANSFER_ABOVE_LIMIT",
                    "Token transfer exceeds configured maximum.",
                ));
            }
        }
        if !transfer_declared && !swap_declared {
            findings.push(Finding::critical(
                "UNEXPECTED_TRANSFER",
                "A transfer was detected but not declared.",
            ));
        }
        if swap_declared && t.is_sol && declared.expected_recipient.is_none() {
            findings.push(Finding::critical(
                "UNEXPECTED_SOL_TRANSFER",
                "An undeclared SOL transfer was detected.",
            ));
        }
        if let Some(expected) = &declared.expected_recipient {
            if t.recipient.as_deref() != Some(expected.as_str()) {
                findings.push(Finding::critical(
                    "UNEXPECTED_RECIPIENT",
                    "A transfer recipient does not match declared intent.",
                ));
            }
        } else if let Some(recipient) = &t.recipient {
            if !policy.allowed_recipient_addresses.is_empty()
                && !policy.allowed_recipient_addresses.contains(recipient)
            {
                findings.push(Finding::critical(
                    "RECIPIENT_NOT_ALLOWED",
                    "A transfer recipient is outside configured allowlist.",
                ));
            }
        }
    }
    for mint in [&declared.input_mint, &declared.output_mint]
        .into_iter()
        .flatten()
    {
        if !policy.allowed_mints.is_empty() && !policy.allowed_mints.contains(mint) {
            findings.push(Finding::critical(
                "MINT_NOT_ALLOWED",
                "Declared mint is outside configured allowlist.",
            ));
        }
    }
}

fn simulate(
    tx_base64: &str,
    policy: &AuditPolicy,
    rpc: Option<&dyn RpcClient>,
    findings: &mut Vec<Finding>,
) -> SimulationSummary {
    let Some(client) = rpc else {
        if policy.simulation_required {
            findings.push(Finding::critical(
                "SIMULATION_REQUIRED_UNAVAILABLE",
                "Simulation is required but no RPC client is configured.",
            ));
        }
        return SimulationSummary {
            status: "unavailable".to_string(),
            units_consumed: None,
            error: Some("no rpc client".to_string()),
        };
    };
    match client.call(
        "simulateTransaction",
        json!([tx_base64, {"encoding": "base64", "sigVerify": false}]),
    ) {
        Ok(v) => {
            let value = v.get("value").unwrap_or(&v);
            if !value.get("err").unwrap_or(&Value::Null).is_null() {
                findings.push(Finding::critical(
                    "SIMULATION_FAILED",
                    "Solana simulation returned a program error.",
                ));
                return SimulationSummary {
                    status: "failed".to_string(),
                    units_consumed: value.get("unitsConsumed").and_then(Value::as_u64),
                    error: Some("program error".to_string()),
                };
            }
            SimulationSummary {
                status: "success".to_string(),
                units_consumed: value.get("unitsConsumed").and_then(Value::as_u64),
                error: None,
            }
        }
        Err(e) => {
            if policy.simulation_required {
                findings.push(Finding::critical(
                    "SIMULATION_RPC_ERROR",
                    "Required simulation RPC call failed.",
                ));
            } else {
                findings.push(Finding::warning(
                    "OPTIONAL_SIMULATION_UNAVAILABLE",
                    "Optional simulation RPC call failed.",
                ));
            }
            SimulationSummary {
                status: "unavailable".to_string(),
                units_consumed: None,
                error: Some(e.to_string()),
            }
        }
    }
}

fn check_expiry(
    policy: &AuditPolicy,
    rpc: Option<&dyn RpcClient>,
    findings: &mut Vec<Finding>,
) -> ExpirySummary {
    let Some(client) = rpc else {
        return ExpirySummary {
            status: "unknown".to_string(),
            current_block_height: None,
            last_valid_block_height: None,
            remaining_block_heights: None,
        };
    };
    let current = client.call("getBlockHeight", json!([])).ok().and_then(|v| {
        v.as_u64()
            .or_else(|| v.get("result").and_then(Value::as_u64))
    });
    let latest = client.call("getLatestBlockhash", json!([])).ok();
    let last_valid = latest
        .as_ref()
        .and_then(|v| {
            v.pointer("/value/lastValidBlockHeight")
                .or_else(|| v.pointer("/result/value/lastValidBlockHeight"))
        })
        .and_then(Value::as_u64);
    match (current, last_valid) {
        (Some(c), Some(l)) if c > l => {
            findings.push(Finding::critical(
                "EXPIRED_BLOCKHASH",
                "Transaction blockhash is expired.",
            ));
            ExpirySummary {
                status: "expired".to_string(),
                current_block_height: Some(c),
                last_valid_block_height: Some(l),
                remaining_block_heights: Some(0),
            }
        }
        (Some(c), Some(l)) => {
            let remaining = l.saturating_sub(c);
            if remaining < policy.minimum_remaining_block_height {
                let f = if policy.allow_short_approval_window {
                    Finding::warning("SHORT_APPROVAL_WINDOW", "Approval window is short.")
                } else {
                    Finding::critical(
                        "SHORT_APPROVAL_WINDOW",
                        "Approval window is below policy minimum.",
                    )
                };
                findings.push(f);
                ExpirySummary {
                    status: "approval_window_short".to_string(),
                    current_block_height: Some(c),
                    last_valid_block_height: Some(l),
                    remaining_block_heights: Some(remaining),
                }
            } else {
                ExpirySummary {
                    status: "fresh".to_string(),
                    current_block_height: Some(c),
                    last_valid_block_height: Some(l),
                    remaining_block_heights: Some(remaining),
                }
            }
        }
        _ => ExpirySummary {
            status: "unknown".to_string(),
            current_block_height: current,
            last_valid_block_height: last_valid,
            remaining_block_heights: None,
        },
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct JupiterInput {
    pub user_public_key: String,
    pub input_mint: String,
    pub output_mint: String,
    pub amount: String,
    pub amount_type: String,
    pub slippage_bps: u16,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default)]
    pub only_direct_routes: bool,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

#[derive(Clone)]
pub struct JupiterPolicy {
    pub audit_policy: AuditPolicy,
    pub jupiter_quote_url: Option<String>,
    pub jupiter_swap_url: Option<String>,
    pub allowed_input_mints: HashSet<String>,
    pub allowed_output_mints: HashSet<String>,
    pub allowed_intermediate_mints: HashSet<String>,
    pub max_slippage_bps: u16,
    pub max_raw_amount_by_mint: HashMap<String, u128>,
    pub max_ui_amount_by_mint: HashMap<String, String>,
    pub max_price_impact_bps: u32,
    pub max_route_hops: usize,
    pub only_direct_routes: bool,
    pub minimum_output_required: bool,
    pub max_response_bytes: usize,
    pub max_output_chars: usize,
}

impl JupiterPolicy {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, SolSafeError> {
        let audit_policy = AuditPolicy::from_section(section)?;
        Ok(Self {
            audit_policy,
            jupiter_quote_url: nonempty(section, "jupiter_quote_url").map(str::to_string),
            jupiter_swap_url: nonempty(section, "jupiter_swap_url").map(str::to_string),
            allowed_input_mints: parse_address_set(section.get("allowed_input_mints"))?,
            allowed_output_mints: parse_address_set(section.get("allowed_output_mints"))?,
            allowed_intermediate_mints: parse_address_set(
                section.get("allowed_intermediate_mints"),
            )?,
            max_slippage_bps: parse_u16_key(section, "max_slippage_bps", 100)?,
            max_raw_amount_by_mint: parse_amount_map(section.get("max_raw_amount_by_mint"))?,
            max_ui_amount_by_mint: parse_string_map(section.get("max_ui_amount_by_mint"))?,
            max_price_impact_bps: parse_price_bps(section.get("max_price_impact_pct"), 300)?,
            max_route_hops: parse_usize_key(section, "max_route_hops", 3)?,
            only_direct_routes: bool_key(section, "only_direct_routes", false),
            minimum_output_required: bool_key(section, "minimum_output_required", true),
            max_response_bytes: parse_usize_key(section, "max_response_bytes", 1_000_000)?,
            max_output_chars: parse_usize_key(section, "max_output_chars", 3000)?,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QuoteRequest {
    pub input_mint: String,
    pub output_mint: String,
    pub amount: String,
    pub slippage_bps: u16,
    pub only_direct_routes: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QuoteResponse {
    pub input_mint: String,
    pub output_mint: String,
    pub in_amount: String,
    pub out_amount: String,
    pub other_amount_threshold: String,
    pub price_impact_pct: String,
    #[serde(default)]
    pub route_plan: Vec<RouteLeg>,
    #[serde(default)]
    pub raw: Value,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RouteLeg {
    #[serde(default)]
    pub input_mint: Option<String>,
    #[serde(default)]
    pub output_mint: Option<String>,
    #[serde(default)]
    pub amm_key: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SwapRequest {
    pub user_public_key: String,
    pub quote: QuoteResponse,
    pub memo: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SwapResponse {
    pub swap_transaction: String,
}

pub trait JupiterClient {
    fn get_quote(&self, request: QuoteRequest) -> Result<QuoteResponse, SolSafeError>;
    fn build_swap(&self, request: SwapRequest) -> Result<SwapResponse, SolSafeError>;
}

#[derive(Clone, Serialize)]
pub struct JupiterBuildReport {
    pub verdict: Verdict,
    pub custody_tier: String,
    pub summary: String,
    pub quote: Option<Value>,
    pub audit: AuditReport,
    pub unsigned_transaction_base64: Option<String>,
    pub approval_text: String,
}

pub fn jupiter_build_json(
    args: &str,
    jupiter: &dyn JupiterClient,
    rpc: Option<&dyn RpcClient>,
) -> Result<String, SolSafeError> {
    if args.chars().count() > AuditPolicy::default().max_input_chars {
        return Err(SolSafeError::Input(
            "arguments exceed maximum size".to_string(),
        ));
    }
    let input: JupiterInput = serde_json::from_str(args)
        .map_err(|e| SolSafeError::Input(format!("invalid JSON: {e}")))?;
    let policy = JupiterPolicy::from_section(&input.config)?;
    validate_jupiter_input(&input, &policy)?;
    let raw_amount = if input.amount_type == "ui" {
        let decimals = resolve_decimals(&input.input_mint, rpc)?;
        ui_to_raw(&input.amount, decimals)?
    } else {
        parse_decimal_integer(&input.amount)?
    };
    enforce_amount_limit(&input, &policy, raw_amount)?;
    let quote_req = QuoteRequest {
        input_mint: input.input_mint.clone(),
        output_mint: input.output_mint.clone(),
        amount: raw_amount.to_string(),
        slippage_bps: input.slippage_bps,
        only_direct_routes: input.only_direct_routes || policy.only_direct_routes,
    };
    let quote = jupiter.get_quote(quote_req)?;
    validate_quote(&input, &policy, raw_amount, &quote)?;
    let swap = jupiter.build_swap(SwapRequest {
        user_public_key: input.user_public_key.clone(),
        quote: quote.clone(),
        memo: input.memo.clone(),
    })?;
    if swap.swap_transaction.is_empty() {
        return Err(SolSafeError::Jupiter(
            "swap transaction missing".to_string(),
        ));
    }
    let declared = DeclaredIntent {
        action: Some("swap".to_string()),
        input_mint: Some(input.input_mint.clone()),
        output_mint: Some(input.output_mint.clone()),
        amount: Some(raw_amount.to_string()),
        max_amount: Some(raw_amount.to_string()),
        expected_recipient: None,
        expected_programs: vec![JUPITER_V6_PROGRAM.to_string()],
        expected_signer: Some(input.user_public_key),
        memo: input.memo,
    };
    let audit = audit_transaction(
        &swap.swap_transaction,
        &declared,
        &AuditOptions {
            simulate: true,
            strict: true,
        },
        &policy.audit_policy,
        true,
        rpc,
    );
    let verdict = audit.verdict;
    let unsigned_transaction_base64 = (verdict != Verdict::Red).then_some(swap.swap_transaction);
    let report = JupiterBuildReport {
        verdict,
        custody_tier: "T1".to_string(),
        summary: match verdict {
            Verdict::Green => "Guarded unsigned Jupiter swap built and audited.".to_string(),
            Verdict::Amber => {
                "Guarded unsigned Jupiter swap built but requires human attention.".to_string()
            }
            Verdict::Red => "Jupiter swap rejected by SolSafe audit or policy.".to_string(),
        },
        quote: Some(json!({
            "input_mint": quote.input_mint,
            "output_mint": quote.output_mint,
            "in_amount": quote.in_amount,
            "out_amount": quote.out_amount,
            "other_amount_threshold": quote.other_amount_threshold,
            "price_impact_pct": quote.price_impact_pct,
            "route_hops": quote.route_plan.len()
        })),
        audit,
        unsigned_transaction_base64,
        approval_text: match verdict {
            Verdict::Green => {
                "APPROVED FOR HUMAN REVIEW: unsigned Jupiter swap is ready for host approval."
            }
            Verdict::Amber => "REVIEW REQUIRED: unsigned Jupiter swap has warnings.",
            Verdict::Red => "REJECTED: no approval-ready transaction returned.",
        }
        .to_string(),
    };
    let out = serde_json::to_string(&report).map_err(|e| SolSafeError::Output(e.to_string()))?;
    if out.chars().count() > policy.max_output_chars {
        let compact = json!({
            "verdict": report.verdict,
            "custody_tier": "T1",
            "summary": report.summary,
            "audit": {
                "verdict": report.audit.verdict,
                "findings": report.audit.findings,
                "approval_text": report.audit.approval_text
            },
            "unsigned_transaction_base64": report.unsigned_transaction_base64,
            "approval_text": report.approval_text
        });
        return Ok(compact.to_string());
    }
    Ok(out)
}

fn validate_jupiter_input(
    input: &JupiterInput,
    policy: &JupiterPolicy,
) -> Result<(), SolSafeError> {
    validate_address(&input.user_public_key)?;
    validate_address(&input.input_mint)?;
    validate_address(&input.output_mint)?;
    if input.input_mint == input.output_mint {
        return Err(SolSafeError::Input(
            "input and output mints must differ".to_string(),
        ));
    }
    if input.amount_type != "raw" && input.amount_type != "ui" {
        return Err(SolSafeError::Input(
            "amount_type must be raw or ui".to_string(),
        ));
    }
    if input.slippage_bps > policy.max_slippage_bps {
        return Err(SolSafeError::Policy(
            "slippage exceeds configured maximum".to_string(),
        ));
    }
    if !policy.allowed_input_mints.is_empty()
        && !policy.allowed_input_mints.contains(&input.input_mint)
    {
        return Err(SolSafeError::Policy(
            "input mint is not allowed".to_string(),
        ));
    }
    if !policy.allowed_output_mints.is_empty()
        && !policy.allowed_output_mints.contains(&input.output_mint)
    {
        return Err(SolSafeError::Policy(
            "output mint is not allowed".to_string(),
        ));
    }
    if let Some(memo) = &input.memo {
        if memo.chars().count() > 180 || memo.chars().any(char::is_control) {
            return Err(SolSafeError::Input("memo is invalid".to_string()));
        }
    }
    Ok(())
}

fn validate_quote(
    input: &JupiterInput,
    policy: &JupiterPolicy,
    raw_amount: u128,
    quote: &QuoteResponse,
) -> Result<(), SolSafeError> {
    if quote.input_mint != input.input_mint {
        return Err(SolSafeError::Jupiter(
            "quote input mint mismatch".to_string(),
        ));
    }
    if quote.output_mint != input.output_mint {
        return Err(SolSafeError::Jupiter(
            "quote output mint mismatch".to_string(),
        ));
    }
    if parse_decimal_integer(&quote.in_amount)? != raw_amount {
        return Err(SolSafeError::Jupiter(
            "quote input amount mismatch".to_string(),
        ));
    }
    if parse_decimal_integer(&quote.out_amount)? == 0
        || parse_decimal_integer(&quote.other_amount_threshold)? == 0
    {
        return Err(SolSafeError::Jupiter(
            "quote output amount missing".to_string(),
        ));
    }
    if parse_price_bps(Some(&quote.price_impact_pct), 0)? > policy.max_price_impact_bps {
        return Err(SolSafeError::Policy(
            "price impact exceeds configured maximum".to_string(),
        ));
    }
    if quote.route_plan.len() > policy.max_route_hops {
        return Err(SolSafeError::Policy("route has too many hops".to_string()));
    }
    for leg in &quote.route_plan {
        for mint in [&leg.input_mint, &leg.output_mint].into_iter().flatten() {
            if mint != &input.input_mint
                && mint != &input.output_mint
                && !policy.allowed_intermediate_mints.is_empty()
                && !policy.allowed_intermediate_mints.contains(mint)
            {
                return Err(SolSafeError::Policy(
                    "intermediate mint is not allowed".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn resolve_decimals(mint: &str, rpc: Option<&dyn RpcClient>) -> Result<u8, SolSafeError> {
    let Some(client) = rpc else {
        return Err(SolSafeError::Rpc(
            "UI amount conversion requires RPC token decimals".to_string(),
        ));
    };
    let v = client.call("getTokenSupply", json!([mint]))?;
    let decimals = v
        .pointer("/value/decimals")
        .or_else(|| v.pointer("/result/value/decimals"))
        .and_then(Value::as_u64)
        .ok_or_else(|| SolSafeError::Rpc("token decimals missing from RPC response".to_string()))?;
    u8::try_from(decimals).map_err(|_| SolSafeError::Rpc("token decimals out of range".to_string()))
}

pub fn ui_to_raw(amount: &str, decimals: u8) -> Result<u128, SolSafeError> {
    if decimals > 38 {
        return Err(SolSafeError::Input("token decimals too large".to_string()));
    }
    if amount.starts_with('-') {
        return Err(SolSafeError::Input(
            "amount must not be negative".to_string(),
        ));
    }
    let (whole, frac) = amount.split_once('.').unwrap_or((amount, ""));
    if whole.is_empty() && frac.is_empty() {
        return Err(SolSafeError::Input("amount is empty".to_string()));
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(SolSafeError::Input(
            "amount is not a decimal string".to_string(),
        ));
    }
    if frac.len() > decimals as usize {
        return Err(SolSafeError::Input(
            "amount has too much decimal precision".to_string(),
        ));
    }
    let scale = 10u128
        .checked_pow(decimals as u32)
        .ok_or_else(|| SolSafeError::Input("decimal scale overflow".to_string()))?;
    let whole_raw = whole
        .parse::<u128>()
        .map_err(|_| SolSafeError::Input("amount is too large".to_string()))?
        .checked_mul(scale)
        .ok_or_else(|| SolSafeError::Input("amount overflow".to_string()))?;
    let mut frac_s = frac.to_string();
    while frac_s.len() < decimals as usize {
        frac_s.push('0');
    }
    let frac_raw = if frac_s.is_empty() {
        0
    } else {
        frac_s
            .parse::<u128>()
            .map_err(|_| SolSafeError::Input("fraction is too large".to_string()))?
    };
    let raw = whole_raw
        .checked_add(frac_raw)
        .ok_or_else(|| SolSafeError::Input("amount overflow".to_string()))?;
    if raw == 0 {
        return Err(SolSafeError::Input(
            "amount must be greater than zero".to_string(),
        ));
    }
    Ok(raw)
}

fn enforce_amount_limit(
    input: &JupiterInput,
    policy: &JupiterPolicy,
    raw_amount: u128,
) -> Result<(), SolSafeError> {
    if raw_amount == 0 {
        return Err(SolSafeError::Input(
            "amount must be greater than zero".to_string(),
        ));
    }
    if let Some(max) = policy.max_raw_amount_by_mint.get(&input.input_mint) {
        if raw_amount > *max {
            return Err(SolSafeError::Policy(
                "requested amount exceeds configured maximum".to_string(),
            ));
        }
    }
    if let Some(max_ui) = policy.max_ui_amount_by_mint.get(&input.input_mint) {
        if input.amount_type == "ui" {
            let decimals = 9;
            let requested = ui_to_raw(&input.amount, decimals)?;
            let max = ui_to_raw(max_ui, decimals)?;
            if requested > max {
                return Err(SolSafeError::Policy(
                    "requested UI amount exceeds configured maximum".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub fn validate_address(s: &str) -> Result<(), SolSafeError> {
    if s.len() < 32 || s.len() > 44 {
        return Err(SolSafeError::Input(
            "invalid base58 address length".to_string(),
        ));
    }
    let decoded = bs58::decode(s)
        .into_vec()
        .map_err(|_| SolSafeError::Input("invalid base58 address".to_string()))?;
    if decoded.len() != 32 {
        return Err(SolSafeError::Input(
            "base58 address is not 32 bytes".to_string(),
        ));
    }
    Ok(())
}

pub fn redact_url(input: &str) -> String {
    let mut out = input.to_string();
    if let Some(q) = out.find('?') {
        out.truncate(q);
        out.push_str("?[redacted]");
    }
    for marker in ["/api-key/", "/apikey/", "/token/"] {
        if let Some(i) = out.to_ascii_lowercase().find(marker) {
            out.truncate(i + marker.len());
            out.push_str("[redacted]");
        }
    }
    out
}

fn validate_intent(intent: &DeclaredIntent) -> Result<(), SolSafeError> {
    for v in [
        &intent.input_mint,
        &intent.output_mint,
        &intent.expected_recipient,
        &intent.expected_signer,
    ]
    .into_iter()
    .flatten()
    {
        validate_address(v)?;
    }
    for p in &intent.expected_programs {
        validate_address(p)?;
    }
    for amount in [&intent.amount, &intent.max_amount].into_iter().flatten() {
        parse_decimal_string(amount)?;
    }
    if let Some(memo) = &intent.memo {
        if memo.chars().count() > 180 || memo.chars().any(char::is_control) {
            return Err(SolSafeError::Input("memo is invalid".to_string()));
        }
    }
    Ok(())
}

fn parse_decimal_string(s: &str) -> Result<(), SolSafeError> {
    if s.starts_with('-') || s.is_empty() {
        return Err(SolSafeError::Input(
            "amount must be a non-negative decimal string".to_string(),
        ));
    }
    if !s.chars().all(|c| c.is_ascii_digit() || c == '.') || s.matches('.').count() > 1 {
        return Err(SolSafeError::Input("amount is malformed".to_string()));
    }
    Ok(())
}

fn parse_decimal_integer(s: &str) -> Result<u128, SolSafeError> {
    if s.starts_with('-') || s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(SolSafeError::Input(
            "amount must be a raw integer string".to_string(),
        ));
    }
    let n = s
        .parse::<u128>()
        .map_err(|_| SolSafeError::Input("amount is too large".to_string()))?;
    if n == 0 {
        return Err(SolSafeError::Input(
            "amount must be greater than zero".to_string(),
        ));
    }
    Ok(n)
}

fn program_label(program_id: &str, allowed: &HashSet<String>) -> (&'static str, bool) {
    match program_id {
        SYSTEM_PROGRAM => ("System Program", true),
        SPL_TOKEN_PROGRAM => ("SPL Token Program", true),
        TOKEN_2022_PROGRAM => ("Token-2022 Program", true),
        ATA_PROGRAM => ("Associated Token Account Program", true),
        COMPUTE_BUDGET_PROGRAM => ("Compute Budget Program", true),
        MEMO_PROGRAM | MEMO_LEGACY_PROGRAM => ("Memo Program", true),
        ADDRESS_LOOKUP_TABLE_PROGRAM => ("Address Lookup Table Program", true),
        JUPITER_V6_PROGRAM => ("Jupiter Aggregator v6", true),
        _ if allowed.contains(program_id) => ("Configured Program", true),
        _ => ("Unknown Program", false),
    }
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn nonempty<'a>(section: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    section
        .get(key)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
}

fn bool_key(section: &HashMap<String, String>, key: &str, default: bool) -> bool {
    section
        .get(key)
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(default)
}

fn parse_u64_key(
    section: &HashMap<String, String>,
    key: &str,
    default: u64,
) -> Result<u64, SolSafeError> {
    section
        .get(key)
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.parse()
                .map_err(|_| SolSafeError::Config(format!("{key} must be u64")))
        })
        .unwrap_or(Ok(default))
}

fn parse_u16_key(
    section: &HashMap<String, String>,
    key: &str,
    default: u16,
) -> Result<u16, SolSafeError> {
    section
        .get(key)
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.parse()
                .map_err(|_| SolSafeError::Config(format!("{key} must be u16")))
        })
        .unwrap_or(Ok(default))
}

fn parse_usize_key(
    section: &HashMap<String, String>,
    key: &str,
    default: usize,
) -> Result<usize, SolSafeError> {
    section
        .get(key)
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.parse()
                .map_err(|_| SolSafeError::Config(format!("{key} must be usize")))
        })
        .unwrap_or(Ok(default))
}

fn parse_u64_opt(
    section: &HashMap<String, String>,
    key: &str,
) -> Result<Option<u64>, SolSafeError> {
    section
        .get(key)
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.parse()
                .map(Some)
                .map_err(|_| SolSafeError::Config(format!("{key} must be u64")))
        })
        .unwrap_or(Ok(None))
}

fn parse_u128_opt(
    section: &HashMap<String, String>,
    key: &str,
) -> Result<Option<u128>, SolSafeError> {
    section
        .get(key)
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.parse()
                .map(Some)
                .map_err(|_| SolSafeError::Config(format!("{key} must be u128")))
        })
        .unwrap_or(Ok(None))
}

fn parse_address_set(v: Option<&String>) -> Result<HashSet<String>, SolSafeError> {
    let mut set = HashSet::new();
    if let Some(v) = v {
        for item in split_list(v) {
            validate_address(item)?;
            set.insert(item.to_string());
        }
    }
    Ok(set)
}

fn extend_addresses(
    section: &HashMap<String, String>,
    key: &str,
    set: &mut HashSet<String>,
) -> Result<(), SolSafeError> {
    if let Some(v) = section.get(key) {
        for item in split_list(v) {
            validate_address(item)?;
            set.insert(item.to_string());
        }
    }
    Ok(())
}

fn split_list(v: &str) -> impl Iterator<Item = &str> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn parse_amount_map(v: Option<&String>) -> Result<HashMap<String, u128>, SolSafeError> {
    let mut map = HashMap::new();
    if let Some(v) = v {
        let parsed: HashMap<String, String> = serde_json::from_str(v)
            .map_err(|_| SolSafeError::Config("amount map must be JSON object".to_string()))?;
        for (k, val) in parsed {
            validate_address(&k)?;
            map.insert(k, parse_decimal_integer(&val)?);
        }
    }
    Ok(map)
}

fn parse_string_map(v: Option<&String>) -> Result<HashMap<String, String>, SolSafeError> {
    let mut map = HashMap::new();
    if let Some(v) = v {
        let parsed: HashMap<String, String> = serde_json::from_str(v)
            .map_err(|_| SolSafeError::Config("string map must be JSON object".to_string()))?;
        for (k, val) in parsed {
            validate_address(&k)?;
            parse_decimal_string(&val)?;
            map.insert(k, val);
        }
    }
    Ok(map)
}

fn parse_price_bps(v: Option<&String>, default: u32) -> Result<u32, SolSafeError> {
    let Some(v) = v.filter(|s| !s.is_empty()) else {
        return Ok(default);
    };
    let (whole, frac) = v.split_once('.').unwrap_or((v, ""));
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(SolSafeError::Config(
            "price impact must be decimal percent".to_string(),
        ));
    }
    let whole_bps = whole
        .parse::<u32>()
        .map_err(|_| SolSafeError::Config("price impact too large".to_string()))?
        .checked_mul(100)
        .ok_or_else(|| SolSafeError::Config("price impact overflow".to_string()))?;
    let frac_two = frac.chars().take(2).collect::<String>();
    let frac_bps = if frac_two.is_empty() {
        0
    } else {
        let mut padded = frac_two;
        while padded.len() < 2 {
            padded.push('0');
        }
        padded
            .parse::<u32>()
            .map_err(|_| SolSafeError::Config("price impact fraction invalid".to_string()))?
    };
    whole_bps
        .checked_add(frac_bps)
        .ok_or_else(|| SolSafeError::Config("price impact overflow".to_string()))
}
