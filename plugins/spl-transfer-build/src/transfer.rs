//! Host-testable validation, transaction construction, final-byte verification,
//! simulation, and summary construction.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    str::FromStr,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use nanosol::{
    amount::{format_ui_amount, parse_ui_amount, AmountError},
    inspect::{
        decode_ata_create_idempotent, decode_memo, decode_transfer_checked,
        decode_unsigned_v0_transaction,
    },
    instruction::{
        create_associated_token_account_idempotent, memo as memo_instruction, transfer_checked,
        AccountMeta, TokenProgram,
    },
    message::{Message, MessageVersion, Transaction, MAX_TRANSACTION_BYTES},
    mint::{parse_mint_account, MintInfo},
    pubkey::{derive_associated_token_address, Pubkey},
    reference::derive_payment_reference,
    rpc::{
        get_account_info_request, get_latest_blockhash_request, parse_account_info_response,
        parse_latest_blockhash_response, parse_simulation_response, simulate_transaction_request,
        RpcError, MAX_RPC_RESPONSE_BYTES,
    },
    shape::{elide_address, quote_untrusted, single_line},
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::rpc::{RpcTransport, TransportError};

pub const MAX_TOOL_OUTPUT_BYTES: usize = 4_000;
pub const MAX_ERROR_CHARS: usize = 240;
pub const MAX_RPC_URL_BYTES: usize = 2_048;

const MAX_AMOUNT_BYTES: usize = 64;
const MAX_MEMO_BYTES: usize = 256;
const MAX_INVOICE_BYTES: usize = 128;
const MAX_ALIAS_BYTES: usize = 24;
const MAX_MINTS: usize = 64;
const MAX_RECIPIENTS: usize = 256;
const SUMMARY_MEMO_CHARS: usize = 96;

const MINT_RPC_ID: u64 = 1;
const BLOCKHASH_RPC_ID: u64 = 2;
const SIMULATION_RPC_ID: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPhase {
    ConfigValidated,
    MintRpc,
    BlockhashRpc,
    TransactionBuilt,
    VerificationPassed,
    SimulationRpc,
    SimulationPassed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferArgs {
    pub recipient: String,
    pub amount: String,
    pub mint: String,
    pub memo: Option<String>,
    pub invoice_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferOutput {
    pub transaction_base64: String,
    pub summary: String,
    pub last_valid_block_height: u64,
    pub blockhash_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResponse {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

impl ToolResponse {
    fn success(output: String) -> Self {
        Self {
            success: true,
            output,
            error: None,
        }
    }

    fn refusal(error: impl fmt::Display) -> Self {
        Self {
            success: false,
            output: String::new(),
            error: Some(single_line(&error.to_string(), MAX_ERROR_CHARS)),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentArgs {
    recipient: String,
    amount: String,
    mint: String,
    #[serde(default)]
    memo: Option<String>,
    #[serde(default)]
    invoice_id: Option<String>,
    // Not present in the public schema. The host removes caller-provided
    // `__config`, then injects the resolved operator section at this boundary.
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

impl From<&ComponentArgs> for TransferArgs {
    fn from(value: &ComponentArgs) -> Self {
        Self {
            recipient: value.recipient.clone(),
            amount: value.amount.clone(),
            mint: value.mint.clone(),
            memo: value.memo.clone(),
            invoice_id: value.invoice_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferConfig {
    rpc_url: String,
    sender: Pubkey,
    allowed_mints: BTreeSet<Pubkey>,
    maximum_amounts: BTreeMap<Pubkey, String>,
    aliases: BTreeMap<String, Pubkey>,
    allowed_recipients: Option<BTreeSet<Pubkey>>,
    allow_off_curve_recipients: bool,
    allow_token_2022: bool,
}

impl TransferConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, TransferError> {
        for key in section.keys() {
            if !matches!(
                key.as_str(),
                "rpc_url"
                    | "sender_pubkey"
                    | "mint_allowlist"
                    | "max_amounts"
                    | "mint_aliases"
                    | "recipient_allowlist"
                    | "allow_off_curve_recipients"
                    | "allow_token_2022"
            ) {
                return Err(TransferError::InvalidConfig(
                    "unknown configuration key".to_string(),
                ));
            }
        }

        let rpc_url = required_config(section, "rpc_url")?;
        validate_rpc_url(rpc_url)?;
        let sender = parse_config_pubkey(required_config(section, "sender_pubkey")?, "sender")?;
        if !sender.is_on_curve() {
            return Err(TransferError::InvalidConfig(
                "sender_pubkey must identify an on-curve wallet".to_string(),
            ));
        }

        let allowed_mints = parse_pubkey_set(
            required_config(section, "mint_allowlist")?,
            "mint_allowlist",
            MAX_MINTS,
        )?;
        if allowed_mints.is_empty() {
            return Err(TransferError::InvalidConfig(
                "mint_allowlist must not be empty".to_string(),
            ));
        }

        let cap_entries = parse_assignments(
            required_config(section, "max_amounts")?,
            "max_amounts",
            MAX_MINTS,
        )?;
        let mut maximum_amounts = BTreeMap::new();
        for (mint_text, cap) in cap_entries {
            let mint = parse_config_pubkey(&mint_text, "max_amounts mint")?;
            if cap.len() > MAX_AMOUNT_BYTES {
                return Err(TransferError::InvalidConfig(
                    "maximum amount exceeds 64 bytes".to_string(),
                ));
            }
            validate_decimal_syntax(&cap, "maximum amount").map_err(|_| {
                TransferError::InvalidConfig(
                    "maximum amount has invalid decimal syntax".to_string(),
                )
            })?;
            if decimal_is_zero(&cap) {
                return Err(TransferError::InvalidConfig(
                    "maximum amounts must be greater than zero".to_string(),
                ));
            }
            if maximum_amounts.insert(mint, cap).is_some() {
                return Err(TransferError::InvalidConfig(
                    "max_amounts contains a duplicate mint".to_string(),
                ));
            }
        }
        if maximum_amounts.keys().copied().collect::<BTreeSet<_>>() != allowed_mints {
            return Err(TransferError::InvalidConfig(
                "every allowlisted mint must have exactly one maximum amount".to_string(),
            ));
        }

        let aliases = match section.get("mint_aliases") {
            None => BTreeMap::new(),
            Some(value) => {
                let entries = parse_assignments(value, "mint_aliases", MAX_MINTS)?;
                let mut aliases = BTreeMap::new();
                for (alias, mint_text) in entries {
                    let alias = normalize_alias(&alias)?;
                    let mint = parse_config_pubkey(&mint_text, "mint alias")?;
                    if !allowed_mints.contains(&mint) {
                        return Err(TransferError::InvalidConfig(
                            "mint aliases must target allowlisted mints".to_string(),
                        ));
                    }
                    if aliases.insert(alias, mint).is_some() {
                        return Err(TransferError::InvalidConfig(
                            "mint_aliases contains a duplicate normalized alias".to_string(),
                        ));
                    }
                }
                aliases
            }
        };

        let allowed_recipients = section
            .get("recipient_allowlist")
            .map(|value| parse_pubkey_set(value, "recipient_allowlist", MAX_RECIPIENTS))
            .transpose()?;
        if allowed_recipients.as_ref().is_some_and(BTreeSet::is_empty) {
            return Err(TransferError::InvalidConfig(
                "recipient_allowlist must not be empty when configured".to_string(),
            ));
        }

        let allow_off_curve_recipients = parse_optional_bool(
            section.get("allow_off_curve_recipients"),
            "allow_off_curve_recipients",
        )?;
        let allow_token_2022 =
            parse_optional_bool(section.get("allow_token_2022"), "allow_token_2022")?;

        Ok(Self {
            rpc_url: rpc_url.to_string(),
            sender,
            allowed_mints,
            maximum_amounts,
            aliases,
            allowed_recipients,
            allow_off_curve_recipients,
            allow_token_2022,
        })
    }

    pub fn sender(&self) -> Pubkey {
        self.sender
    }

    fn resolve_mint(&self, input: &str) -> Result<Pubkey, TransferError> {
        let mint = Pubkey::from_str(input).ok().or_else(|| {
            normalize_alias(input)
                .ok()
                .and_then(|alias| self.aliases.get(&alias).copied())
        });
        let mint = mint.ok_or(TransferError::InvalidMint)?;
        if !self.allowed_mints.contains(&mint) {
            return Err(TransferError::MintNotAllowed);
        }
        Ok(mint)
    }

    fn unique_alias(&self, mint: &Pubkey) -> Option<&str> {
        let mut aliases = self
            .aliases
            .iter()
            .filter_map(|(alias, candidate)| (candidate == mint).then_some(alias.as_str()));
        let first = aliases.next()?;
        aliases.next().is_none().then_some(first)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPolicy {
    pub sender: Pubkey,
    pub recipient: Pubkey,
    pub mint: Pubkey,
    pub token_program: TokenProgram,
    pub raw_amount: u64,
    pub decimals: u8,
    pub recent_blockhash: [u8; 32],
    pub reference: Option<Pubkey>,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransfer {
    pub sender: Pubkey,
    pub recipient: Pubkey,
    pub mint: Pubkey,
    pub source_ata: Pubkey,
    pub destination_ata: Pubkey,
    pub token_program: TokenProgram,
    pub raw_amount: u64,
    pub decimals: u8,
    pub reference: Option<Pubkey>,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    InvalidArguments,
    InvalidConfig(String),
    InvalidRecipient,
    OffCurveRecipient,
    SelfTransferUnsupported,
    RecipientNotAllowed,
    InvalidMint,
    MintNotAllowed,
    InvalidAmount(String),
    AmountZero,
    AmountAboveMaximum,
    InvalidMemo,
    InvalidInvoice,
    RpcTransport(TransportError),
    Rpc(RpcError),
    MintState(String),
    Token2022Disabled,
    Token2022ExtensionsDenied,
    TransactionBuild,
    TransactionVerification(String),
    SimulationFailed(String),
    OutputTooLong,
    OutputSerialization,
}

impl TransferError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::InvalidConfig(_) => "invalid_config",
            Self::InvalidRecipient => "invalid_recipient",
            Self::OffCurveRecipient => "off_curve_recipient",
            Self::SelfTransferUnsupported => "self_transfer_unsupported",
            Self::RecipientNotAllowed => "recipient_not_allowed",
            Self::InvalidMint => "invalid_mint",
            Self::MintNotAllowed => "mint_not_allowed",
            Self::InvalidAmount(_) | Self::AmountZero | Self::AmountAboveMaximum => {
                "invalid_amount"
            }
            Self::InvalidMemo => "invalid_memo",
            Self::InvalidInvoice => "invalid_invoice",
            Self::RpcTransport(_) | Self::Rpc(_) => "rpc_failure",
            Self::MintState(_) => "invalid_mint_state",
            Self::Token2022Disabled | Self::Token2022ExtensionsDenied => "token_2022_policy",
            Self::TransactionBuild => "transaction_build",
            Self::TransactionVerification(_) => "transaction_verification",
            Self::SimulationFailed(_) => "simulation_failed",
            Self::OutputTooLong | Self::OutputSerialization => "output_failure",
        }
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => formatter.write_str("invalid tool arguments"),
            Self::InvalidConfig(reason) => write!(formatter, "invalid plugin config: {reason}"),
            Self::InvalidRecipient => {
                formatter.write_str("recipient must be a base58-encoded 32-byte wallet public key")
            }
            Self::OffCurveRecipient => formatter.write_str(
                "recipient is off-curve; operator configuration does not permit off-curve recipients",
            ),
            Self::SelfTransferUnsupported => {
                formatter.write_str("sender and recipient must be different wallets")
            }
            Self::RecipientNotAllowed => {
                formatter.write_str("recipient is not allowed by operator configuration")
            }
            Self::InvalidMint => {
                formatter.write_str("mint must be an allowlisted public key or configured alias")
            }
            Self::MintNotAllowed => {
                formatter.write_str("mint is not allowed by operator configuration")
            }
            Self::InvalidAmount(reason) => write!(formatter, "invalid amount: {reason}"),
            Self::AmountZero => formatter.write_str("amount must be greater than zero"),
            Self::AmountAboveMaximum => {
                formatter.write_str("amount exceeds the operator-configured maximum")
            }
            Self::InvalidMemo => formatter.write_str("memo is empty or exceeds 256 bytes"),
            Self::InvalidInvoice => {
                formatter.write_str("invoice_id is empty, malformed, or exceeds 128 bytes")
            }
            Self::RpcTransport(error) => error.fmt(formatter),
            Self::Rpc(error) => error.fmt(formatter),
            Self::MintState(reason) => write!(formatter, "mint account refused: {reason}"),
            Self::Token2022Disabled => formatter.write_str(
                "Token-2022 mint refused; operator must explicitly enable extension-free Token-2022",
            ),
            Self::Token2022ExtensionsDenied => formatter.write_str(
                "Token-2022 mint extensions are outside the supported safe subset",
            ),
            Self::TransactionBuild => formatter.write_str("could not build supported transaction"),
            Self::TransactionVerification(reason) => {
                write!(formatter, "final transaction verification failed: {reason}")
            }
            Self::SimulationFailed(reason) => write!(formatter, "simulation failed: {reason}"),
            Self::OutputTooLong => formatter.write_str("tool output exceeds the 4000-byte limit"),
            Self::OutputSerialization => formatter.write_str("could not serialize tool output"),
        }
    }
}

impl std::error::Error for TransferError {}

impl From<TransportError> for TransferError {
    fn from(error: TransportError) -> Self {
        Self::RpcTransport(error)
    }
}

impl From<RpcError> for TransferError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

/// Parse the host envelope. User/config/policy/RPC failures are model-visible
/// refusals rather than component faults.
pub fn execute_component_input(input: &str, transport: &impl RpcTransport) -> ToolResponse {
    execute_component_input_observed(input, transport, |_| {})
}

pub fn execute_component_input_observed(
    input: &str,
    transport: &impl RpcTransport,
    mut observer: impl FnMut(ExecutionPhase),
) -> ToolResponse {
    let parsed: ComponentArgs = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(_) => return ToolResponse::refusal(TransferError::InvalidArguments),
    };
    let config = match TransferConfig::from_section(&parsed.config) {
        Ok(value) => value,
        Err(error) => return ToolResponse::refusal(error),
    };
    observer(ExecutionPhase::ConfigValidated);
    match build_transfer_observed(
        TransferArgs::from(&parsed),
        &config,
        transport,
        &mut observer,
    )
    .and_then(serialize_output)
    {
        Ok(output) => ToolResponse::success(output),
        Err(error) => ToolResponse::refusal(error),
    }
}

pub fn build_transfer(
    args: TransferArgs,
    config: &TransferConfig,
    transport: &impl RpcTransport,
) -> Result<TransferOutput, TransferError> {
    build_transfer_observed(args, config, transport, &mut |_| {})
}

fn build_transfer_observed(
    args: TransferArgs,
    config: &TransferConfig,
    transport: &impl RpcTransport,
    observer: &mut impl FnMut(ExecutionPhase),
) -> Result<TransferOutput, TransferError> {
    validate_decimal_syntax(&args.amount, "amount")?;
    if args.amount.len() > MAX_AMOUNT_BYTES {
        return Err(TransferError::InvalidAmount(
            "decimal string exceeds 64 bytes".to_string(),
        ));
    }
    let memo = validate_optional_text(args.memo, MAX_MEMO_BYTES, TransferError::InvalidMemo)?;
    let invoice_id = validate_invoice(args.invoice_id)?;

    let recipient =
        Pubkey::from_str(&args.recipient).map_err(|_| TransferError::InvalidRecipient)?;
    if recipient == config.sender {
        return Err(TransferError::SelfTransferUnsupported);
    }
    if !config.allow_off_curve_recipients && !recipient.is_on_curve() {
        return Err(TransferError::OffCurveRecipient);
    }
    if config
        .allowed_recipients
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(&recipient))
    {
        return Err(TransferError::RecipientNotAllowed);
    }
    let mint = config.resolve_mint(&args.mint)?;

    observer(ExecutionPhase::MintRpc);
    let mint_body = rpc_post(
        transport,
        &config.rpc_url,
        &get_account_info_request(MINT_RPC_ID, &mint),
    )?;
    let account = parse_account_info_response(&mint_body, MINT_RPC_ID)?;
    let mint_info = parse_mint_account(&account)
        .map_err(|error| TransferError::MintState(single_line(&error.to_string(), 120)))?;
    enforce_token_policy(&mint_info, config)?;

    let raw_amount = parse_ui_amount(&args.amount, mint_info.decimals).map_err(amount_error)?;
    if raw_amount == 0 {
        return Err(TransferError::AmountZero);
    }
    let maximum = config
        .maximum_amounts
        .get(&mint)
        .ok_or_else(|| TransferError::InvalidConfig("selected mint has no maximum".to_string()))?;
    let maximum_raw = parse_ui_amount(maximum, mint_info.decimals).map_err(|error| {
        TransferError::InvalidConfig(format!(
            "selected mint maximum is incompatible with on-chain decimals: {error}"
        ))
    })?;
    if raw_amount > maximum_raw {
        return Err(TransferError::AmountAboveMaximum);
    }
    let canonical_amount =
        format_ui_amount(raw_amount, mint_info.decimals).map_err(amount_error)?;

    observer(ExecutionPhase::BlockhashRpc);
    let blockhash_body = rpc_post(
        transport,
        &config.rpc_url,
        &get_latest_blockhash_request(BLOCKHASH_RPC_ID),
    )?;
    let latest = parse_latest_blockhash_response(&blockhash_body, BLOCKHASH_RPC_ID)?;

    let reference = invoice_id.as_deref().map(|invoice| {
        derive_payment_reference(&recipient, Some(&mint), &canonical_amount, invoice)
    });
    let policy = VerificationPolicy {
        sender: config.sender,
        recipient,
        mint,
        token_program: mint_info.token_program,
        raw_amount,
        decimals: mint_info.decimals,
        recent_blockhash: latest.blockhash,
        reference,
        memo,
    };
    let bytes = build_unsigned_bytes(&policy)?;
    observer(ExecutionPhase::TransactionBuilt);
    let verified = verify_final_bytes(&bytes, &policy)?;
    observer(ExecutionPhase::VerificationPassed);
    let transaction_base64 = STANDARD.encode(&bytes);

    observer(ExecutionPhase::SimulationRpc);
    let simulation_body = rpc_post(
        transport,
        &config.rpc_url,
        &simulate_transaction_request(SIMULATION_RPC_ID, &transaction_base64),
    )?;
    let simulation = parse_simulation_response(&simulation_body, SIMULATION_RPC_ID)?;
    if let Some(reason) = simulation.error {
        return Err(TransferError::SimulationFailed(reason));
    }
    observer(ExecutionPhase::SimulationPassed);

    let summary = approval_summary(
        &verified,
        config.unique_alias(&verified.mint),
        latest.last_valid_block_height,
    )?;
    Ok(TransferOutput {
        transaction_base64,
        summary,
        last_valid_block_height: latest.last_valid_block_height,
        blockhash_mode: "recent".to_string(),
        reference: verified.reference.map(|value| value.to_string()),
    })
}

pub fn build_unsigned_bytes(policy: &VerificationPolicy) -> Result<Vec<u8>, TransferError> {
    let (create, destination) = create_associated_token_account_idempotent(
        policy.sender,
        policy.recipient,
        policy.mint,
        policy.token_program,
    )
    .map_err(|_| TransferError::TransactionBuild)?;
    let (source, _) =
        derive_associated_token_address(&policy.sender, &policy.mint, &policy.token_program.id())
            .map_err(|_| TransferError::TransactionBuild)?;
    let mut transfer = transfer_checked(
        source,
        policy.mint,
        destination,
        policy.sender,
        policy.raw_amount,
        policy.decimals,
        policy.token_program,
    );
    if let Some(reference) = policy.reference {
        transfer
            .accounts
            .push(AccountMeta::readonly(reference, false));
    }
    let mut instructions = vec![create, transfer];
    if let Some(memo) = &policy.memo {
        instructions.push(memo_instruction(memo));
    }
    let message = Message::compile(
        MessageVersion::V0,
        policy.sender,
        policy.recent_blockhash,
        &instructions,
    )
    .map_err(|_| TransferError::TransactionBuild)?;
    Transaction::new_unsigned(message)
        .serialize()
        .map_err(|_| TransferError::TransactionBuild)
}

/// Decode and semantically verify the exact final bytes that will be returned.
/// Recompiling the decoded instructions and comparing the whole message also
/// rejects unused keys, privilege changes, non-canonical ordering, and extras.
pub fn verify_final_bytes(
    bytes: &[u8],
    policy: &VerificationPolicy,
) -> Result<VerifiedTransfer, TransferError> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return verification_refusal("transaction exceeds the Solana packet limit");
    }
    let transaction = decode_unsigned_v0_transaction(bytes)
        .map_err(|_| TransferError::TransactionVerification("wire decoding refused".to_string()))?;
    let message = &transaction.message;
    if transaction.signatures.len() != 1
        || message.header.num_required_signatures != 1
        || message.header.num_readonly_signed_accounts != 0
        || message.account_keys.first() != Some(&policy.sender)
    {
        return verification_refusal("fee payer or signer set differs from policy");
    }
    if message.recent_blockhash != policy.recent_blockhash {
        return verification_refusal("recent blockhash differs from verified RPC value");
    }
    let expected_instruction_count = 2 + usize::from(policy.memo.is_some());
    if message.instructions.len() != expected_instruction_count {
        return verification_refusal("instruction count is outside the supported subset");
    }

    let create = decode_ata_create_idempotent(message, 0).map_err(|_| {
        TransferError::TransactionVerification("ATA instruction refused".to_string())
    })?;
    let transfer = decode_transfer_checked(message, 1).map_err(|_| {
        TransferError::TransactionVerification("TransferChecked instruction refused".to_string())
    })?;
    let decoded_memo = if policy.memo.is_some() {
        Some(decode_memo(message, 2).map_err(|_| {
            TransferError::TransactionVerification("memo instruction refused".to_string())
        })?)
    } else {
        None
    };

    if create.payer != policy.sender
        || create.owner != policy.recipient
        || create.mint != policy.mint
        || create.token_program != policy.token_program
        || transfer.authority != policy.sender
        || transfer.mint != policy.mint
        || transfer.token_program != policy.token_program
        || transfer.amount != policy.raw_amount
        || transfer.decimals != policy.decimals
        || transfer.reference != policy.reference
        || decoded_memo != policy.memo
    {
        return verification_refusal("decoded transfer fields differ from policy");
    }

    let (expected_source, _) = derive_associated_token_address(
        &transfer.authority,
        &transfer.mint,
        &transfer.token_program.id(),
    )
    .map_err(|_| {
        TransferError::TransactionVerification("source ATA derivation failed".to_string())
    })?;
    let (expected_destination, _) =
        derive_associated_token_address(&create.owner, &create.mint, &create.token_program.id())
            .map_err(|_| {
                TransferError::TransactionVerification(
                    "destination ATA derivation failed".to_string(),
                )
            })?;
    if transfer.source != expected_source
        || create.ata != expected_destination
        || transfer.destination != expected_destination
    {
        return verification_refusal("decoded associated token accounts differ from derivation");
    }

    let reconstructed =
        reconstruct_message(&transaction, &create, &transfer, decoded_memo.as_deref())?;
    if reconstructed != *message {
        return verification_refusal("message contains non-canonical keys, flags, or structure");
    }

    Ok(VerifiedTransfer {
        sender: transfer.authority,
        recipient: create.owner,
        mint: transfer.mint,
        source_ata: transfer.source,
        destination_ata: transfer.destination,
        token_program: transfer.token_program,
        raw_amount: transfer.amount,
        decimals: transfer.decimals,
        reference: transfer.reference,
        memo: decoded_memo,
    })
}

fn reconstruct_message(
    transaction: &Transaction,
    create: &nanosol::inspect::DecodedAtaCreateIdempotent,
    transfer: &nanosol::inspect::DecodedTransferChecked,
    memo: Option<&str>,
) -> Result<Message, TransferError> {
    let (create_instruction, derived_destination) = create_associated_token_account_idempotent(
        create.payer,
        create.owner,
        create.mint,
        create.token_program,
    )
    .map_err(|_| TransferError::TransactionVerification("ATA reconstruction failed".to_string()))?;
    if derived_destination != create.ata {
        return verification_refusal("ATA instruction contains a non-derived address");
    }
    let mut transfer_instruction = transfer_checked(
        transfer.source,
        transfer.mint,
        transfer.destination,
        transfer.authority,
        transfer.amount,
        transfer.decimals,
        transfer.token_program,
    );
    if let Some(reference) = transfer.reference {
        transfer_instruction
            .accounts
            .push(AccountMeta::readonly(reference, false));
    }
    let mut instructions = vec![create_instruction, transfer_instruction];
    if let Some(memo) = memo {
        instructions.push(memo_instruction(memo));
    }
    Message::compile(
        MessageVersion::V0,
        create.payer,
        transaction.message.recent_blockhash,
        &instructions,
    )
    .map_err(|_| {
        TransferError::TransactionVerification("message reconstruction failed".to_string())
    })
}

fn approval_summary(
    transfer: &VerifiedTransfer,
    alias: Option<&str>,
    last_valid_block_height: u64,
) -> Result<String, TransferError> {
    let amount = format_ui_amount(transfer.raw_amount, transfer.decimals).map_err(amount_error)?;
    let mint = elide_address(&transfer.mint);
    let asset = alias
        .map(|alias| format!("{alias} ({mint})"))
        .unwrap_or_else(|| format!("token {mint}"));
    let mut summary = format!(
        "SEND {amount} {asset} to owner {} · destination ATA {} · sender/fee payer {}",
        transfer.recipient,
        elide_address(&transfer.destination_ata),
        elide_address(&transfer.sender),
    );
    if let Some(memo) = &transfer.memo {
        summary.push_str(" · memo ");
        summary.push_str(&quote_untrusted(memo, SUMMARY_MEMO_CHARS));
    }
    if let Some(reference) = transfer.reference {
        summary.push_str(" · reference ");
        summary.push_str(&reference.to_string());
    }
    summary.push_str(&format!(
        " · recent blockhash valid through block height {last_valid_block_height} · UNSIGNED: external approval and signing required; not submitted"
    ));
    Ok(summary)
}

fn enforce_token_policy(mint: &MintInfo, config: &TransferConfig) -> Result<(), TransferError> {
    match mint.token_program {
        TokenProgram::Legacy => Ok(()),
        TokenProgram::Token2022 if !config.allow_token_2022 => {
            Err(TransferError::Token2022Disabled)
        }
        TokenProgram::Token2022 if !mint.extensions.is_empty() => {
            Err(TransferError::Token2022ExtensionsDenied)
        }
        TokenProgram::Token2022 => Ok(()),
    }
}

fn rpc_post(
    transport: &impl RpcTransport,
    endpoint: &str,
    request: &str,
) -> Result<String, TransferError> {
    transport
        .post(endpoint, request, MAX_RPC_RESPONSE_BYTES)
        .map_err(TransferError::from)
}

fn serialize_output(output: TransferOutput) -> Result<String, TransferError> {
    let serialized =
        serde_json::to_string(&output).map_err(|_| TransferError::OutputSerialization)?;
    if serialized.len() >= MAX_TOOL_OUTPUT_BYTES {
        return Err(TransferError::OutputTooLong);
    }
    Ok(serialized)
}

pub fn parameters_schema() -> String {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "recipient": {
                "type": "string",
                "minLength": 32,
                "maxLength": 44,
                "description": "Recipient wallet public key; do not supply a token account."
            },
            "amount": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_AMOUNT_BYTES,
                "pattern": "^[0-9]+(?:\\.[0-9]+)?$",
                "description": "Exact UI amount as an unsigned decimal string. Decimals come from the mint account."
            },
            "mint": {
                "type": "string",
                "minLength": 1,
                "maxLength": 44,
                "description": "Allowlisted SPL mint public key or operator-configured alias."
            },
            "memo": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_MEMO_BYTES,
                "description": "Optional public on-chain memo. Never include secrets."
            },
            "invoice_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_INVOICE_BYTES,
                "description": "Optional invoice identifier used for the deterministic Solana Pay reference account."
            }
        },
        "required": ["recipient", "amount", "mint"]
    })
    .to_string()
}

fn required_config<'a>(
    section: &'a HashMap<String, String>,
    key: &'static str,
) -> Result<&'a str, TransferError> {
    section
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| TransferError::InvalidConfig(format!("missing or empty {key}")))
}

fn validate_rpc_url(value: &str) -> Result<(), TransferError> {
    if value.len() > MAX_RPC_URL_BYTES
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || value.contains('\\')
    {
        return Err(TransferError::InvalidConfig(
            "rpc_url is malformed or too long".to_string(),
        ));
    }
    let parsed = Url::parse(value)
        .map_err(|_| TransferError::InvalidConfig("rpc_url is malformed".to_string()))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(TransferError::InvalidConfig(
            "rpc_url must be HTTPS without credentials or a fragment".to_string(),
        ));
    }
    Ok(())
}

fn parse_config_pubkey(value: &str, field: &str) -> Result<Pubkey, TransferError> {
    Pubkey::from_str(value).map_err(|_| {
        TransferError::InvalidConfig(format!("{field} contains an invalid public key"))
    })
}

fn parse_pubkey_set(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<BTreeSet<Pubkey>, TransferError> {
    let entries = split_strict_list(value, field, maximum)?;
    let mut output = BTreeSet::new();
    for entry in entries {
        let key = parse_config_pubkey(entry, field)?;
        if !output.insert(key) {
            return Err(TransferError::InvalidConfig(format!(
                "{field} contains a duplicate entry"
            )));
        }
    }
    Ok(output)
}

fn parse_assignments(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<Vec<(String, String)>, TransferError> {
    let entries = split_strict_list(value, field, maximum)?;
    let mut output = Vec::with_capacity(entries.len());
    let mut seen = BTreeSet::new();
    for entry in entries {
        let (key, assigned) = entry.split_once('=').ok_or_else(|| {
            TransferError::InvalidConfig(format!("{field} entries must use NAME=value"))
        })?;
        if key.is_empty() || assigned.is_empty() || assigned.contains('=') {
            return Err(TransferError::InvalidConfig(format!(
                "{field} contains a malformed assignment"
            )));
        }
        if !seen.insert(key) {
            return Err(TransferError::InvalidConfig(format!(
                "{field} contains a duplicate key"
            )));
        }
        output.push((key.to_string(), assigned.to_string()));
    }
    Ok(output)
}

fn split_strict_list<'a>(
    value: &'a str,
    field: &'static str,
    maximum: usize,
) -> Result<Vec<&'a str>, TransferError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.chars().any(char::is_whitespace) {
        return Err(TransferError::InvalidConfig(format!(
            "{field} must not contain whitespace"
        )));
    }
    let entries: Vec<_> = value.split(',').collect();
    if entries.len() > maximum || entries.iter().any(|entry| entry.is_empty()) {
        return Err(TransferError::InvalidConfig(format!(
            "{field} is empty, malformed, or exceeds {maximum} entries"
        )));
    }
    Ok(entries)
}

fn normalize_alias(alias: &str) -> Result<String, TransferError> {
    if alias.is_empty()
        || alias.len() > MAX_ALIAS_BYTES
        || !alias.is_ascii()
        || !alias
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(TransferError::InvalidConfig(
            "mint alias has invalid syntax".to_string(),
        ));
    }
    Ok(alias.to_ascii_uppercase())
}

fn parse_optional_bool(value: Option<&String>, field: &'static str) -> Result<bool, TransferError> {
    match value.map(String::as_str) {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(TransferError::InvalidConfig(format!(
            "{field} must be exactly true or false"
        ))),
    }
}

fn validate_decimal_syntax(value: &str, field: &str) -> Result<(), TransferError> {
    if value.is_empty() || !value.is_ascii() {
        return Err(TransferError::InvalidAmount(format!(
            "{field} must use ASCII decimal digits"
        )));
    }
    let mut pieces = value.split('.');
    let whole = pieces.next().unwrap_or_default();
    let fraction = pieces.next();
    if pieces.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction
            .is_some_and(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(TransferError::InvalidAmount(format!(
            "{field} must be unsigned decimal digits with an optional fractional part"
        )));
    }
    Ok(())
}

fn decimal_is_zero(value: &str) -> bool {
    value.bytes().all(|byte| matches!(byte, b'0' | b'.'))
}

fn validate_optional_text(
    value: Option<String>,
    maximum: usize,
    error: TransferError,
) -> Result<Option<String>, TransferError> {
    match value {
        None => Ok(None),
        Some(value) if !value.is_empty() && value.len() <= maximum => Ok(Some(value)),
        Some(_) => Err(error),
    }
}

fn validate_invoice(value: Option<String>) -> Result<Option<String>, TransferError> {
    let value = validate_optional_text(value, MAX_INVOICE_BYTES, TransferError::InvalidInvoice)?;
    if value
        .as_deref()
        .is_some_and(|invoice| invoice.chars().any(char::is_control))
    {
        return Err(TransferError::InvalidInvoice);
    }
    Ok(value)
}

fn amount_error(error: AmountError) -> TransferError {
    TransferError::InvalidAmount(error.to_string())
}

fn verification_refusal<T>(reason: &str) -> Result<T, TransferError> {
    Err(TransferError::TransactionVerification(reason.to_string()))
}
