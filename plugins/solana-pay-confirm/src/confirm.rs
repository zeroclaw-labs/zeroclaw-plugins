//! Host-testable Solana Pay payment confirmation.
//!
//! The safety property that shapes this whole module: the payment reference is
//! **derived from the invoice, never accepted as an argument**. A tool that took
//! a `reference` would let a model point it at any payment on chain and get back
//! `paid: true`, which is a confirmation-forgery primitive. Here the reference
//! is `SHA-256` over the same four fields `solana-pay-request` hashed, so a
//! wrong recipient, amount, mint, or invoice id produces a different reference
//! that finds nothing.
//!
//! Nothing is constructed, signed, or submitted, and no byte returned by this
//! tool could ever be signed.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    str::FromStr,
};

use nanosol::{
    amount::{format_ui_amount, parse_ui_amount, AmountError},
    inspect::{
        decode_signed_transaction, find_token_transfers, DecodedTokenTransfer, TokenTransferKind,
    },
    instruction::TokenProgram,
    mint::{parse_mint_account, MintInfo},
    pubkey::{derive_associated_token_address, Pubkey},
    reference::derive_payment_reference,
    rpc::{
        get_account_info_request, get_signatures_for_address_request, get_transaction_request,
        parse_account_info_response, parse_signatures_for_address_response,
        parse_transaction_response, CommitmentLevel, RpcError, SignatureRecord, TransactionRecord,
        MAX_RPC_RESPONSE_BYTES, MAX_TRANSACTION_RESPONSE_BYTES,
    },
    shape::{elide_address, quote_untrusted, single_line},
    signature::Signature,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::rpc::{RpcTransport, TransportError};

pub const MAX_TOOL_OUTPUT_BYTES: usize = 4_000;
pub const MAX_ERROR_CHARS: usize = 240;
pub const MAX_RPC_URL_BYTES: usize = 2_048;
/// Signatures scanned per call when the operator does not choose a window.
pub const DEFAULT_SIGNATURES_SCANNED: u16 = 10;
/// Hard ceiling on the scan window. Each candidate costs one `getTransaction`
/// per configured endpoint, so the window is bounded by code, not only config.
pub const MAX_SIGNATURES_SCANNED: u16 = 25;
/// Total response bytes one call will accept across every read.
///
/// Each individual read is already capped, but a full scan window against two
/// endpoints multiplies that cap by fifty. This budget bounds the whole call, so
/// an endpoint that answers every read at its maximum size cannot turn a bounded
/// window into unbounded parsing inside the host's fuel limit.
pub const MAX_TOTAL_RESPONSE_BYTES: usize = 1_024 * 1_024;

const MAX_AMOUNT_BYTES: usize = 64;
const MAX_INVOICE_BYTES: usize = 128;
const MAX_ALIAS_BYTES: usize = 24;
const MAX_MINTS: usize = 64;
const MAX_RECIPIENTS: usize = 256;
const SUMMARY_INVOICE_CHARS: usize = 80;

const SIGNATURES_RPC_ID: u64 = 1;
const MINT_RPC_ID: u64 = 2;
/// Per-candidate `getTransaction` ids start here, so a response that belongs to
/// a different candidate is rejected by the envelope id check.
const TRANSACTION_RPC_ID_BASE: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPhase {
    ConfigValidated,
    MintRpc,
    SignatureScanRpc,
    TransactionRpc,
    VerificationComplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmArgs {
    pub recipient: String,
    pub amount: String,
    pub mint: String,
    pub invoice_id: String,
}

/// The bounded verdict. `paid: false` is a *successful* call: the tool looked
/// and did not find a settled payment matching these exact terms. There is no
/// third state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmOutput {
    pub paid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_status: Option<String>,
    pub mint: String,
    pub recipient: String,
    pub reference: String,
    /// Base units, as a string: a raw `u64` amount can exceed the range JSON
    /// numbers survive intact.
    pub expected_raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_ui: Option<String>,
    /// Settled transfers that fully verified against this invoice. `2` or more
    /// means the invoice was paid more than once — a real merchant condition a
    /// cursor-based watcher would silently skip.
    pub match_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResponse {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    /// Bounded refusal taxonomy for structured component logging. Not part of
    /// the WIT tool result returned to the model.
    pub category: Option<&'static str>,
}

impl ToolResponse {
    fn success(output: String) -> Self {
        Self {
            success: true,
            output,
            error: None,
            category: None,
        }
    }

    fn refusal(error: ConfirmError) -> Self {
        let category = error.code();
        Self {
            success: false,
            output: String::new(),
            error: Some(single_line(&error.to_string(), MAX_ERROR_CHARS)),
            category: Some(category),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentArgs {
    recipient: String,
    amount: String,
    mint: String,
    invoice_id: String,
    // Not present in the public schema. The host removes caller-provided
    // `__config`, then injects the resolved operator section at this boundary.
    // There is deliberately no `reference` field anywhere in this struct.
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

impl From<&ComponentArgs> for ConfirmArgs {
    fn from(value: &ComponentArgs) -> Self {
        Self {
            recipient: value.recipient.clone(),
            amount: value.amount.clone(),
            mint: value.mint.clone(),
            invoice_id: value.invoice_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmConfig {
    rpc_url: String,
    /// When set, both endpoints must return the same transaction for the same
    /// signature or the call refuses. One lying endpoint then stops being
    /// sufficient to forge a confirmation.
    rpc_url_secondary: Option<String>,
    allowed_recipients: BTreeSet<Pubkey>,
    allowed_mints: BTreeSet<Pubkey>,
    aliases: BTreeMap<String, Pubkey>,
    min_commitment: CommitmentLevel,
    max_signatures_scanned: u16,
    allow_token_2022: bool,
}

impl ConfirmConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, ConfirmError> {
        for key in section.keys() {
            if !matches!(
                key.as_str(),
                "rpc_url"
                    | "rpc_url_secondary"
                    | "allowed_recipients"
                    | "mint_allowlist"
                    | "mint_aliases"
                    | "min_commitment"
                    | "max_signatures_scanned"
                    | "allow_token_2022"
            ) {
                return Err(ConfirmError::InvalidConfig(
                    "unknown configuration key".to_string(),
                ));
            }
        }

        let rpc_url = required_config(section, "rpc_url")?;
        validate_rpc_url(rpc_url)?;
        let rpc_url_secondary = section
            .get("rpc_url_secondary")
            .filter(|value| !value.is_empty())
            .map(|value| validate_rpc_url(value).map(|()| value.to_string()))
            .transpose()?;
        if rpc_url_secondary.as_deref() == Some(rpc_url) {
            return Err(ConfirmError::InvalidConfig(
                "rpc_url_secondary must differ from rpc_url".to_string(),
            ));
        }

        let allowed_recipients = parse_pubkey_set(
            required_config(section, "allowed_recipients")?,
            "allowed_recipients",
            MAX_RECIPIENTS,
        )?;
        if allowed_recipients.is_empty() {
            return Err(ConfirmError::InvalidConfig(
                "allowed_recipients must not be empty".to_string(),
            ));
        }

        let allowed_mints = parse_pubkey_set(
            required_config(section, "mint_allowlist")?,
            "mint_allowlist",
            MAX_MINTS,
        )?;
        if allowed_mints.is_empty() {
            return Err(ConfirmError::InvalidConfig(
                "mint_allowlist must not be empty".to_string(),
            ));
        }

        let aliases = match section.get("mint_aliases") {
            None => BTreeMap::new(),
            Some(value) => {
                let mut aliases = BTreeMap::new();
                for (alias, mint_text) in parse_assignments(value, "mint_aliases", MAX_MINTS)? {
                    let alias = normalize_alias(&alias)?;
                    let mint = parse_config_pubkey(&mint_text, "mint alias")?;
                    if !allowed_mints.contains(&mint) {
                        return Err(ConfirmError::InvalidConfig(
                            "mint aliases must target allowlisted mints".to_string(),
                        ));
                    }
                    if aliases.insert(alias, mint).is_some() {
                        return Err(ConfirmError::InvalidConfig(
                            "mint_aliases contains a duplicate normalized alias".to_string(),
                        ));
                    }
                }
                aliases
            }
        };

        // Default `finalized`: a confirmation is a claim that money arrived, so
        // the weaker level must be opted into explicitly.
        let min_commitment = match section.get("min_commitment").map(String::as_str) {
            None | Some("finalized") => CommitmentLevel::Finalized,
            Some("confirmed") => CommitmentLevel::Confirmed,
            Some(_) => {
                return Err(ConfirmError::InvalidConfig(
                    "min_commitment must be exactly \"confirmed\" or \"finalized\"".to_string(),
                ))
            }
        };

        let max_signatures_scanned = match section
            .get("max_signatures_scanned")
            .filter(|value| !value.is_empty())
        {
            None => DEFAULT_SIGNATURES_SCANNED,
            Some(value) => {
                let scanned = value.parse::<u16>().map_err(|_| {
                    ConfirmError::InvalidConfig(
                        "max_signatures_scanned must be an integer".to_string(),
                    )
                })?;
                if scanned == 0 || scanned > MAX_SIGNATURES_SCANNED {
                    return Err(ConfirmError::InvalidConfig(format!(
                        "max_signatures_scanned must be between 1 and {MAX_SIGNATURES_SCANNED}"
                    )));
                }
                scanned
            }
        };

        let allow_token_2022 =
            parse_optional_bool(section.get("allow_token_2022"), "allow_token_2022")?;

        Ok(Self {
            rpc_url: rpc_url.to_string(),
            rpc_url_secondary,
            allowed_recipients,
            allowed_mints,
            aliases,
            min_commitment,
            max_signatures_scanned,
            allow_token_2022,
        })
    }

    pub fn min_commitment(&self) -> CommitmentLevel {
        self.min_commitment
    }

    fn resolve_mint(&self, input: &str) -> Result<Pubkey, ConfirmError> {
        let mint = Pubkey::from_str(input).ok().or_else(|| {
            normalize_alias(input)
                .ok()
                .and_then(|alias| self.aliases.get(&alias).copied())
        });
        let mint = mint.ok_or(ConfirmError::InvalidMint)?;
        if !self.allowed_mints.contains(&mint) {
            return Err(ConfirmError::MintNotAllowed);
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

/// Everything a settled transfer must match, derived before any candidate is
/// fetched. Nothing here comes from a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPayment {
    pub recipient: Pubkey,
    pub mint: Pubkey,
    pub destination_ata: Pubkey,
    pub token_program: TokenProgram,
    pub decimals: u8,
    pub raw_amount: u64,
    pub reference: Pubkey,
    pub min_commitment: CommitmentLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub signature: Signature,
    pub slot: u64,
    pub confirmation_status: CommitmentLevel,
    pub received_raw: u64,
}

/// Why one candidate transaction did not confirm the invoice.
///
/// This is a closed taxonomy of *our* conclusions. No endpoint-supplied string
/// ever reaches it, so a hostile RPC cannot write the reason a model reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    CommitmentTooWeak,
    TransactionFailed,
    UndecodableTransaction,
    NoTokenTransfer,
    MultipleTokenTransfers,
    WrongTokenProgram,
    WrongDestination,
    WrongMint,
    WrongDecimals,
    WrongInstructionAmount,
    ReferenceNotInTransferInstruction,
    SlotMismatch,
    MissingBalanceRecord,
    BalanceDidNotIncrease,
    /// The instruction amount was right but the recipient's balance rose by a
    /// different amount — a Token-2022 transfer fee, or any other divergence
    /// between what was asked for and what arrived.
    AmountReceivedDiffers,
}

impl Rejection {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::CommitmentTooWeak => "candidate has not reached the required commitment level",
            Self::TransactionFailed => "candidate transaction failed on chain",
            Self::UndecodableTransaction => {
                "candidate transaction bytes are outside the supported message subset"
            }
            Self::NoTokenTransfer => "candidate contains no SPL token transfer instruction",
            Self::MultipleTokenTransfers => {
                "candidate contains more than one token transfer instruction"
            }
            Self::WrongTokenProgram => "candidate transfer uses a different token program",
            Self::WrongDestination => {
                "candidate transfer pays a different associated token account"
            }
            Self::WrongMint => "candidate transfer moves a different mint",
            Self::WrongDecimals => "candidate transfer asserts decimals the mint does not have",
            Self::WrongInstructionAmount => "candidate transfer amount differs from the invoice",
            Self::ReferenceNotInTransferInstruction => {
                "invoice reference is not a read-only account of the transfer instruction"
            }
            Self::SlotMismatch => "endpoint reported inconsistent slots for this signature",
            Self::MissingBalanceRecord => {
                "endpoint reported no post-transfer balance for the destination account"
            }
            Self::BalanceDidNotIncrease => "destination balance did not increase",
            Self::AmountReceivedDiffers => "amount received differs from the amount requested",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmError {
    InvalidArguments,
    InvalidConfig(String),
    InvalidRecipient,
    RecipientNotAllowed,
    InvalidMint,
    MintNotAllowed,
    InvalidAmount(String),
    AmountZero,
    InvalidInvoice,
    RpcTransport(TransportError),
    Rpc(RpcError),
    MintState(String),
    Token2022Disabled,
    Token2022ExtensionsDenied,
    EndpointDisagreement,
    ReadBudgetExhausted,
    OutputTooLong,
    OutputSerialization,
}

impl ConfirmError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::InvalidConfig(_) => "invalid_config",
            Self::InvalidRecipient => "invalid_recipient",
            Self::RecipientNotAllowed => "recipient_not_allowed",
            Self::InvalidMint => "invalid_mint",
            Self::MintNotAllowed => "mint_not_allowed",
            Self::InvalidAmount(_) | Self::AmountZero => "invalid_amount",
            Self::InvalidInvoice => "invalid_invoice",
            Self::RpcTransport(_) | Self::Rpc(_) => "rpc_failure",
            Self::MintState(_) => "invalid_mint_state",
            Self::Token2022Disabled | Self::Token2022ExtensionsDenied => "token_2022_policy",
            Self::EndpointDisagreement => "endpoint_disagreement",
            Self::ReadBudgetExhausted => "read_budget_exhausted",
            Self::OutputTooLong | Self::OutputSerialization => "output_failure",
        }
    }
}

impl fmt::Display for ConfirmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => formatter.write_str("invalid tool arguments"),
            Self::InvalidConfig(reason) => write!(formatter, "invalid plugin config: {reason}"),
            Self::InvalidRecipient => formatter
                .write_str("recipient must be a base58-encoded 32-byte wallet public key"),
            Self::RecipientNotAllowed => formatter.write_str(
                "recipient is not allowed by operator configuration; confirmation is restricted to the configured recipients",
            ),
            Self::InvalidMint => {
                formatter.write_str("mint must be an allowlisted public key or configured alias")
            }
            Self::MintNotAllowed => {
                formatter.write_str("mint is not allowed by operator configuration")
            }
            Self::InvalidAmount(reason) => write!(formatter, "invalid amount: {reason}"),
            Self::AmountZero => formatter.write_str("amount must be greater than zero"),
            Self::InvalidInvoice => {
                formatter.write_str("invoice_id is empty, malformed, or exceeds 128 bytes")
            }
            Self::RpcTransport(error) => error.fmt(formatter),
            Self::Rpc(error) => error.fmt(formatter),
            Self::MintState(reason) => write!(formatter, "mint account refused: {reason}"),
            Self::Token2022Disabled => formatter.write_str(
                "Token-2022 mint refused; operator must explicitly enable extension-free Token-2022",
            ),
            Self::Token2022ExtensionsDenied => formatter
                .write_str("Token-2022 mint extensions are outside the supported safe subset"),
            Self::EndpointDisagreement => formatter.write_str(
                "configured RPC endpoints returned different data for the same signature; refusing rather than trusting either",
            ),
            Self::ReadBudgetExhausted => formatter.write_str(
                "configured endpoints returned more data than one confirmation may read; refusing rather than continuing a partial scan",
            ),
            Self::OutputTooLong => formatter.write_str("tool output exceeds the 4000-byte limit"),
            Self::OutputSerialization => formatter.write_str("could not serialize tool output"),
        }
    }
}

impl std::error::Error for ConfirmError {}

impl From<TransportError> for ConfirmError {
    fn from(error: TransportError) -> Self {
        Self::RpcTransport(error)
    }
}

impl From<RpcError> for ConfirmError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

/// Parse the host envelope. Argument, config, policy, and RPC failures are
/// model-visible refusals rather than component faults.
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
        Err(_) => return ToolResponse::refusal(ConfirmError::InvalidArguments),
    };
    let config = match ConfirmConfig::from_section(&parsed.config) {
        Ok(value) => value,
        Err(error) => return ToolResponse::refusal(error),
    };
    observer(ExecutionPhase::ConfigValidated);
    match confirm_payment_observed(
        ConfirmArgs::from(&parsed),
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

pub fn confirm_payment(
    args: ConfirmArgs,
    config: &ConfirmConfig,
    transport: &impl RpcTransport,
) -> Result<ConfirmOutput, ConfirmError> {
    confirm_payment_observed(args, config, transport, &mut |_| {})
}

fn confirm_payment_observed(
    args: ConfirmArgs,
    config: &ConfirmConfig,
    transport: &impl RpcTransport,
    observer: &mut impl FnMut(ExecutionPhase),
) -> Result<ConfirmOutput, ConfirmError> {
    let recipient =
        Pubkey::from_str(&args.recipient).map_err(|_| ConfirmError::InvalidRecipient)?;
    if !config.allowed_recipients.contains(&recipient) {
        return Err(ConfirmError::RecipientNotAllowed);
    }
    let mint = config.resolve_mint(&args.mint)?;
    let invoice_id = validate_invoice(&args.invoice_id)?;
    validate_decimal_syntax(&args.amount, "amount")?;
    if args.amount.len() > MAX_AMOUNT_BYTES {
        return Err(ConfirmError::InvalidAmount(
            "decimal string exceeds 64 bytes".to_string(),
        ));
    }

    // One byte budget covers every read this call makes, across both endpoints.
    let mut budget = ReadBudget::new();

    // Decimals come from the mint account, never from config or arguments: this
    // is a money path, and the RPC call is already being made.
    observer(ExecutionPhase::MintRpc);
    let mint_body = rpc_post(
        transport,
        &config.rpc_url,
        &get_account_info_request(MINT_RPC_ID, &mint),
        MAX_RPC_RESPONSE_BYTES,
        &mut budget,
    )?;
    let account = parse_account_info_response(&mint_body, MINT_RPC_ID)?;
    let mint_info = parse_mint_account(&account)
        .map_err(|error| ConfirmError::MintState(single_line(&error.to_string(), 120)))?;
    enforce_token_policy(&mint_info, config)?;

    let raw_amount = parse_ui_amount(&args.amount, mint_info.decimals).map_err(amount_error)?;
    if raw_amount == 0 {
        return Err(ConfirmError::AmountZero);
    }
    let canonical_amount =
        format_ui_amount(raw_amount, mint_info.decimals).map_err(amount_error)?;
    // Identical derivation to `solana-pay-request`, from the same shared core,
    // so a request URL and this confirmation cannot drift apart.
    let reference =
        derive_payment_reference(&recipient, Some(&mint), &canonical_amount, invoice_id);
    let (destination_ata, _) =
        derive_associated_token_address(&recipient, &mint, &mint_info.token_program.id())
            .map_err(|error| ConfirmError::MintState(single_line(&error.to_string(), 120)))?;

    let expected = ExpectedPayment {
        recipient,
        mint,
        destination_ata,
        token_program: mint_info.token_program,
        decimals: mint_info.decimals,
        raw_amount,
        reference,
        min_commitment: config.min_commitment,
    };

    observer(ExecutionPhase::SignatureScanRpc);
    let signatures_body = rpc_post(
        transport,
        &config.rpc_url,
        &get_signatures_for_address_request(
            SIGNATURES_RPC_ID,
            &reference,
            config.max_signatures_scanned,
            config.min_commitment,
        ),
        MAX_RPC_RESPONSE_BYTES,
        &mut budget,
    )?;
    let candidates = parse_signatures_for_address_response(&signatures_body, SIGNATURES_RPC_ID)?;

    // Newest first, as the endpoint returns them. Every candidate is examined so
    // `match_count` is honest about double payment.
    let mut verified: Vec<VerifiedPayment> = Vec::new();
    let mut first_rejection: Option<Rejection> = None;
    for (index, candidate) in candidates.iter().enumerate() {
        match verify_candidate(
            candidate,
            index,
            &expected,
            config,
            transport,
            observer,
            &mut budget,
        ) {
            Ok(payment) => verified.push(payment),
            Err(CandidateError::Rejected(rejection)) => {
                first_rejection.get_or_insert(rejection);
            }
            Err(CandidateError::Fatal(error)) => return Err(error),
        }
    }
    observer(ExecutionPhase::VerificationComplete);

    let alias = config.unique_alias(&mint);
    // The oldest verified match is reported: it is the transfer that settled the
    // invoice, and it does not change when a later duplicate payment arrives.
    match verified.last() {
        Some(payment) => paid_output(&expected, payment, verified.len(), alias, invoice_id),
        None => unpaid_output(
            &expected,
            candidates.len(),
            config.max_signatures_scanned,
            first_rejection,
            alias,
            invoice_id,
        ),
    }
}

/// A candidate either fails verification (a verdict) or breaks the call (a
/// refusal). Endpoint disagreement and transport faults are never verdicts.
enum CandidateError {
    Rejected(Rejection),
    Fatal(ConfirmError),
}

impl From<ConfirmError> for CandidateError {
    fn from(error: ConfirmError) -> Self {
        Self::Fatal(error)
    }
}

fn verify_candidate(
    candidate: &SignatureRecord,
    index: usize,
    expected: &ExpectedPayment,
    config: &ConfirmConfig,
    transport: &impl RpcTransport,
    observer: &mut impl FnMut(ExecutionPhase),
    budget: &mut ReadBudget,
) -> Result<VerifiedPayment, CandidateError> {
    // Cheap rejections first: neither costs a `getTransaction`. Both are checked
    // again inside `verify_record`, which is the authority — this is only an
    // optimisation, never the gate.
    if !candidate
        .confirmation_status
        .is_some_and(|status| status.satisfies(expected.min_commitment))
    {
        return Err(CandidateError::Rejected(Rejection::CommitmentTooWeak));
    }
    if candidate.failed {
        return Err(CandidateError::Rejected(Rejection::TransactionFailed));
    }

    let request_id = TRANSACTION_RPC_ID_BASE.saturating_add(index as u64);
    let request = get_transaction_request(request_id, &candidate.signature, config.min_commitment);
    observer(ExecutionPhase::TransactionRpc);
    let record = fetch_transaction(transport, &config.rpc_url, &request, request_id, budget)?;
    if let Some(secondary) = &config.rpc_url_secondary {
        // A pure read is cheap to duplicate, and requiring agreement means a
        // single dishonest endpoint cannot forge a confirmation.
        let cross_check = fetch_transaction(transport, secondary, &request, request_id, budget)
            .map_err(|error| {
                // One endpoint listing a signature the other has never seen is
                // itself a disagreement, not a generic endpoint fault.
                match error {
                    ConfirmError::Rpc(RpcError::TransactionNotFound) => {
                        ConfirmError::EndpointDisagreement
                    }
                    error => error,
                }
            })?;
        if cross_check != record {
            return Err(CandidateError::Fatal(ConfirmError::EndpointDisagreement));
        }
    }

    verify_record(candidate, &record, expected).map_err(CandidateError::Rejected)
}

/// Verify one settled transaction against the invoice, from its raw bytes and
/// its balance metadata. No `jsonParsed` interpretation is involved.
///
/// Every gate lives here, including the commitment gate: the reported
/// commitment is read from the candidate rather than accepted as an argument, so
/// no caller of this function — now or later — can hand it a level the endpoint
/// did not report.
pub fn verify_record(
    candidate: &SignatureRecord,
    record: &TransactionRecord,
    expected: &ExpectedPayment,
) -> Result<VerifiedPayment, Rejection> {
    let confirmation_status = candidate
        .confirmation_status
        .filter(|status| status.satisfies(expected.min_commitment))
        .ok_or(Rejection::CommitmentTooWeak)?;
    if candidate.failed || record.failed {
        return Err(Rejection::TransactionFailed);
    }
    if record.slot != candidate.slot {
        return Err(Rejection::SlotMismatch);
    }

    let transaction = decode_signed_transaction(&record.transaction)
        .map_err(|_| Rejection::UndecodableTransaction)?;
    let message = &transaction.message;
    let transfers = find_token_transfers(message).map_err(|_| Rejection::UndecodableTransaction)?;
    let transfer = match transfers.len() {
        0 => return Err(Rejection::NoTokenTransfer),
        1 => &transfers[0].1,
        _ => return Err(Rejection::MultipleTokenTransfers),
    };
    check_transfer_instruction(transfer, expected)?;

    // The bytes say what was *asked for*. The balance delta says what *arrived*.
    // Both must agree with the invoice, which is what closes the Token-2022
    // transfer-fee divergence a bytes-only confirmer would inherit.
    let received_raw = destination_delta(message, record, expected)?;
    if received_raw != expected.raw_amount {
        return Err(Rejection::AmountReceivedDiffers);
    }

    Ok(VerifiedPayment {
        signature: candidate.signature,
        slot: record.slot,
        confirmation_status,
        received_raw,
    })
}

fn check_transfer_instruction(
    transfer: &DecodedTokenTransfer,
    expected: &ExpectedPayment,
) -> Result<(), Rejection> {
    if transfer.token_program != expected.token_program {
        return Err(Rejection::WrongTokenProgram);
    }
    if transfer.destination != expected.destination_ata {
        return Err(Rejection::WrongDestination);
    }
    match transfer.kind {
        TokenTransferKind::TransferChecked => {
            if transfer.mint != Some(expected.mint) {
                return Err(Rejection::WrongMint);
            }
            // `TransferChecked` asserts the mint's decimals on chain; a mismatch
            // means this is not the asset the invoice priced.
            if transfer.decimals != Some(expected.decimals) {
                return Err(Rejection::WrongDecimals);
            }
        }
        // A plain `Transfer` names no mint. The destination ATA is derived from
        // (recipient, mint), and the balance record below is required to carry
        // the expected mint, so the asset is still pinned.
        TokenTransferKind::Transfer => {}
    }
    if transfer.amount != expected.raw_amount {
        return Err(Rejection::WrongInstructionAmount);
    }
    if !transfer.carries_reference(&expected.reference) {
        return Err(Rejection::ReferenceNotInTransferInstruction);
    }
    Ok(())
}

/// The increase in the destination ATA's balance across this transaction.
///
/// A destination created by this transaction has no pre-balance, which is a zero
/// starting point rather than a missing record.
fn destination_delta(
    message: &nanosol::message::Message,
    record: &TransactionRecord,
    expected: &ExpectedPayment,
) -> Result<u64, Rejection> {
    // Address-table lookups are refused by the decoder, so a balance's
    // `accountIndex` indexes exactly these static keys.
    let account_index = message
        .account_keys
        .iter()
        .position(|key| key == &expected.destination_ata)
        .ok_or(Rejection::WrongDestination)?;

    let post = record
        .post_token_balances
        .iter()
        .find(|balance| balance.account_index == account_index)
        .ok_or(Rejection::MissingBalanceRecord)?;
    if post.mint != expected.mint {
        return Err(Rejection::WrongMint);
    }
    if post.decimals != expected.decimals {
        return Err(Rejection::WrongDecimals);
    }
    if post.owner.is_some_and(|owner| owner != expected.recipient) {
        return Err(Rejection::WrongDestination);
    }

    let pre = record
        .pre_token_balances
        .iter()
        .find(|balance| balance.account_index == account_index);
    if let Some(pre) = pre {
        if pre.mint != expected.mint {
            return Err(Rejection::WrongMint);
        }
    }
    let pre_amount = pre.map_or(0, |balance| balance.raw_amount);
    post.raw_amount
        .checked_sub(pre_amount)
        .filter(|delta| *delta > 0)
        .ok_or(Rejection::BalanceDidNotIncrease)
}

fn paid_output(
    expected: &ExpectedPayment,
    payment: &VerifiedPayment,
    match_count: usize,
    alias: Option<&str>,
    invoice_id: &str,
) -> Result<ConfirmOutput, ConfirmError> {
    let received_ui =
        format_ui_amount(payment.received_raw, expected.decimals).map_err(amount_error)?;
    let mut summary = format!(
        "CONFIRMED {received_ui} {} received by {} · {} · slot {} · signature {} · invoice {}",
        asset_name(&expected.mint, alias),
        elide_address(&expected.recipient),
        payment.confirmation_status,
        payment.slot,
        payment.signature,
        quote_untrusted(invoice_id, SUMMARY_INVOICE_CHARS),
    );
    if match_count > 1 {
        summary.push_str(&format!(
            " · WARNING {match_count} settled transfers match this invoice: it was paid more than once"
        ));
    }
    summary.push_str(" · verified from transaction bytes and the recipient balance delta");
    Ok(ConfirmOutput {
        paid: true,
        signature: Some(payment.signature.to_string()),
        slot: Some(payment.slot),
        confirmation_status: Some(payment.confirmation_status.to_string()),
        mint: expected.mint.to_string(),
        recipient: expected.recipient.to_string(),
        reference: expected.reference.to_string(),
        expected_raw: expected.raw_amount.to_string(),
        received_raw: Some(payment.received_raw.to_string()),
        received_ui: Some(received_ui),
        match_count,
        reason: None,
        summary,
    })
}

fn unpaid_output(
    expected: &ExpectedPayment,
    scanned: usize,
    window: u16,
    rejection: Option<Rejection>,
    alias: Option<&str>,
    invoice_id: &str,
) -> Result<ConfirmOutput, ConfirmError> {
    let expected_ui =
        format_ui_amount(expected.raw_amount, expected.decimals).map_err(amount_error)?;
    // With no candidates the honest statement is how wide the window was, not
    // how many transactions came back; with candidates it is what they were.
    let reason = match rejection {
        None => format!(
            "no transaction referencing this invoice was found in the most recent {window} signatures for its reference"
        ),
        Some(rejection) => format!(
            "scanned {scanned} candidate transaction(s); none confirmed this invoice: {}",
            rejection.reason()
        ),
    };
    let summary = format!(
        "NOT PAID: no settled transfer of {expected_ui} {} to {} matches invoice {} · {reason} · this verdict re-derives from the invoice on every call",
        asset_name(&expected.mint, alias),
        elide_address(&expected.recipient),
        quote_untrusted(invoice_id, SUMMARY_INVOICE_CHARS),
    );
    Ok(ConfirmOutput {
        paid: false,
        signature: None,
        slot: None,
        confirmation_status: None,
        mint: expected.mint.to_string(),
        recipient: expected.recipient.to_string(),
        reference: expected.reference.to_string(),
        expected_raw: expected.raw_amount.to_string(),
        received_raw: None,
        received_ui: None,
        match_count: 0,
        reason: Some(reason),
        summary,
    })
}

fn asset_name(mint: &Pubkey, alias: Option<&str>) -> String {
    let elided = elide_address(mint);
    alias.map_or_else(
        || format!("token {elided}"),
        |alias| format!("{alias} ({elided})"),
    )
}

fn enforce_token_policy(mint: &MintInfo, config: &ConfirmConfig) -> Result<(), ConfirmError> {
    match mint.token_program {
        TokenProgram::Legacy => Ok(()),
        TokenProgram::Token2022 if !config.allow_token_2022 => Err(ConfirmError::Token2022Disabled),
        // Identical policy to the transfer builder: an extension-bearing mint can
        // make the amount received differ from the amount transferred, so the
        // supported subset is extension-free.
        TokenProgram::Token2022 if !mint.extensions.is_empty() => {
            Err(ConfirmError::Token2022ExtensionsDenied)
        }
        TokenProgram::Token2022 => Ok(()),
    }
}

fn fetch_transaction(
    transport: &impl RpcTransport,
    endpoint: &str,
    request: &str,
    request_id: u64,
    budget: &mut ReadBudget,
) -> Result<TransactionRecord, ConfirmError> {
    let body = rpc_post(
        transport,
        endpoint,
        request,
        MAX_TRANSACTION_RESPONSE_BYTES,
        budget,
    )?;
    parse_transaction_response(&body, request_id).map_err(ConfirmError::from)
}

/// The remaining response-byte allowance for one tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadBudget {
    remaining: usize,
}

impl ReadBudget {
    const fn new() -> Self {
        Self {
            remaining: MAX_TOTAL_RESPONSE_BYTES,
        }
    }

    /// The limit handed to the transport: never more than what is left, so the
    /// transport refuses an oversize body before it is buffered.
    const fn allowance(self, ceiling: usize) -> usize {
        if ceiling < self.remaining {
            ceiling
        } else {
            self.remaining
        }
    }
}

fn rpc_post(
    transport: &impl RpcTransport,
    endpoint: &str,
    request: &str,
    ceiling: usize,
    budget: &mut ReadBudget,
) -> Result<String, ConfirmError> {
    let allowance = budget.allowance(ceiling);
    if allowance == 0 {
        return Err(ConfirmError::ReadBudgetExhausted);
    }
    let body = transport
        .post(endpoint, request, allowance)
        .map_err(ConfirmError::from)?;
    budget.remaining = budget
        .remaining
        .checked_sub(body.len())
        .ok_or(ConfirmError::ReadBudgetExhausted)?;
    Ok(body)
}

fn serialize_output(output: ConfirmOutput) -> Result<String, ConfirmError> {
    let serialized =
        serde_json::to_string(&output).map_err(|_| ConfirmError::OutputSerialization)?;
    if serialized.len() >= MAX_TOOL_OUTPUT_BYTES {
        return Err(ConfirmError::OutputTooLong);
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
                "description": "Recipient wallet public key from the original payment request; must be one the operator allows."
            },
            "amount": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_AMOUNT_BYTES,
                "pattern": "^[0-9]+(?:\\.[0-9]+)?$",
                "description": "Exact UI amount that was requested, as an unsigned decimal string. Decimals come from the mint account."
            },
            "mint": {
                "type": "string",
                "minLength": 1,
                "maxLength": 44,
                "description": "Allowlisted SPL mint public key or operator-configured alias from the original request."
            },
            "invoice_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_INVOICE_BYTES,
                "description": "Invoice identifier from the original request. The payment reference is derived from these four fields and cannot be supplied directly."
            }
        },
        "required": ["recipient", "amount", "mint", "invoice_id"]
    })
    .to_string()
}

fn required_config<'a>(
    section: &'a HashMap<String, String>,
    key: &'static str,
) -> Result<&'a str, ConfirmError> {
    section
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| ConfirmError::InvalidConfig(format!("missing or empty {key}")))
}

fn validate_rpc_url(value: &str) -> Result<(), ConfirmError> {
    if value.len() > MAX_RPC_URL_BYTES
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || value.contains('\\')
    {
        return Err(ConfirmError::InvalidConfig(
            "an RPC URL is malformed or too long".to_string(),
        ));
    }
    let parsed = Url::parse(value)
        .map_err(|_| ConfirmError::InvalidConfig("an RPC URL is malformed".to_string()))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfirmError::InvalidConfig(
            "an RPC URL must be HTTPS without credentials or a fragment".to_string(),
        ));
    }
    Ok(())
}

fn parse_config_pubkey(value: &str, field: &str) -> Result<Pubkey, ConfirmError> {
    Pubkey::from_str(value)
        .map_err(|_| ConfirmError::InvalidConfig(format!("{field} contains an invalid public key")))
}

fn parse_pubkey_set(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<BTreeSet<Pubkey>, ConfirmError> {
    let entries = split_strict_list(value, field, maximum)?;
    let mut output = BTreeSet::new();
    for entry in entries {
        let key = parse_config_pubkey(entry, field)?;
        if !output.insert(key) {
            return Err(ConfirmError::InvalidConfig(format!(
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
) -> Result<Vec<(String, String)>, ConfirmError> {
    let entries = split_strict_list(value, field, maximum)?;
    let mut output = Vec::with_capacity(entries.len());
    let mut seen = BTreeSet::new();
    for entry in entries {
        let (key, assigned) = entry.split_once('=').ok_or_else(|| {
            ConfirmError::InvalidConfig(format!("{field} entries must use NAME=value"))
        })?;
        if key.is_empty() || assigned.is_empty() || assigned.contains('=') {
            return Err(ConfirmError::InvalidConfig(format!(
                "{field} contains a malformed assignment"
            )));
        }
        if !seen.insert(key) {
            return Err(ConfirmError::InvalidConfig(format!(
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
) -> Result<Vec<&'a str>, ConfirmError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ConfirmError::InvalidConfig(format!(
            "{field} must not contain whitespace"
        )));
    }
    let entries: Vec<_> = value.split(',').collect();
    if entries.len() > maximum || entries.iter().any(|entry| entry.is_empty()) {
        return Err(ConfirmError::InvalidConfig(format!(
            "{field} is empty, malformed, or exceeds {maximum} entries"
        )));
    }
    Ok(entries)
}

fn normalize_alias(alias: &str) -> Result<String, ConfirmError> {
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
        return Err(ConfirmError::InvalidConfig(
            "mint alias has invalid syntax".to_string(),
        ));
    }
    Ok(alias.to_ascii_uppercase())
}

fn parse_optional_bool(value: Option<&String>, field: &'static str) -> Result<bool, ConfirmError> {
    match value.map(String::as_str) {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(ConfirmError::InvalidConfig(format!(
            "{field} must be exactly true or false"
        ))),
    }
}

fn validate_decimal_syntax(value: &str, field: &str) -> Result<(), ConfirmError> {
    if value.is_empty() || !value.is_ascii() {
        return Err(ConfirmError::InvalidAmount(format!(
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
        return Err(ConfirmError::InvalidAmount(format!(
            "{field} must be unsigned decimal digits with an optional fractional part"
        )));
    }
    Ok(())
}

fn validate_invoice(value: &str) -> Result<&str, ConfirmError> {
    if value.is_empty() || value.len() > MAX_INVOICE_BYTES || value.chars().any(char::is_control) {
        return Err(ConfirmError::InvalidInvoice);
    }
    Ok(value)
}

fn amount_error(error: AmountError) -> ConfirmError {
    ConfirmError::InvalidAmount(error.to_string())
}
