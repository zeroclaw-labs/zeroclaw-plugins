use std::{collections::BTreeSet, error::Error, fmt};

use crate::pubkey::{proposal_transaction_address, Pubkey, PubkeyError};

pub const MAX_ACCOUNT_DATA_LEN: usize = 1_048_576;
pub const MAX_STRING_LEN: usize = 4_096;
pub const MAX_PROPOSAL_OPTIONS: usize = 10;
pub const MAX_PROPOSAL_TRANSACTIONS: usize = 64;
pub const MAX_TRANSACTION_INSTRUCTIONS: usize = 128;
pub const MAX_ACCOUNTS_PER_INSTRUCTION: usize = 64;
pub const MAX_INSTRUCTION_DATA_LEN: usize = 65_536;
pub const MAX_LOCK_AUTHORITIES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Truncated,
    Invalid(&'static str),
    Unsupported(&'static str),
    LimitExceeded(&'static str),
    ArithmeticOverflow,
    Relationship(&'static str),
    Pda(PubkeyError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated governance account"),
            Self::Invalid(field) => write!(f, "invalid governance field: {field}"),
            Self::Unsupported(field) => write!(f, "unsupported governance feature: {field}"),
            Self::LimitExceeded(field) => write!(f, "governance limit exceeded: {field}"),
            Self::ArithmeticOverflow => f.write_str("governance arithmetic overflow"),
            Self::Relationship(field) => write!(f, "invalid governance relationship: {field}"),
            Self::Pda(error) => write!(f, "PDA derivation failed: {error}"),
        }
    }
}

impl Error for DecodeError {}

impl From<PubkeyError> for DecodeError {
    fn from(value: PubkeyError) -> Self {
        Self::Pda(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalState {
    Draft,
    SigningOff,
    Voting,
    Succeeded,
    Executing,
    Completed,
    Cancelled,
    Defeated,
    ExecutingWithErrors,
    Vetoed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionVoteResult {
    None,
    Succeeded,
    Defeated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultiChoiceType {
    FullWeight,
    Weighted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteType {
    SingleChoice,
    MultiChoice {
        choice_type: MultiChoiceType,
        min_voter_options: u8,
        max_voter_options: u8,
        max_winning_options: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstructionExecutionFlags {
    None,
    Ordered,
    UseTransaction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteThreshold {
    YesVotePercentage(u8),
    QuorumPercentage(u8),
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteTipping {
    Strict,
    Early,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionExecutionStatus {
    None,
    Success,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernanceAccountType {
    GovernanceV2,
    ProgramGovernanceV2,
    MintGovernanceV2,
    TokenGovernanceV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MintMaxVoterWeightSource {
    SupplyFraction(u64),
    Absolute(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoverningTokenType {
    Liquid,
    Membership,
    Dormant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalOption {
    pub label: String,
    pub vote_weight: u64,
    pub vote_result: OptionVoteResult,
    pub transactions_executed_count: u16,
    pub transactions_count: u16,
    pub transactions_next_index: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalV2 {
    pub governance: Pubkey,
    pub governing_token_mint: Pubkey,
    pub state: ProposalState,
    pub token_owner_record: Pubkey,
    pub signatories_count: u8,
    pub signatories_signed_off_count: u8,
    pub vote_type: VoteType,
    pub options: Vec<ProposalOption>,
    pub deny_vote_weight: Option<u64>,
    pub abstain_vote_weight: Option<u64>,
    pub start_voting_at: Option<i64>,
    pub draft_at: i64,
    pub signing_off_at: Option<i64>,
    pub voting_at: Option<i64>,
    pub voting_at_slot: Option<u64>,
    pub voting_completed_at: Option<i64>,
    pub executing_at: Option<i64>,
    pub closed_at: Option<i64>,
    pub execution_flags: InstructionExecutionFlags,
    pub max_vote_weight: Option<u64>,
    pub max_voting_time: Option<u32>,
    pub vote_threshold: Option<VoteThreshold>,
    pub name: String,
    pub description_link: String,
    pub veto_vote_weight: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountMetaData {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstructionData {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMetaData>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalTransactionV2 {
    pub proposal: Pubkey,
    pub option_index: u8,
    pub transaction_index: u16,
    pub instructions: Vec<InstructionData>,
    pub executed_at: Option<i64>,
    pub execution_status: TransactionExecutionStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceConfig {
    pub community_vote_threshold: VoteThreshold,
    pub min_community_weight_to_create_proposal: u64,
    pub transactions_hold_up_time: u32,
    pub voting_base_time: u32,
    pub community_vote_tipping: VoteTipping,
    pub council_vote_threshold: VoteThreshold,
    pub council_veto_vote_threshold: VoteThreshold,
    pub min_council_weight_to_create_proposal: u64,
    pub council_vote_tipping: VoteTipping,
    pub community_veto_vote_threshold: VoteThreshold,
    pub voting_cool_off_time: u32,
    pub deposit_exempt_proposal_count: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceV2 {
    pub account_type: GovernanceAccountType,
    pub realm: Pubkey,
    pub governance_seed: Pubkey,
    pub config: GovernanceConfig,
    pub required_signatories_count: u8,
    pub active_proposal_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmConfig {
    pub legacy_voter_weight_addin: bool,
    pub legacy_max_voter_weight_addin: bool,
    pub min_community_weight_to_create_governance: u64,
    pub community_mint_max_voter_weight_source: MintMaxVoterWeightSource,
    pub council_mint: Option<Pubkey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmV2 {
    pub community_mint: Pubkey,
    pub config: RealmConfig,
    pub authority: Option<Pubkey>,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoverningTokenConfig {
    pub voter_weight_addin: Option<Pubkey>,
    pub max_voter_weight_addin: Option<Pubkey>,
    pub token_type: GoverningTokenType,
    pub lock_authorities: Vec<Pubkey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmConfigAccount {
    pub realm: Pubkey,
    pub community_token_config: GoverningTokenConfig,
    pub council_token_config: GoverningTokenConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedProposalTransaction {
    pub option_index: u8,
    pub transaction_index: u16,
    pub address: Pubkey,
    pub bump: u8,
}

pub fn decode_proposal_v2(data: &[u8]) -> Result<ProposalV2, DecodeError> {
    let mut reader = Reader::new(data)?;
    reader.expect_tag(14)?;
    let governance = reader.pubkey()?;
    let governing_token_mint = reader.pubkey()?;
    let state = read_proposal_state(&mut reader)?;
    let token_owner_record = reader.pubkey()?;
    let signatories_count = reader.u8()?;
    let signatories_signed_off_count = reader.u8()?;
    let vote_type = read_vote_type(&mut reader)?;

    let option_count = reader.bounded_count(MAX_PROPOSAL_OPTIONS, "proposal options")?;
    if option_count == 0 {
        return Err(DecodeError::Invalid("proposal options"));
    }
    let mut options = Vec::with_capacity(option_count);
    let mut total_transaction_indexes = 0usize;
    for _ in 0..option_count {
        let option = ProposalOption {
            label: reader.string(MAX_STRING_LEN, "proposal option label")?,
            vote_weight: reader.u64()?,
            vote_result: read_option_vote_result(&mut reader)?,
            transactions_executed_count: reader.u16()?,
            transactions_count: reader.u16()?,
            transactions_next_index: reader.u16()?,
        };
        if option.transactions_executed_count > option.transactions_count
            || option.transactions_count > option.transactions_next_index
        {
            return Err(DecodeError::Invalid("proposal transaction counts"));
        }
        total_transaction_indexes = total_transaction_indexes
            .checked_add(option.transactions_next_index as usize)
            .ok_or(DecodeError::ArithmeticOverflow)?;
        if total_transaction_indexes > MAX_PROPOSAL_TRANSACTIONS {
            return Err(DecodeError::LimitExceeded("proposal transactions"));
        }
        options.push(option);
    }
    validate_vote_type(vote_type, option_count)?;

    let deny_vote_weight = reader.option_u64()?;
    let _reserved1 = reader.u8()?;
    let abstain_vote_weight = reader.option_u64()?;
    let start_voting_at = reader.option_i64()?;
    let draft_at = reader.i64()?;
    let signing_off_at = reader.option_i64()?;
    let voting_at = reader.option_i64()?;
    let voting_at_slot = reader.option_u64()?;
    let voting_completed_at = reader.option_i64()?;
    let executing_at = reader.option_i64()?;
    let closed_at = reader.option_i64()?;
    let execution_flags = read_execution_flags(&mut reader)?;
    let max_vote_weight = reader.option_u64()?;
    let max_voting_time = reader.option_u32()?;
    let vote_threshold = reader.option_vote_threshold()?;
    if let Some(threshold) = vote_threshold {
        validate_supported_threshold(threshold, true)?;
    }
    reader.skip(64)?;
    let name = reader.string(MAX_STRING_LEN, "proposal name")?;
    let description_link = reader.string(MAX_STRING_LEN, "proposal description link")?;
    let veto_vote_weight = reader.u64()?;

    Ok(ProposalV2 {
        governance,
        governing_token_mint,
        state,
        token_owner_record,
        signatories_count,
        signatories_signed_off_count,
        vote_type,
        options,
        deny_vote_weight,
        abstain_vote_weight,
        start_voting_at,
        draft_at,
        signing_off_at,
        voting_at,
        voting_at_slot,
        voting_completed_at,
        executing_at,
        closed_at,
        execution_flags,
        max_vote_weight,
        max_voting_time,
        vote_threshold,
        name,
        description_link,
        veto_vote_weight,
    })
}

pub fn decode_proposal_transaction_v2(data: &[u8]) -> Result<ProposalTransactionV2, DecodeError> {
    let mut reader = Reader::new(data)?;
    reader.expect_tag(13)?;
    let proposal = reader.pubkey()?;
    let option_index = reader.u8()?;
    let transaction_index = reader.u16()?;
    // This pre-v4 hold-up field remains serialized but v4 execution ignores it.
    let _legacy_hold_up_time = reader.u32()?;

    let instruction_count =
        reader.bounded_count(MAX_TRANSACTION_INSTRUCTIONS, "transaction instructions")?;
    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        let program_id = reader.pubkey()?;
        let account_count =
            reader.bounded_count(MAX_ACCOUNTS_PER_INSTRUCTION, "instruction account metadata")?;
        let mut accounts = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            accounts.push(AccountMetaData {
                pubkey: reader.pubkey()?,
                is_signer: reader.bool()?,
                is_writable: reader.bool()?,
            });
        }
        let data = reader.byte_vec(MAX_INSTRUCTION_DATA_LEN, "instruction data")?;
        instructions.push(InstructionData {
            program_id,
            accounts,
            data,
        });
    }
    let executed_at = reader.option_i64()?;
    let execution_status = read_transaction_status(&mut reader)?;
    reader.skip(8)?;

    Ok(ProposalTransactionV2 {
        proposal,
        option_index,
        transaction_index,
        instructions,
        executed_at,
        execution_status,
    })
}

pub fn decode_governance_v2(data: &[u8]) -> Result<GovernanceV2, DecodeError> {
    let mut reader = Reader::new(data)?;
    let account_type = match reader.u8()? {
        18 => GovernanceAccountType::GovernanceV2,
        19 => GovernanceAccountType::ProgramGovernanceV2,
        20 => GovernanceAccountType::MintGovernanceV2,
        21 => GovernanceAccountType::TokenGovernanceV2,
        _ => return Err(DecodeError::Invalid("GovernanceV2 account tag")),
    };
    let realm = reader.pubkey()?;
    let governance_seed = reader.pubkey()?;
    let _reserved1 = reader.u32()?;
    let config = read_governance_config(&mut reader)?;
    reader.skip(119)?;
    let required_signatories_count = reader.u8()?;
    let active_proposal_count = reader.u64()?;

    Ok(GovernanceV2 {
        account_type,
        realm,
        governance_seed,
        config,
        required_signatories_count,
        active_proposal_count,
    })
}

pub fn decode_realm_v2(data: &[u8]) -> Result<RealmV2, DecodeError> {
    let mut reader = Reader::new(data)?;
    reader.expect_tag(16)?;
    let community_mint = reader.pubkey()?;
    let legacy_voter_weight_addin = reader.bool()?;
    let legacy_max_voter_weight_addin = reader.bool()?;
    reader.skip(6)?;
    let min_community_weight_to_create_governance = reader.u64()?;
    let community_mint_max_voter_weight_source = read_max_voter_weight_source(&mut reader)?;
    let council_mint = reader.option_pubkey()?;
    reader.skip(6)?;
    let _legacy1 = reader.u16()?;
    let authority = reader.option_pubkey()?;
    let name = reader.string(MAX_STRING_LEN, "realm name")?;
    reader.skip(128)?;

    Ok(RealmV2 {
        community_mint,
        config: RealmConfig {
            legacy_voter_weight_addin,
            legacy_max_voter_weight_addin,
            min_community_weight_to_create_governance,
            community_mint_max_voter_weight_source,
            council_mint,
        },
        authority,
        name,
    })
}

pub fn decode_realm_config_account(data: &[u8]) -> Result<RealmConfigAccount, DecodeError> {
    let mut reader = Reader::new(data)?;
    reader.expect_tag(11)?;
    let realm = reader.pubkey()?;
    let community_token_config = read_governing_token_config(&mut reader)?;
    let council_token_config = read_governing_token_config(&mut reader)?;
    reader.skip(110)?;

    Ok(RealmConfigAccount {
        realm,
        community_token_config,
        council_token_config,
    })
}

pub fn minimum_vote_weight(
    threshold: VoteThreshold,
    max_voter_weight: u64,
) -> Result<u64, DecodeError> {
    let percentage = match threshold {
        VoteThreshold::YesVotePercentage(value @ 1..=100) => value,
        VoteThreshold::YesVotePercentage(_) => {
            return Err(DecodeError::Invalid("vote threshold percentage"))
        }
        VoteThreshold::QuorumPercentage(_) => {
            return Err(DecodeError::Unsupported("quorum vote threshold"))
        }
        VoteThreshold::Disabled => return Err(DecodeError::Unsupported("disabled vote threshold")),
    };
    let numerator = (percentage as u128)
        .checked_mul(max_voter_weight as u128)
        .ok_or(DecodeError::ArithmeticOverflow)?;
    let rounded = numerator
        .checked_add(99)
        .ok_or(DecodeError::ArithmeticOverflow)?
        / 100;
    u64::try_from(rounded).map_err(|_| DecodeError::ArithmeticOverflow)
}

pub fn effective_vote_threshold(
    proposal: &ProposalV2,
    governance: &GovernanceV2,
    realm: &RealmV2,
) -> Result<VoteThreshold, DecodeError> {
    let threshold = if let Some(captured) = proposal.vote_threshold {
        captured
    } else if proposal.governing_token_mint == realm.community_mint {
        governance.config.community_vote_threshold
    } else if Some(proposal.governing_token_mint) == realm.config.council_mint {
        governance.config.council_vote_threshold
    } else {
        return Err(DecodeError::Relationship("proposal governing mint"));
    };
    validate_supported_threshold(threshold, false)?;
    Ok(threshold)
}

pub fn voting_deadline(
    proposal: &ProposalV2,
    governance: &GovernanceV2,
) -> Result<i64, DecodeError> {
    let voting_at = proposal
        .voting_at
        .ok_or(DecodeError::Relationship("proposal voting_at"))?;
    voting_at
        .checked_add(governance.config.voting_base_time as i64)
        .and_then(|value| value.checked_add(governance.config.voting_cool_off_time as i64))
        .ok_or(DecodeError::ArithmeticOverflow)
}

pub fn has_voting_ended(
    proposal: &ProposalV2,
    governance: &GovernanceV2,
    now: i64,
) -> Result<bool, DecodeError> {
    Ok(now > voting_deadline(proposal, governance)?)
}

pub fn execution_hold_up_end(
    proposal: &ProposalV2,
    governance: &GovernanceV2,
) -> Result<i64, DecodeError> {
    proposal
        .voting_completed_at
        .ok_or(DecodeError::Relationship("proposal voting_completed_at"))?
        .checked_add(governance.config.transactions_hold_up_time as i64)
        .ok_or(DecodeError::ArithmeticOverflow)
}

pub fn can_execute_at(
    proposal: &ProposalV2,
    governance: &GovernanceV2,
    now: i64,
) -> Result<bool, DecodeError> {
    Ok(now > execution_hold_up_end(proposal, governance)?)
}

pub fn expected_proposal_transactions(
    governance_program_id: &Pubkey,
    proposal_address: &Pubkey,
    proposal: &ProposalV2,
    max_transactions: usize,
) -> Result<Vec<ExpectedProposalTransaction>, DecodeError> {
    let mut expected = Vec::new();
    for (option_index, option) in proposal.options.iter().enumerate() {
        // `transactions_next_index` is the high-water mark. Removed accounts
        // leave null holes, so every index below it must still be fetched.
        for transaction_index in 0..option.transactions_next_index {
            if expected.len() >= max_transactions {
                return Err(DecodeError::LimitExceeded("proposal transactions"));
            }
            let (address, bump) = proposal_transaction_address(
                governance_program_id,
                proposal_address,
                option_index as u8,
                transaction_index,
            )?;
            expected.push(ExpectedProposalTransaction {
                option_index: option_index as u8,
                transaction_index,
                address,
                bump,
            });
        }
    }
    Ok(expected)
}

pub fn validate_proposal_transaction_relationship(
    governance_program_id: &Pubkey,
    proposal_address: &Pubkey,
    transaction_address: &Pubkey,
    transaction: &ProposalTransactionV2,
) -> Result<(), DecodeError> {
    if transaction.proposal != *proposal_address {
        return Err(DecodeError::Relationship("transaction proposal"));
    }
    let expected = proposal_transaction_address(
        governance_program_id,
        proposal_address,
        transaction.option_index,
        transaction.transaction_index,
    )?
    .0;
    if expected != *transaction_address {
        return Err(DecodeError::Relationship("transaction PDA"));
    }
    Ok(())
}

pub fn validate_proposal_transaction_set(
    governance_program_id: &Pubkey,
    proposal_address: &Pubkey,
    proposal: &ProposalV2,
    transactions: &[(Pubkey, ProposalTransactionV2)],
    max_transactions: usize,
) -> Result<(), DecodeError> {
    let expected = expected_proposal_transactions(
        governance_program_id,
        proposal_address,
        proposal,
        max_transactions,
    )?;
    let mut seen = BTreeSet::new();
    let mut option_counts = vec![0usize; proposal.options.len()];
    for (address, transaction) in transactions {
        validate_proposal_transaction_relationship(
            governance_program_id,
            proposal_address,
            address,
            transaction,
        )?;
        if !seen.insert(*address) {
            return Err(DecodeError::Relationship("duplicate transaction"));
        }
        let option = proposal
            .options
            .get(transaction.option_index as usize)
            .ok_or(DecodeError::Relationship("transaction option index"))?;
        if transaction.transaction_index >= option.transactions_next_index {
            return Err(DecodeError::Relationship("transaction index"));
        }
        option_counts[transaction.option_index as usize] += 1;
    }
    if seen
        .iter()
        .any(|address| !expected.iter().any(|item| item.address == *address))
    {
        return Err(DecodeError::Relationship("unexpected transaction"));
    }
    for (option, present) in proposal.options.iter().zip(option_counts) {
        if present != option.transactions_count as usize {
            return Err(DecodeError::Relationship("transaction count"));
        }
    }
    Ok(())
}

fn read_governance_config(reader: &mut Reader<'_>) -> Result<GovernanceConfig, DecodeError> {
    let community_vote_threshold = read_vote_threshold(reader)?;
    let min_community_weight_to_create_proposal = reader.u64()?;
    let transactions_hold_up_time = reader.u32()?;
    let voting_base_time = reader.u32()?;
    let community_vote_tipping = read_vote_tipping(reader)?;
    let council_vote_threshold = read_vote_threshold(reader)?;
    if council_vote_threshold == VoteThreshold::YesVotePercentage(0) {
        return Err(DecodeError::Unsupported("legacy governance config marker"));
    }
    let council_veto_vote_threshold = read_vote_threshold(reader)?;
    let min_council_weight_to_create_proposal = reader.u64()?;
    let council_vote_tipping = read_vote_tipping(reader)?;
    let community_veto_vote_threshold = read_vote_threshold(reader)?;
    let voting_cool_off_time = reader.u32()?;
    let deposit_exempt_proposal_count = reader.u8()?;

    for threshold in [
        community_vote_threshold,
        council_vote_threshold,
        council_veto_vote_threshold,
        community_veto_vote_threshold,
    ] {
        validate_supported_threshold(threshold, true)?;
    }
    Ok(GovernanceConfig {
        community_vote_threshold,
        min_community_weight_to_create_proposal,
        transactions_hold_up_time,
        voting_base_time,
        community_vote_tipping,
        council_vote_threshold,
        council_veto_vote_threshold,
        min_council_weight_to_create_proposal,
        council_vote_tipping,
        community_veto_vote_threshold,
        voting_cool_off_time,
        deposit_exempt_proposal_count,
    })
}

fn read_governing_token_config(
    reader: &mut Reader<'_>,
) -> Result<GoverningTokenConfig, DecodeError> {
    let voter_weight_addin = reader.option_pubkey()?;
    let max_voter_weight_addin = reader.option_pubkey()?;
    let token_type = match reader.u8()? {
        0 => GoverningTokenType::Liquid,
        1 => GoverningTokenType::Membership,
        2 => GoverningTokenType::Dormant,
        _ => return Err(DecodeError::Invalid("governing token type")),
    };
    reader.skip(4)?;
    let count = reader.bounded_count(MAX_LOCK_AUTHORITIES, "lock authorities")?;
    let mut lock_authorities = Vec::with_capacity(count);
    for _ in 0..count {
        lock_authorities.push(reader.pubkey()?);
    }
    Ok(GoverningTokenConfig {
        voter_weight_addin,
        max_voter_weight_addin,
        token_type,
        lock_authorities,
    })
}

fn read_max_voter_weight_source(
    reader: &mut Reader<'_>,
) -> Result<MintMaxVoterWeightSource, DecodeError> {
    match reader.u8()? {
        0 => {
            let fraction = reader.u64()?;
            if !(1..=10_000_000_000).contains(&fraction) {
                return Err(DecodeError::Invalid("max voter weight supply fraction"));
            }
            Ok(MintMaxVoterWeightSource::SupplyFraction(fraction))
        }
        1 => {
            let absolute = reader.u64()?;
            if absolute == 0 {
                return Err(DecodeError::Invalid("absolute max voter weight"));
            }
            Ok(MintMaxVoterWeightSource::Absolute(absolute))
        }
        _ => Err(DecodeError::Invalid("max voter weight source")),
    }
}

fn validate_supported_threshold(
    threshold: VoteThreshold,
    allow_disabled: bool,
) -> Result<(), DecodeError> {
    match threshold {
        VoteThreshold::YesVotePercentage(1..=100) => Ok(()),
        VoteThreshold::YesVotePercentage(_) => {
            Err(DecodeError::Invalid("vote threshold percentage"))
        }
        VoteThreshold::QuorumPercentage(_) => {
            Err(DecodeError::Unsupported("quorum vote threshold"))
        }
        VoteThreshold::Disabled if allow_disabled => Ok(()),
        VoteThreshold::Disabled => Err(DecodeError::Unsupported("disabled vote threshold")),
    }
}

fn validate_vote_type(vote_type: VoteType, option_count: usize) -> Result<(), DecodeError> {
    if let VoteType::MultiChoice {
        min_voter_options,
        max_voter_options,
        max_winning_options,
        ..
    } = vote_type
    {
        if option_count == 1
            || min_voter_options != 1
            || max_voter_options as usize != option_count
            || max_winning_options as usize != option_count
        {
            return Err(DecodeError::Invalid("multi-choice vote parameters"));
        }
    }
    Ok(())
}

fn read_proposal_state(reader: &mut Reader<'_>) -> Result<ProposalState, DecodeError> {
    match reader.u8()? {
        0 => Ok(ProposalState::Draft),
        1 => Ok(ProposalState::SigningOff),
        2 => Ok(ProposalState::Voting),
        3 => Ok(ProposalState::Succeeded),
        4 => Ok(ProposalState::Executing),
        5 => Ok(ProposalState::Completed),
        6 => Ok(ProposalState::Cancelled),
        7 => Ok(ProposalState::Defeated),
        8 => Ok(ProposalState::ExecutingWithErrors),
        9 => Ok(ProposalState::Vetoed),
        _ => Err(DecodeError::Invalid("proposal state")),
    }
}

fn read_option_vote_result(reader: &mut Reader<'_>) -> Result<OptionVoteResult, DecodeError> {
    match reader.u8()? {
        0 => Ok(OptionVoteResult::None),
        1 => Ok(OptionVoteResult::Succeeded),
        2 => Ok(OptionVoteResult::Defeated),
        _ => Err(DecodeError::Invalid("proposal option vote result")),
    }
}

fn read_vote_type(reader: &mut Reader<'_>) -> Result<VoteType, DecodeError> {
    match reader.u8()? {
        0 => Ok(VoteType::SingleChoice),
        1 => {
            let choice_type = match reader.u8()? {
                0 => MultiChoiceType::FullWeight,
                1 => MultiChoiceType::Weighted,
                _ => return Err(DecodeError::Invalid("multi-choice type")),
            };
            Ok(VoteType::MultiChoice {
                choice_type,
                min_voter_options: reader.u8()?,
                max_voter_options: reader.u8()?,
                max_winning_options: reader.u8()?,
            })
        }
        _ => Err(DecodeError::Invalid("proposal vote type")),
    }
}

fn read_execution_flags(reader: &mut Reader<'_>) -> Result<InstructionExecutionFlags, DecodeError> {
    match reader.u8()? {
        0 => Ok(InstructionExecutionFlags::None),
        1 => Ok(InstructionExecutionFlags::Ordered),
        2 => Ok(InstructionExecutionFlags::UseTransaction),
        _ => Err(DecodeError::Invalid("instruction execution flags")),
    }
}

fn read_vote_threshold(reader: &mut Reader<'_>) -> Result<VoteThreshold, DecodeError> {
    match reader.u8()? {
        0 => Ok(VoteThreshold::YesVotePercentage(reader.u8()?)),
        1 => Ok(VoteThreshold::QuorumPercentage(reader.u8()?)),
        2 => Ok(VoteThreshold::Disabled),
        _ => Err(DecodeError::Invalid("vote threshold")),
    }
}

fn read_vote_tipping(reader: &mut Reader<'_>) -> Result<VoteTipping, DecodeError> {
    match reader.u8()? {
        0 => Ok(VoteTipping::Strict),
        1 => Ok(VoteTipping::Early),
        2 => Ok(VoteTipping::Disabled),
        _ => Err(DecodeError::Invalid("vote tipping")),
    }
}

fn read_transaction_status(
    reader: &mut Reader<'_>,
) -> Result<TransactionExecutionStatus, DecodeError> {
    match reader.u8()? {
        0 => Ok(TransactionExecutionStatus::None),
        1 => Ok(TransactionExecutionStatus::Success),
        2 => Ok(TransactionExecutionStatus::Error),
        _ => Err(DecodeError::Invalid("transaction execution status")),
    }
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() > MAX_ACCOUNT_DATA_LEN {
            return Err(DecodeError::LimitExceeded("account data"));
        }
        Ok(Self { data, offset: 0 })
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DecodeError::ArithmeticOverflow)?;
        let value = self
            .data
            .get(self.offset..end)
            .ok_or(DecodeError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn skip(&mut self, len: usize) -> Result<(), DecodeError> {
        self.take(len).map(|_| ())
    }

    fn expect_tag(&mut self, expected: u8) -> Result<(), DecodeError> {
        if self.u8()? != expected {
            return Err(DecodeError::Invalid("account tag"));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::Invalid("bool")),
        }
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?.try_into().map_err(|_| DecodeError::Truncated)
    }

    fn pubkey(&mut self) -> Result<Pubkey, DecodeError> {
        Ok(Pubkey::new(self.array()?))
    }

    fn option_tag(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::Invalid("option tag")),
        }
    }

    fn option_u32(&mut self) -> Result<Option<u32>, DecodeError> {
        if self.option_tag()? {
            Ok(Some(self.u32()?))
        } else {
            Ok(None)
        }
    }

    fn option_u64(&mut self) -> Result<Option<u64>, DecodeError> {
        if self.option_tag()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }

    fn option_i64(&mut self) -> Result<Option<i64>, DecodeError> {
        if self.option_tag()? {
            Ok(Some(self.i64()?))
        } else {
            Ok(None)
        }
    }

    fn option_pubkey(&mut self) -> Result<Option<Pubkey>, DecodeError> {
        if self.option_tag()? {
            Ok(Some(self.pubkey()?))
        } else {
            Ok(None)
        }
    }

    fn option_vote_threshold(&mut self) -> Result<Option<VoteThreshold>, DecodeError> {
        if self.option_tag()? {
            Ok(Some(read_vote_threshold(self)?))
        } else {
            Ok(None)
        }
    }

    fn bounded_count(&mut self, maximum: usize, name: &'static str) -> Result<usize, DecodeError> {
        let count = self.u32()? as usize;
        if count > maximum {
            return Err(DecodeError::LimitExceeded(name));
        }
        Ok(count)
    }

    fn byte_vec(&mut self, maximum: usize, name: &'static str) -> Result<Vec<u8>, DecodeError> {
        let len = self.bounded_count(maximum, name)?;
        Ok(self.take(len)?.to_vec())
    }

    fn string(&mut self, maximum: usize, name: &'static str) -> Result<String, DecodeError> {
        let bytes = self.byte_vec(maximum, name)?;
        String::from_utf8(bytes).map_err(|_| DecodeError::Invalid("UTF-8 string"))
    }
}
