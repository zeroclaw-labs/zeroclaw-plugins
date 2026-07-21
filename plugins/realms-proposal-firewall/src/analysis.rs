use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use crate::{
    config::Config,
    governance::{
        decode_governance_v2, decode_proposal_transaction_v2, decode_proposal_v2,
        decode_realm_config_account, decode_realm_v2, effective_vote_threshold,
        expected_proposal_transactions, minimum_vote_weight,
        validate_proposal_transaction_relationship, validate_proposal_transaction_set,
        voting_deadline, GovernanceConfig, GovernanceV2, InstructionExecutionFlags,
        OptionVoteResult, ProposalState, ProposalTransactionV2, ProposalV2, RealmConfigAccount,
        RealmV2, TransactionExecutionStatus, VoteThreshold, VoteTipping,
    },
    instructions::{
        decode_instruction, parse_token_account, parse_token_mint, parse_upgradeable_loader_state,
        DecodeOutcome, Operation, RealmAuthorityAction, TokenAccountData, TokenAccountState,
        TokenAuthorityType, TokenMintState, UpgradeableLoaderState,
    },
    output::{
        Finding, InstructionLocation, ProposalOptionSummary, ProposalSummary,
        ProposalTransactionSummary, Report, Severity, UnknownInstruction, Verdict,
    },
    pubkey::{
        bpf_upgradeable_loader_id, find_program_address, native_treasury_address,
        realm_config_address, spl_token_program_id, system_program_id, Pubkey,
    },
    rpc::{Account, RpcClient, Transport, MAX_MULTIPLE_ACCOUNTS},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisError {
    GenesisUnavailable,
    GenesisMismatch,
    ProposalUnavailable,
    ProposalOwnerNotAllowed,
    ProposalMalformed,
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GenesisUnavailable => "could not verify the configured Solana cluster",
            Self::GenesisMismatch => "the RPC endpoint is connected to an unexpected cluster",
            Self::ProposalUnavailable => "could not read the proposal account",
            Self::ProposalOwnerNotAllowed => {
                "the proposal owner is not an allowed governance program"
            }
            Self::ProposalMalformed => "the proposal is not a supported SPL Governance V2 proposal",
        })
    }
}

impl Error for AnalysisError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotTransaction {
    pub address: Pubkey,
    pub transaction: ProposalTransactionV2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyAccount {
    pub address: Pubkey,
    pub account: Option<Account>,
}

/// A relationship-checked, race-checked proposal snapshot. Proposal prose is
/// deliberately absent so it cannot affect analysis or output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub proposal_address: Pubkey,
    pub governance_program_id: Pubkey,
    pub proposal: ProposalV2,
    pub governance: GovernanceV2,
    pub realm: RealmV2,
    pub realm_config: Option<RealmConfigAccount>,
    pub transactions: Vec<SnapshotTransaction>,
    pub dependencies: Vec<DependencyAccount>,
    pub evidence_slot: u64,
}

struct SnapshotFailure {
    code: &'static str,
    evidence: &'static str,
    realm: Option<Pubkey>,
    evidence_slot: u64,
}

/// Performs the finalized, min-context-slot snapshot flow and then invokes the
/// same pure analyzer used by native fixture tests and the WASM component.
pub fn analyze_proposal<T: Transport>(
    config: &Config,
    proposal_address: Pubkey,
    transport: T,
) -> Result<Report, AnalysisError> {
    let client = RpcClient::from_config(config, transport);
    let genesis = client
        .get_genesis_hash()
        .map_err(|_| AnalysisError::GenesisUnavailable)?;
    if genesis != config.expected_genesis_hash {
        return Err(AnalysisError::GenesisMismatch);
    }

    let initial = client
        .get_account_info(&proposal_address, None)
        .map_err(|_| AnalysisError::ProposalUnavailable)?;
    if !config
        .governance_program_ids
        .contains(&initial.account.owner)
    {
        return Err(AnalysisError::ProposalOwnerNotAllowed);
    }
    let proposal =
        decode_proposal_v2(&initial.account.data).map_err(|_| AnalysisError::ProposalMalformed)?;
    let governance_program_id = initial.account.owner;

    match collect_snapshot(
        &client,
        config,
        proposal_address,
        governance_program_id,
        proposal.clone(),
        initial.context_slot,
        initial.account,
    ) {
        Ok(snapshot) => Ok(analyze_snapshot(&snapshot, config)),
        Err(failure) => Ok(incomplete_report(
            proposal_address,
            &proposal,
            failure.realm,
            failure.evidence_slot,
            failure.code,
            failure.evidence,
        )),
    }
}

fn collect_snapshot<T: Transport>(
    client: &RpcClient<T>,
    config: &Config,
    proposal_address: Pubkey,
    governance_program_id: Pubkey,
    proposal: ProposalV2,
    minimum_slot: u64,
    initial_proposal_account: Account,
) -> Result<Snapshot, SnapshotFailure> {
    let mut snapshot_slot = minimum_slot;
    let fail = |code, evidence, realm| SnapshotFailure {
        code,
        evidence,
        realm,
        evidence_slot: minimum_slot,
    };

    let governance_read = client
        .get_account_info(&proposal.governance, Some(snapshot_slot))
        .map_err(|_| {
            fail(
                "SNAPSHOT_INCOMPLETE",
                "A required governance account could not be read",
                None,
            )
        })?;
    snapshot_slot = governance_read.context_slot;
    if governance_read.account.owner != governance_program_id {
        return Err(fail(
            "SNAPSHOT_RELATIONSHIP",
            "The governance account has an unexpected owner",
            None,
        ));
    }
    let governance = decode_governance_v2(&governance_read.account.data).map_err(|_| {
        fail(
            "SNAPSHOT_MALFORMED",
            "The governance account is malformed or unsupported",
            None,
        )
    })?;
    let realm_address = governance.realm;
    let realm_config_address = realm_config_address(&governance_program_id, &realm_address)
        .map_err(|_| {
            fail(
                "SNAPSHOT_RELATIONSHIP",
                "The realm-config address could not be derived",
                Some(realm_address),
            )
        })?
        .0;
    let realm_reads = client
        .get_multiple_accounts(&[realm_address, realm_config_address], Some(snapshot_slot))
        .map_err(|_| {
            fail(
                "SNAPSHOT_INCOMPLETE",
                "The realm accounts could not be read",
                Some(realm_address),
            )
        })?;
    snapshot_slot = realm_reads.context_slot;
    let realm_account = realm_reads
        .accounts
        .first()
        .and_then(Option::as_ref)
        .ok_or_else(|| {
            fail(
                "SNAPSHOT_INCOMPLETE",
                "The realm account is missing",
                Some(realm_address),
            )
        })?;
    if realm_account.owner != governance_program_id {
        return Err(fail(
            "SNAPSHOT_RELATIONSHIP",
            "The realm account has an unexpected owner",
            Some(realm_address),
        ));
    }
    let realm = decode_realm_v2(&realm_account.data).map_err(|_| {
        fail(
            "SNAPSHOT_MALFORMED",
            "The realm account is malformed or unsupported",
            Some(realm_address),
        )
    })?;
    if proposal.governing_token_mint != realm.community_mint
        && Some(proposal.governing_token_mint) != realm.config.council_mint
    {
        return Err(fail(
            "SNAPSHOT_RELATIONSHIP",
            "The proposal governing mint does not belong to the realm",
            Some(realm_address),
        ));
    }
    let realm_config = match realm_reads.accounts.get(1).and_then(Option::as_ref) {
        None => None,
        Some(account) => {
            if account.owner != governance_program_id {
                return Err(fail(
                    "SNAPSHOT_RELATIONSHIP",
                    "The realm-config account has an unexpected owner",
                    Some(realm_address),
                ));
            }
            let decoded = decode_realm_config_account(&account.data).map_err(|_| {
                fail(
                    "UNSUPPORTED_VOTER_WEIGHT_ADDIN",
                    "The realm token configuration is malformed or uses an unsupported add-in",
                    Some(realm_address),
                )
            })?;
            if decoded.realm != realm_address {
                return Err(fail(
                    "SNAPSHOT_RELATIONSHIP",
                    "The realm-config account points to another realm",
                    Some(realm_address),
                ));
            }
            Some(decoded)
        }
    };
    if relevant_voter_weight_addin(&proposal, &realm, realm_config.as_ref()) {
        return Err(fail(
            "UNSUPPORTED_VOTER_WEIGHT_ADDIN",
            "A relevant voter-weight add-in prevents complete threshold analysis",
            Some(realm_address),
        ));
    }

    let expected = expected_proposal_transactions(
        &governance_program_id,
        &proposal_address,
        &proposal,
        config.max_transactions,
    )
    .map_err(|_| {
        fail(
            "RESOURCE_LIMIT_EXCEEDED",
            "The proposal transaction high-water mark exceeds the configured limit",
            Some(realm_address),
        )
    })?;
    let transaction_accounts = if expected.is_empty() {
        Vec::new()
    } else {
        let read = client
            .get_multiple_accounts(
                &expected.iter().map(|item| item.address).collect::<Vec<_>>(),
                Some(snapshot_slot),
            )
            .map_err(|_| {
                fail(
                    "SNAPSHOT_INCOMPLETE",
                    "Proposal transactions could not be read",
                    Some(realm_address),
                )
            })?;
        snapshot_slot = read.context_slot;
        read.accounts
    };

    let mut transactions = Vec::new();
    let mut decoded_set = Vec::new();
    let mut instruction_count = 0usize;
    for (expected_item, account) in expected.iter().zip(&transaction_accounts) {
        let Some(account) = account else { continue };
        if account.owner != governance_program_id {
            return Err(fail(
                "SNAPSHOT_RELATIONSHIP",
                "A proposal transaction has an unexpected owner",
                Some(realm_address),
            ));
        }
        let transaction = decode_proposal_transaction_v2(&account.data).map_err(|_| {
            fail(
                "SNAPSHOT_MALFORMED",
                "A proposal transaction is malformed",
                Some(realm_address),
            )
        })?;
        if transaction.option_index != expected_item.option_index
            || transaction.transaction_index != expected_item.transaction_index
        {
            return Err(fail(
                "SNAPSHOT_RELATIONSHIP",
                "A proposal transaction embeds an unexpected option or index",
                Some(realm_address),
            ));
        }
        validate_proposal_transaction_relationship(
            &governance_program_id,
            &proposal_address,
            &expected_item.address,
            &transaction,
        )
        .map_err(|_| {
            fail(
                "SNAPSHOT_RELATIONSHIP",
                "A proposal transaction relationship is invalid",
                Some(realm_address),
            )
        })?;
        instruction_count = instruction_count
            .checked_add(transaction.instructions.len())
            .ok_or_else(|| {
                fail(
                    "RESOURCE_LIMIT_EXCEEDED",
                    "The proposal instruction count overflowed",
                    Some(realm_address),
                )
            })?;
        if instruction_count > config.max_instructions {
            return Err(fail(
                "RESOURCE_LIMIT_EXCEEDED",
                "The proposal instruction count exceeds the configured limit",
                Some(realm_address),
            ));
        }
        decoded_set.push((expected_item.address, transaction.clone()));
        transactions.push(SnapshotTransaction {
            address: expected_item.address,
            transaction,
        });
    }
    validate_proposal_transaction_set(
        &governance_program_id,
        &proposal_address,
        &proposal,
        &decoded_set,
        config.max_transactions,
    )
    .map_err(|_| {
        fail(
            "SNAPSHOT_CARDINALITY",
            "Proposal transaction holes do not agree with the present transaction counts",
            Some(realm_address),
        )
    })?;

    let selected = selected_options(&proposal);
    let dependency_addresses = dependency_addresses(&transactions, &selected, config);
    let dependency_addresses = dependency_addresses.map_err(|_| {
        fail(
            "RESOURCE_LIMIT_EXCEEDED",
            "The required dependency set exceeds the RPC account limit",
            Some(realm_address),
        )
    })?;
    let mut dependencies = if dependency_addresses.is_empty() {
        Vec::new()
    } else {
        let read = client
            .get_multiple_accounts(&dependency_addresses, Some(snapshot_slot))
            .map_err(|_| {
                fail(
                    "SNAPSHOT_INCOMPLETE",
                    "Required instruction dependencies could not be read",
                    Some(realm_address),
                )
            })?;
        snapshot_slot = read.context_slot;
        dependency_addresses
            .into_iter()
            .zip(read.accounts)
            .map(|(address, account)| DependencyAccount { address, account })
            .collect()
    };
    // Classic Token Transfer does not carry its mint. Resolve it from the
    // source account, then fetch any newly discovered mints in one bounded pass.
    let dependency_map: BTreeMap<_, _> = dependencies
        .iter()
        .map(|item| (item.address, item.account.as_ref()))
        .collect();
    let mut extra_mints = BTreeSet::new();
    for item in &transactions {
        if !selected.contains(&item.transaction.option_index) {
            continue;
        }
        for instruction in &item.transaction.instructions {
            if let DecodeOutcome::Decoded(Operation::TokenTransfer { source, .. }) =
                decode_instruction(instruction, &config.governance_program_ids)
            {
                if let Some(Some(account)) = dependency_map.get(&source) {
                    if account.owner == spl_token_program_id() {
                        if let Ok(token) = parse_token_account(&account.data) {
                            if !dependency_map.contains_key(&token.mint) {
                                extra_mints.insert(token.mint);
                            }
                        }
                    }
                }
            }
        }
    }
    if dependencies.len().saturating_add(extra_mints.len()) > MAX_MULTIPLE_ACCOUNTS {
        return Err(fail(
            "RESOURCE_LIMIT_EXCEEDED",
            "The required dependency set exceeds the RPC account limit",
            Some(realm_address),
        ));
    }
    if !extra_mints.is_empty() {
        let addresses: Vec<_> = extra_mints.into_iter().collect();
        let read = client
            .get_multiple_accounts(&addresses, Some(snapshot_slot))
            .map_err(|_| {
                fail(
                    "SNAPSHOT_INCOMPLETE",
                    "Required token mint dependencies could not be read",
                    Some(realm_address),
                )
            })?;
        snapshot_slot = read.context_slot;
        dependencies.extend(
            addresses
                .into_iter()
                .zip(read.accounts)
                .map(|(address, account)| DependencyAccount { address, account }),
        );
    }

    let mut final_accounts = BTreeMap::<Pubkey, Option<Account>>::new();
    let core_accounts = [
        (proposal_address, Some(initial_proposal_account)),
        (proposal.governance, Some(governance_read.account)),
        (realm_address, realm_reads.accounts[0].clone()),
        (realm_config_address, realm_reads.accounts[1].clone()),
    ];
    for (address, account) in core_accounts
        .into_iter()
        .chain(
            expected
                .iter()
                .map(|item| item.address)
                .zip(transaction_accounts.iter().cloned()),
        )
        .chain(
            dependencies
                .iter()
                .map(|item| (item.address, item.account.clone())),
        )
    {
        if let Some(previous) = final_accounts.insert(address, account.clone()) {
            if previous != account {
                return Err(SnapshotFailure {
                    code: "SNAPSHOT_RACE",
                    evidence: "The same account had contradictory data during collection",
                    realm: Some(realm_address),
                    evidence_slot: snapshot_slot,
                });
            }
        }
    }
    if final_accounts.len() > MAX_MULTIPLE_ACCOUNTS {
        return Err(fail(
            "RESOURCE_LIMIT_EXCEEDED",
            "A coherent final snapshot exceeds the RPC account limit",
            Some(realm_address),
        ));
    }
    let final_addresses: Vec<_> = final_accounts.keys().copied().collect();
    let expected_final: Vec<_> = final_accounts.into_values().collect();
    let final_read = client
        .get_multiple_accounts(&final_addresses, Some(snapshot_slot))
        .map_err(|_| {
            fail(
                "SNAPSHOT_INCOMPLETE",
                "The final snapshot check could not be completed",
                Some(realm_address),
            )
        })?;
    snapshot_slot = final_read.context_slot;
    if final_read.accounts != expected_final {
        return Err(SnapshotFailure {
            code: "SNAPSHOT_RACE",
            evidence: "A security-relevant account changed during snapshot collection",
            realm: Some(realm_address),
            evidence_slot: snapshot_slot,
        });
    }

    Ok(Snapshot {
        proposal_address,
        governance_program_id,
        proposal,
        governance,
        realm,
        realm_config,
        transactions,
        dependencies,
        evidence_slot: snapshot_slot,
    })
}

fn dependency_addresses(
    transactions: &[SnapshotTransaction],
    selected_options: &BTreeSet<u8>,
    config: &Config,
) -> Result<Vec<Pubkey>, ()> {
    let mut addresses = BTreeSet::new();
    for item in transactions {
        if !selected_options.contains(&item.transaction.option_index) {
            continue;
        }
        for instruction in &item.transaction.instructions {
            if let DecodeOutcome::Decoded(operation) =
                decode_instruction(instruction, &config.governance_program_ids)
            {
                for address in operation_dependencies(&operation) {
                    addresses.insert(address);
                    if addresses.len() > MAX_MULTIPLE_ACCOUNTS {
                        return Err(());
                    }
                }
            }
        }
    }
    Ok(addresses.into_iter().collect())
}

fn operation_dependencies(operation: &Operation) -> Vec<Pubkey> {
    match operation {
        Operation::SystemTransfer { source, .. } => vec![*source],
        Operation::TokenTransfer {
            source,
            destination,
            ..
        } => vec![*source, *destination],
        Operation::TokenTransferChecked {
            source,
            mint,
            destination,
            ..
        } => vec![*source, *mint, *destination],
        Operation::TokenApprove { source, .. } => vec![*source],
        Operation::TokenSetAuthority { account, .. } => vec![*account],
        Operation::TokenMintTo {
            mint, destination, ..
        } => vec![*mint, *destination],
        Operation::TokenBurn { source, mint, .. } => vec![*source, *mint],
        Operation::TokenCloseAccount { account, .. } => vec![*account],
        Operation::AssociatedTokenCreate { mint, .. } => vec![*mint],
        Operation::UpgradeableLoaderUpgrade {
            programdata,
            program,
            buffer,
            spill,
            ..
        } => {
            vec![*programdata, *program, *buffer, *spill]
        }
        Operation::UpgradeableLoaderSetAuthority { account, .. } => vec![*account],
        Operation::SetGovernanceConfig { governance, .. } => vec![*governance],
        Operation::SetRealmAuthority {
            realm,
            new_authority,
            action,
            ..
        } => {
            let mut dependencies = vec![*realm];
            if *action == RealmAuthorityAction::SetChecked {
                if let Some(authority) = new_authority {
                    dependencies.push(*authority);
                }
            }
            dependencies
        }
    }
}

#[derive(Clone)]
struct LocatedOperation {
    location: InstructionLocation,
    operation: Operation,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct FlowKey {
    source: Pubkey,
    mint: Option<Pubkey>,
}

struct Flow {
    amount: u128,
    balance: u64,
    decimals: u8,
    location: InstructionLocation,
}

struct AnalysisState {
    findings: Vec<Finding>,
    unknown: Vec<UnknownInstruction>,
    complete: bool,
}

impl AnalysisState {
    fn finding(
        &mut self,
        code: &str,
        severity: Severity,
        evidence: impl Into<String>,
        location: Option<InstructionLocation>,
    ) {
        self.findings.push(Finding {
            code: code.to_owned(),
            severity,
            evidence: evidence.into(),
            location,
        });
    }

    fn incomplete(&mut self, evidence: &'static str, location: Option<InstructionLocation>) {
        self.complete = false;
        self.finding("DEPENDENCY_INVALID", Severity::Critical, evidence, location);
    }
}

pub fn analyze_snapshot(snapshot: &Snapshot, config: &Config) -> Report {
    let selected = selected_options(&snapshot.proposal);
    let mut state = AnalysisState {
        findings: Vec::new(),
        unknown: Vec::new(),
        complete: true,
    };

    if !config
        .governance_program_ids
        .contains(&snapshot.governance_program_id)
        || snapshot.proposal.governance == Pubkey::default()
        || snapshot.governance.realm == Pubkey::default()
        || (snapshot.proposal.governing_token_mint != snapshot.realm.community_mint
            && Some(snapshot.proposal.governing_token_mint) != snapshot.realm.config.council_mint)
    {
        state.incomplete(
            "The synthetic snapshot has invalid governance relationships",
            None,
        );
    }

    let transaction_set = snapshot
        .transactions
        .iter()
        .map(|item| (item.address, item.transaction.clone()))
        .collect::<Vec<_>>();
    if validate_proposal_transaction_set(
        &snapshot.governance_program_id,
        &snapshot.proposal_address,
        &snapshot.proposal,
        &transaction_set,
        config.max_transactions,
    )
    .is_err()
    {
        state.incomplete(
            "The snapshot does not contain the complete proposal transaction set",
            None,
        );
    }
    let all_instruction_count = snapshot
        .transactions
        .iter()
        .try_fold(0usize, |count, item| {
            count.checked_add(item.transaction.instructions.len())
        });
    if all_instruction_count.is_none_or(|count| count > config.max_instructions) {
        state.complete = false;
        state.finding(
            "RESOURCE_LIMIT_EXCEEDED",
            Severity::Critical,
            "The snapshot exceeds configured analysis limits",
            None,
        );
    }
    if snapshot
        .realm_config
        .as_ref()
        .is_some_and(|config| config.realm != snapshot.governance.realm)
        || relevant_voter_weight_addin(
            &snapshot.proposal,
            &snapshot.realm,
            snapshot.realm_config.as_ref(),
        )
    {
        state.incomplete(
            "A voter-weight add-in or realm-config relationship prevents complete analysis",
            None,
        );
    }
    if snapshot.proposal.execution_flags != InstructionExecutionFlags::None {
        state.incomplete(
            "The proposal uses unsupported instruction execution flags",
            None,
        );
    }
    validate_execution_consistency(snapshot, &selected, &mut state);

    let mut transaction_count = 0usize;
    let mut instruction_count = 0usize;
    let mut operations = Vec::new();
    for item in &snapshot.transactions {
        if validate_proposal_transaction_relationship(
            &snapshot.governance_program_id,
            &snapshot.proposal_address,
            &item.address,
            &item.transaction,
        )
        .is_err()
        {
            state.incomplete("A snapshot transaction relationship is invalid", None);
            continue;
        }
        if !selected.contains(&item.transaction.option_index) {
            continue;
        }
        transaction_count += 1;
        for (instruction_index, instruction) in item.transaction.instructions.iter().enumerate() {
            instruction_count += 1;
            let location = InstructionLocation {
                option_index: item.transaction.option_index,
                transaction_index: item.transaction.transaction_index,
                instruction_index: u16::try_from(instruction_index).unwrap_or(u16::MAX),
            };
            match decode_instruction(instruction, &config.governance_program_ids) {
                DecodeOutcome::Decoded(operation) => operations.push(LocatedOperation {
                    location,
                    operation,
                }),
                DecodeOutcome::UnsupportedProgram { program_id } => {
                    state.finding(
                        "UNKNOWN_PROGRAM",
                        Severity::Critical,
                        format!("Unsupported program {program_id} is invoked"),
                        Some(location.clone()),
                    );
                    state.unknown.push(UnknownInstruction {
                        program_id: program_id.to_string(),
                        tag: instruction_tag(&instruction.data),
                        location,
                    });
                }
                DecodeOutcome::UnsupportedInstruction {
                    program_id, tag, ..
                } => {
                    state.finding(
                        "UNKNOWN_INSTRUCTION",
                        Severity::Critical,
                        format!("Program {program_id} uses an unsupported instruction"),
                        Some(location.clone()),
                    );
                    state.unknown.push(UnknownInstruction {
                        program_id: program_id.to_string(),
                        tag,
                        location,
                    });
                }
                DecodeOutcome::Malformed(malformed) => {
                    state.complete = false;
                    state.finding(
                        "MALFORMED_INSTRUCTION",
                        Severity::Critical,
                        format!("Malformed instruction for program {}", malformed.program_id),
                        Some(location),
                    );
                }
            }
        }
    }
    if transaction_count > config.max_transactions || instruction_count > config.max_instructions {
        state.complete = false;
        state.finding(
            "RESOURCE_LIMIT_EXCEEDED",
            Severity::Critical,
            "The snapshot exceeds configured analysis limits",
            None,
        );
    }

    let threshold =
        effective_vote_threshold(&snapshot.proposal, &snapshot.governance, &snapshot.realm);
    let threshold_percent = match threshold {
        Ok(VoteThreshold::YesVotePercentage(percent)) => {
            if percent <= 5 {
                state.finding(
                    "LOW_APPROVAL_THRESHOLD",
                    Severity::High,
                    format!("The captured approval threshold is {percent}%"),
                    None,
                );
            }
            if let Some(maximum) = snapshot.proposal.max_vote_weight {
                if let Ok(required) =
                    minimum_vote_weight(VoteThreshold::YesVotePercentage(percent), maximum)
                {
                    let required = match snapshot.proposal.deny_vote_weight {
                        Some(deny) => match deny.checked_add(1) {
                            Some(deny_requirement) => required.max(deny_requirement),
                            None => {
                                state.incomplete(
                                    "The effective winning vote requirement overflowed",
                                    None,
                                );
                                required
                            }
                        },
                        None => required,
                    };
                    for option in snapshot
                        .proposal
                        .options
                        .iter()
                        .filter(|option| option.vote_result == OptionVoteResult::Succeeded)
                    {
                        let within_margin = (option.vote_weight as u128)
                            .checked_mul(100)
                            .zip((required as u128).checked_mul(110))
                            .is_some_and(|(weight, boundary)| weight <= boundary);
                        if within_margin && option.vote_weight >= required {
                            state.finding(
                                "BARELY_ABOVE_THRESHOLD",
                                Severity::High,
                                format!(
                                    "Winning weight {} is within 10% of required weight {required}",
                                    option.vote_weight
                                ),
                                None,
                            );
                        }
                    }
                } else {
                    state.incomplete("The required vote weight could not be calculated", None);
                }
            }
            Some(percent)
        }
        _ => {
            state.incomplete(
                "The effective vote threshold is unavailable or unsupported",
                None,
            );
            None
        }
    };
    if snapshot.governance.config.transactions_hold_up_time == 0 {
        state.finding(
            "ZERO_EXECUTION_HOLDUP",
            Severity::High,
            "Successful instructions have zero seconds of execution hold-up",
            None,
        );
    }

    let treasury = native_treasury_address(
        &snapshot.governance_program_id,
        &snapshot.proposal.governance,
    )
    .map(|value| value.0);
    let treasury = match treasury {
        Ok(value) => value,
        Err(_) => {
            state.incomplete(
                "The canonical governance treasury could not be derived",
                None,
            );
            Pubkey::default()
        }
    };
    let controlled = [snapshot.proposal.governance, treasury];
    let unique_dependency_count = snapshot
        .dependencies
        .iter()
        .map(|dependency| dependency.address)
        .collect::<BTreeSet<_>>()
        .len();
    if unique_dependency_count != snapshot.dependencies.len()
        || unique_dependency_count > MAX_MULTIPLE_ACCOUNTS
    {
        state.incomplete(
            "The snapshot dependency set is duplicate or oversized",
            None,
        );
    }
    let dependencies: BTreeMap<_, _> = snapshot
        .dependencies
        .iter()
        .map(|item| (item.address, item.account.as_ref()))
        .collect();
    let mut planned_accounts = BTreeMap::new();
    for located in &operations {
        if let Operation::AssociatedTokenCreate {
            account,
            owner,
            mint,
            ..
        } = &located.operation
        {
            planned_accounts.insert(
                (located.location.option_index, *account),
                (*owner, *mint, located.location.clone()),
            );
        }
    }

    let mut flows = BTreeMap::<FlowKey, Flow>::new();
    for located in &operations {
        analyze_operation(
            snapshot,
            config,
            located,
            &controlled,
            &dependencies,
            &planned_accounts,
            &mut flows,
            &mut state,
        );
    }
    for (key, flow) in flows {
        let critical = ratio_reached(flow.amount, flow.balance, config.critical_outflow_bps);
        let large = ratio_reached(flow.amount, flow.balance, config.large_outflow_bps);
        let quantity = decimal_quantity(flow.amount, flow.decimals);
        let asset = key
            .mint
            .map(|mint| mint.to_string())
            .unwrap_or_else(|| "SOL".to_owned());
        if critical {
            state.finding(
                "TREASURY_DRAIN",
                Severity::Critical,
                format!("Aggregate outflow is {quantity} {asset} from source {} with current balance {}", key.source, decimal_quantity(flow.balance as u128, flow.decimals)),
                Some(flow.location),
            );
        } else if large {
            state.finding(
                "LARGE_TREASURY_OUTFLOW",
                Severity::High,
                format!("Aggregate outflow is {quantity} {asset} from source {} with current balance {}", key.source, decimal_quantity(flow.balance as u128, flow.decimals)),
                Some(flow.location),
            );
        }
    }

    let summary = ProposalSummary {
        address: snapshot.proposal_address.to_string(),
        state: proposal_state(snapshot.proposal.state).to_owned(),
        governance: snapshot.proposal.governance.to_string(),
        realm: snapshot.governance.realm.to_string(),
        threshold_percent,
        hold_up_seconds: snapshot
            .governance
            .config
            .transactions_hold_up_time
            .to_string(),
        voting_at: decimal_option(snapshot.proposal.voting_at),
        voting_completed_at: decimal_option(snapshot.proposal.voting_completed_at),
        executing_at: decimal_option(snapshot.proposal.executing_at),
        closed_at: decimal_option(snapshot.proposal.closed_at),
        max_vote_weight: snapshot
            .proposal
            .max_vote_weight
            .map(|value| value.to_string()),
        deny_vote_weight: snapshot
            .proposal
            .deny_vote_weight
            .map(|value| value.to_string()),
        abstain_vote_weight: snapshot
            .proposal
            .abstain_vote_weight
            .map(|value| value.to_string()),
        veto_vote_weight: snapshot.proposal.veto_vote_weight.to_string(),
        voting_deadline: voting_deadline(&snapshot.proposal, &snapshot.governance)
            .ok()
            .map(|value| value.to_string()),
        analyzed_options: selected.into_iter().collect(),
        options: proposal_option_summaries(&snapshot.proposal),
        transactions: proposal_transaction_summaries(snapshot),
        transaction_count: transaction_count.to_string(),
        instruction_count: instruction_count.to_string(),
    };
    let mut report = Report {
        verdict: Verdict::Low,
        complete: state.complete,
        proposal: summary,
        findings: state.findings,
        unknown_instructions: state.unknown,
        evidence_slot: snapshot.evidence_slot.to_string(),
        links: explorer_links(
            snapshot.proposal_address,
            snapshot.proposal.governance,
            snapshot.governance.realm,
        ),
    };
    report.canonicalize();
    report
}

#[allow(clippy::too_many_arguments)]
fn analyze_operation(
    snapshot: &Snapshot,
    config: &Config,
    located: &LocatedOperation,
    controlled: &[Pubkey; 2],
    dependencies: &BTreeMap<Pubkey, Option<&Account>>,
    planned_accounts: &BTreeMap<(u8, Pubkey), (Pubkey, Pubkey, InstructionLocation)>,
    flows: &mut BTreeMap<FlowKey, Flow>,
    state: &mut AnalysisState,
) {
    let location = Some(located.location.clone());
    match &located.operation {
        Operation::SystemTransfer {
            source,
            destination,
            lamports,
        } => {
            let Some(account) = dependency(dependencies, source, state, location.clone()) else {
                return;
            };
            if account.owner != system_program_id() {
                state.incomplete(
                    "A native transfer source is not System Program owned",
                    location,
                );
                return;
            }
            if controlled.contains(source) {
                if !is_allowed_owner(*destination, controlled, config) {
                    state.finding(
                        "EXTERNAL_RECIPIENT",
                        Severity::High,
                        format!("SOL is sent to external address {destination}"),
                        location.clone(),
                    );
                }
                add_flow(
                    flows,
                    FlowKey {
                        source: *source,
                        mint: None,
                    },
                    *lamports,
                    account.lamports,
                    9,
                    &located.location,
                    state,
                );
            }
        }
        Operation::TokenTransfer {
            source,
            destination,
            authority,
            amount,
        }
        | Operation::TokenTransferChecked {
            source,
            destination,
            authority,
            amount,
            ..
        } => {
            let Some(source_account) = token_account(dependencies, source, state, location.clone())
            else {
                return;
            };
            let planned = planned_accounts
                .get(&(located.location.option_index, *destination))
                .cloned();
            let destination_account = dependencies.get(destination).and_then(|value| *value);
            let (destination_owner, destination_mint) = if let Some(account) = destination_account {
                if account.owner != spl_token_program_id() {
                    state.incomplete("A token destination has an unexpected owner", location);
                    return;
                }
                match parse_token_account(&account.data) {
                    Ok(token) if token.state != TokenAccountState::Uninitialized => {
                        (token.owner, token.mint)
                    }
                    _ => {
                        state.incomplete(
                            "A token destination is malformed or uninitialized",
                            location,
                        );
                        return;
                    }
                }
            } else if let Some((owner, mint, _)) = planned
                .as_ref()
                .filter(|(_, _, create_location)| create_location < &located.location)
            {
                (*owner, *mint)
            } else {
                state.incomplete("A required token destination is missing", location);
                return;
            };
            if source_account.mint != destination_mint
                || !valid_token_authority(&source_account, *authority, *amount)
            {
                state.incomplete(
                    "Token transfer mint or authority data is contradictory",
                    location,
                );
                return;
            }
            let Some(mint_state) =
                token_mint(dependencies, &source_account.mint, state, location.clone())
            else {
                return;
            };
            if let Operation::TokenTransferChecked { mint, decimals, .. } = &located.operation {
                if *mint != source_account.mint || *decimals != mint_state.decimals {
                    state.incomplete(
                        "TransferChecked mint or decimals do not match mint state",
                        location,
                    );
                    return;
                }
            }
            if source == destination {
                return;
            }
            let outflow =
                controlled.contains(&source_account.owner) || controlled.contains(authority);
            if outflow {
                if !is_allowed_owner(destination_owner, controlled, config) {
                    state.finding(
                        "EXTERNAL_RECIPIENT",
                        Severity::High,
                        format!("Token destination owner {destination_owner} is external"),
                        location.clone(),
                    );
                }
                if planned
                    .as_ref()
                    .is_some_and(|(_, _, create_location)| create_location < &located.location)
                {
                    state.finding(
                        "FRESH_DESTINATION_ACCOUNT",
                        Severity::High,
                        format!("The proposal creates and funds token account {destination}"),
                        location.clone(),
                    );
                }
                if config.allowed_mints.is_empty()
                    || !config.allowed_mints.contains(&source_account.mint)
                {
                    state.finding(
                        "UNAPPROVED_MINT",
                        Severity::High,
                        format!(
                            "Transfer mint {} is not approved by local policy",
                            source_account.mint
                        ),
                        location.clone(),
                    );
                }
                add_flow(
                    flows,
                    FlowKey {
                        source: *source,
                        mint: Some(source_account.mint),
                    },
                    *amount,
                    source_account.amount,
                    mint_state.decimals,
                    &located.location,
                    state,
                );
            }
        }
        Operation::TokenApprove {
            source,
            delegate,
            authority,
            amount,
        } => {
            let Some(source_account) = token_account(dependencies, source, state, location.clone())
            else {
                return;
            };
            if !valid_token_authority(&source_account, *authority, *amount) {
                state.incomplete(
                    "Token approval authority does not match token state",
                    location,
                );
            } else {
                state.finding(
                    "TOKEN_AUTHORITY_CHANGE",
                    Severity::Critical,
                    format!(
                        "Delegate {delegate} is approved to spend {} raw units",
                        amount
                    ),
                    location,
                );
            }
        }
        Operation::TokenSetAuthority {
            account,
            current_authority,
            authority_type,
            new_authority,
        } => {
            let Some(raw) = dependency(dependencies, account, state, location.clone()) else {
                return;
            };
            if raw.owner != spl_token_program_id()
                || !token_authority_matches(raw, *authority_type, *current_authority)
            {
                state.incomplete("SetAuthority does not match current token state", location);
            } else {
                let next = new_authority
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "removed".to_owned());
                state.finding(
                    "TOKEN_AUTHORITY_CHANGE",
                    Severity::Critical,
                    format!("Token authority is changed to {next}"),
                    location,
                );
            }
        }
        Operation::TokenMintTo {
            mint,
            destination,
            authority,
            amount,
        } => {
            let Some(mint_state) = token_mint(dependencies, mint, state, location.clone()) else {
                return;
            };
            let Some(destination_state) =
                token_account(dependencies, destination, state, location.clone())
            else {
                return;
            };
            if mint_state.mint_authority != Some(*authority) || destination_state.mint != *mint {
                state.incomplete(
                    "MintTo authority or destination mint is contradictory",
                    location,
                );
            } else {
                state.finding(
                    "TOKEN_MINT",
                    Severity::High,
                    format!(
                        "{} tokens are minted to {destination}",
                        decimal_quantity(*amount as u128, mint_state.decimals)
                    ),
                    location.clone(),
                );
                if !is_allowed_owner(destination_state.owner, controlled, config) {
                    state.finding(
                        "EXTERNAL_RECIPIENT",
                        Severity::High,
                        format!(
                            "Minted tokens are sent to external owner {}",
                            destination_state.owner
                        ),
                        location,
                    );
                }
            }
        }
        Operation::TokenBurn {
            source,
            mint,
            authority,
            amount,
        } => {
            let Some(source_state) = token_account(dependencies, source, state, location.clone())
            else {
                return;
            };
            let Some(mint_state) = token_mint(dependencies, mint, state, location.clone()) else {
                return;
            };
            if source_state.mint != *mint
                || !valid_token_authority(&source_state, *authority, *amount)
            {
                state.incomplete("Burn authority or mint is contradictory", location);
            } else {
                state.finding(
                    "TOKEN_BURN",
                    Severity::High,
                    format!(
                        "{} tokens are burned from {source}",
                        decimal_quantity(*amount as u128, mint_state.decimals)
                    ),
                    location,
                );
            }
        }
        Operation::TokenCloseAccount {
            account,
            destination,
            authority,
        } => {
            let Some(token) = token_account(dependencies, account, state, location.clone()) else {
                return;
            };
            let valid = token.close_authority.unwrap_or(token.owner) == *authority;
            if !valid {
                state.incomplete(
                    "CloseAccount authority does not match token state",
                    location,
                );
            } else {
                state.finding(
                    "TOKEN_ACCOUNT_CLOSE",
                    Severity::High,
                    format!("Token account {account} is closed to {destination}"),
                    location.clone(),
                );
                if (controlled.contains(&token.owner) || controlled.contains(authority))
                    && !is_allowed_owner(*destination, controlled, config)
                {
                    state.finding(
                        "EXTERNAL_RECIPIENT",
                        Severity::High,
                        format!(
                            "Closed-account lamports are sent to external address {destination}"
                        ),
                        location,
                    );
                }
            }
        }
        Operation::AssociatedTokenCreate { mint, .. } => {
            let _ = token_mint(dependencies, mint, state, location);
        }
        Operation::UpgradeableLoaderUpgrade {
            programdata,
            program,
            buffer,
            spill,
            current_authority,
            ..
        } => {
            let spill_exists = dependency(dependencies, spill, state, location.clone()).is_some();
            if validate_upgrade(
                dependencies,
                *programdata,
                *program,
                *buffer,
                *current_authority,
            ) && spill_exists
            {
                state.finding(
                    "PROGRAM_UPGRADE",
                    Severity::Critical,
                    format!("Upgradeable program {program} receives new code"),
                    location,
                );
                if !is_allowed_owner(*spill, controlled, config) {
                    state.finding(
                        "EXTERNAL_RECIPIENT",
                        Severity::High,
                        format!("Upgrade spill lamports are sent to external address {spill}"),
                        Some(located.location.clone()),
                    );
                }
            } else {
                state.incomplete("Upgradeable-loader Program, ProgramData, Buffer, or authority state is contradictory", location);
            }
        }
        Operation::UpgradeableLoaderSetAuthority {
            account,
            current_authority,
            new_authority,
            ..
        } => {
            if loader_authority(dependencies, *account) != Some(Some(*current_authority)) {
                state.incomplete(
                    "Upgradeable-loader authority does not match current state",
                    location,
                );
            } else {
                let next = new_authority
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "removed".to_owned());
                state.finding(
                    "UPGRADE_AUTHORITY_CHANGE",
                    Severity::Critical,
                    format!("Upgrade authority is changed to {next}"),
                    location,
                );
            }
        }
        Operation::SetGovernanceConfig {
            governance,
            config: proposed,
        } => {
            let current = if *governance == snapshot.proposal.governance {
                Some(snapshot.governance.config.clone())
            } else {
                dependency(dependencies, governance, state, location.clone()).and_then(|account| {
                    if account.owner != snapshot.governance_program_id {
                        None
                    } else {
                        decode_governance_v2(&account.data)
                            .ok()
                            .map(|value| value.config)
                    }
                })
            };
            let Some(current) = current else {
                state.incomplete(
                    "The target governance configuration is unavailable",
                    location,
                );
                return;
            };
            if governance_weakened(&current, proposed) {
                state.finding("GOVERNANCE_WEAKENING", Severity::Critical, "The proposed governance configuration lowers a threshold or shortens a voting, hold-up, or cool-off period", location);
            }
        }
        Operation::SetRealmAuthority {
            realm,
            current_authority,
            new_authority,
            action,
        } => {
            let current_authority_state = if *realm == snapshot.governance.realm {
                Some(snapshot.realm.authority)
            } else {
                dependency(dependencies, realm, state, location.clone()).and_then(|account| {
                    if account.owner != snapshot.governance_program_id {
                        None
                    } else {
                        decode_realm_v2(&account.data)
                            .ok()
                            .map(|value| value.authority)
                    }
                })
            };
            let valid_action = match action {
                RealmAuthorityAction::Remove => new_authority.is_none(),
                RealmAuthorityAction::SetUnchecked | RealmAuthorityAction::SetChecked => {
                    new_authority.is_some()
                }
            };
            let checked_authority_valid = if *action == RealmAuthorityAction::SetChecked {
                new_authority.is_some_and(|authority| {
                    dependencies
                        .get(&authority)
                        .copied()
                        .flatten()
                        .filter(|account| account.owner == snapshot.governance_program_id)
                        .and_then(|account| decode_governance_v2(&account.data).ok())
                        .is_some_and(|governance| governance.realm == *realm)
                })
            } else {
                true
            };
            if current_authority_state != Some(Some(*current_authority))
                || !valid_action
                || !checked_authority_valid
            {
                state.incomplete(
                    "SetRealmAuthority does not match current realm state",
                    location,
                );
            } else {
                state.finding(
                    "REALM_AUTHORITY_CHANGE",
                    Severity::Critical,
                    "The proposal changes or removes the realm authority",
                    location,
                );
            }
        }
    }
}

fn dependency<'a>(
    dependencies: &'a BTreeMap<Pubkey, Option<&'a Account>>,
    address: &Pubkey,
    state: &mut AnalysisState,
    location: Option<InstructionLocation>,
) -> Option<&'a Account> {
    match dependencies.get(address).copied().flatten() {
        Some(account) => Some(account),
        None => {
            state.incomplete("A required dependency account is missing", location);
            None
        }
    }
}

fn token_account(
    dependencies: &BTreeMap<Pubkey, Option<&Account>>,
    address: &Pubkey,
    state: &mut AnalysisState,
    location: Option<InstructionLocation>,
) -> Option<TokenAccountData> {
    let account = dependency(dependencies, address, state, location.clone())?;
    if account.owner != spl_token_program_id() {
        state.incomplete("A token account has an unexpected program owner", location);
        return None;
    }
    match parse_token_account(&account.data) {
        Ok(token) if token.state != TokenAccountState::Uninitialized => Some(token),
        _ => {
            state.incomplete("A token account is malformed or uninitialized", location);
            None
        }
    }
}

fn token_mint(
    dependencies: &BTreeMap<Pubkey, Option<&Account>>,
    address: &Pubkey,
    state: &mut AnalysisState,
    location: Option<InstructionLocation>,
) -> Option<TokenMintState> {
    let account = dependency(dependencies, address, state, location.clone())?;
    if account.owner != spl_token_program_id() {
        state.incomplete("A token mint has an unexpected program owner", location);
        return None;
    }
    match parse_token_mint(&account.data) {
        Ok(mint) if mint.is_initialized => Some(mint),
        _ => {
            state.incomplete("A token mint is malformed or uninitialized", location);
            None
        }
    }
}

fn valid_token_authority(account: &TokenAccountData, authority: Pubkey, amount: u64) -> bool {
    account.owner == authority
        || (account.delegate == Some(authority) && account.delegated_amount >= amount)
}

fn token_authority_matches(account: &Account, kind: TokenAuthorityType, authority: Pubkey) -> bool {
    match kind {
        TokenAuthorityType::MintTokens => {
            parse_token_mint(&account.data)
                .ok()
                .and_then(|value| value.mint_authority)
                == Some(authority)
        }
        TokenAuthorityType::FreezeAccount => {
            parse_token_mint(&account.data)
                .ok()
                .and_then(|value| value.freeze_authority)
                == Some(authority)
        }
        TokenAuthorityType::AccountOwner => {
            parse_token_account(&account.data)
                .ok()
                .map(|value| value.owner)
                == Some(authority)
        }
        TokenAuthorityType::CloseAccount => {
            parse_token_account(&account.data)
                .ok()
                .map(|value| value.close_authority.unwrap_or(value.owner))
                == Some(authority)
        }
    }
}

fn validate_upgrade(
    dependencies: &BTreeMap<Pubkey, Option<&Account>>,
    programdata: Pubkey,
    program: Pubkey,
    buffer: Pubkey,
    authority: Pubkey,
) -> bool {
    let Some(program_account) = dependencies.get(&program).copied().flatten() else {
        return false;
    };
    let Some(programdata_account) = dependencies.get(&programdata).copied().flatten() else {
        return false;
    };
    let Some(buffer_account) = dependencies.get(&buffer).copied().flatten() else {
        return false;
    };
    if program_account.owner != bpf_upgradeable_loader_id()
        || programdata_account.owner != bpf_upgradeable_loader_id()
        || buffer_account.owner != bpf_upgradeable_loader_id()
        || !program_account.executable
    {
        return false;
    }
    let Ok((derived, _)) = find_program_address(&[program.as_ref()], &bpf_upgradeable_loader_id())
    else {
        return false;
    };
    matches!(parse_upgradeable_loader_state(&program_account.data), Ok(UpgradeableLoaderState::Program { programdata_address }) if programdata_address == programdata && programdata == derived)
        && matches!(parse_upgradeable_loader_state(&programdata_account.data), Ok(UpgradeableLoaderState::ProgramData { upgrade_authority: Some(value), .. }) if value == authority)
        && matches!(parse_upgradeable_loader_state(&buffer_account.data), Ok(UpgradeableLoaderState::Buffer { authority: Some(value), .. }) if value == authority)
}

fn loader_authority(
    dependencies: &BTreeMap<Pubkey, Option<&Account>>,
    address: Pubkey,
) -> Option<Option<Pubkey>> {
    let account = dependencies.get(&address).copied().flatten()?;
    if account.owner != bpf_upgradeable_loader_id() {
        return None;
    }
    match parse_upgradeable_loader_state(&account.data).ok()? {
        UpgradeableLoaderState::Buffer { authority, .. }
        | UpgradeableLoaderState::ProgramData {
            upgrade_authority: authority,
            ..
        } => Some(authority),
        UpgradeableLoaderState::Program { .. } => None,
    }
}

pub(crate) fn governance_weakened(current: &GovernanceConfig, proposed: &GovernanceConfig) -> bool {
    electorate_threshold_lowered(
        current.community_vote_threshold,
        proposed.community_vote_threshold,
    ) || electorate_threshold_lowered(
        current.council_vote_threshold,
        proposed.council_vote_threshold,
    ) || veto_threshold_lowered(
        current.community_veto_vote_threshold,
        proposed.community_veto_vote_threshold,
    ) || veto_threshold_lowered(
        current.council_veto_vote_threshold,
        proposed.council_veto_vote_threshold,
    ) || proposed.transactions_hold_up_time < current.transactions_hold_up_time
        || proposed.voting_base_time < current.voting_base_time
        || proposed.voting_cool_off_time < current.voting_cool_off_time
        || tipping_weakened(
            current.community_vote_tipping,
            proposed.community_vote_tipping,
        )
        || tipping_weakened(current.council_vote_tipping, proposed.council_vote_tipping)
}

fn electorate_threshold_lowered(current: VoteThreshold, proposed: VoteThreshold) -> bool {
    matches!((current, proposed), (VoteThreshold::YesVotePercentage(old), VoteThreshold::YesVotePercentage(new)) if new < old)
        || matches!(
            (current, proposed),
            (VoteThreshold::Disabled, VoteThreshold::YesVotePercentage(_))
        )
}

fn veto_threshold_lowered(current: VoteThreshold, proposed: VoteThreshold) -> bool {
    matches!((current, proposed), (VoteThreshold::YesVotePercentage(old), VoteThreshold::YesVotePercentage(new)) if new < old)
        || matches!(
            (current, proposed),
            (VoteThreshold::YesVotePercentage(_), VoteThreshold::Disabled)
        )
}

fn tipping_weakened(current: VoteTipping, proposed: VoteTipping) -> bool {
    let strength = |value| match value {
        VoteTipping::Early => 0,
        VoteTipping::Strict => 1,
        VoteTipping::Disabled => 2,
    };
    strength(proposed) < strength(current)
}

fn add_flow(
    flows: &mut BTreeMap<FlowKey, Flow>,
    key: FlowKey,
    amount: u64,
    balance: u64,
    decimals: u8,
    location: &InstructionLocation,
    state: &mut AnalysisState,
) {
    if let Some(flow) = flows.get_mut(&key) {
        if flow.balance != balance || flow.decimals != decimals {
            state.incomplete(
                "Aggregate transfer dependencies are contradictory",
                Some(location.clone()),
            );
            return;
        }
        match flow.amount.checked_add(amount as u128) {
            Some(value) => flow.amount = value,
            None => state.incomplete(
                "Aggregate transfer amount overflowed",
                Some(location.clone()),
            ),
        }
    } else {
        flows.insert(
            key,
            Flow {
                amount: amount as u128,
                balance,
                decimals,
                location: location.clone(),
            },
        );
    }
}

fn ratio_reached(amount: u128, balance: u64, basis_points: u16) -> bool {
    amount
        .checked_mul(10_000)
        .zip((balance as u128).checked_mul(basis_points as u128))
        .is_some_and(|(left, right)| amount > 0 && left >= right)
}

pub fn decimal_quantity(amount: u128, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let digits = amount.to_string();
    let decimal_places = decimals as usize;
    let (whole, mut fraction) = if digits.len() > decimal_places {
        let split = digits.len() - decimal_places;
        (digits[..split].to_owned(), digits[split..].to_owned())
    } else {
        let mut fraction = "0".repeat(decimal_places - digits.len());
        fraction.push_str(&digits);
        ("0".to_owned(), fraction)
    };
    while fraction.ends_with('0') {
        fraction.pop();
    }
    if fraction.is_empty() {
        whole
    } else {
        format!("{whole}.{fraction}")
    }
}

fn is_allowed_owner(owner: Pubkey, controlled: &[Pubkey; 2], config: &Config) -> bool {
    controlled.contains(&owner) || config.allowed_destination_owners.contains(&owner)
}

fn selected_options(proposal: &ProposalV2) -> BTreeSet<u8> {
    let succeeded: BTreeSet<_> = proposal
        .options
        .iter()
        .enumerate()
        .filter(|(_, option)| option.vote_result == OptionVoteResult::Succeeded)
        .filter_map(|(index, _)| u8::try_from(index).ok())
        .collect();
    if !succeeded.is_empty() {
        return succeeded;
    }
    if matches!(
        proposal.state,
        ProposalState::Draft | ProposalState::SigningOff | ProposalState::Voting
    ) {
        proposal
            .options
            .iter()
            .enumerate()
            .filter(|(_, option)| option.vote_result != OptionVoteResult::Defeated)
            .filter_map(|(index, _)| u8::try_from(index).ok())
            .collect()
    } else {
        BTreeSet::new()
    }
}

fn relevant_voter_weight_addin(
    proposal: &ProposalV2,
    realm: &RealmV2,
    realm_config: Option<&RealmConfigAccount>,
) -> bool {
    // Resolution captures both values in ProposalV2, so an add-in is no longer
    // needed to establish the threshold or required winning weight.
    if proposal.vote_threshold.is_some() && proposal.max_vote_weight.is_some() {
        return false;
    }
    if proposal.governing_token_mint == realm.community_mint {
        realm.config.legacy_voter_weight_addin
            || realm.config.legacy_max_voter_weight_addin
            || realm_config.is_some_and(|config| {
                config.community_token_config.voter_weight_addin.is_some()
                    || config
                        .community_token_config
                        .max_voter_weight_addin
                        .is_some()
            })
    } else if Some(proposal.governing_token_mint) == realm.config.council_mint {
        realm_config.is_some_and(|config| {
            config.council_token_config.voter_weight_addin.is_some()
                || config.council_token_config.max_voter_weight_addin.is_some()
        })
    } else {
        true
    }
}

fn proposal_option_summaries(proposal: &ProposalV2) -> Vec<ProposalOptionSummary> {
    proposal
        .options
        .iter()
        .enumerate()
        .filter_map(|(index, option)| {
            Some(ProposalOptionSummary {
                option_index: u8::try_from(index).ok()?,
                vote_weight: option.vote_weight.to_string(),
                result: match option.vote_result {
                    OptionVoteResult::None => "None",
                    OptionVoteResult::Succeeded => "Succeeded",
                    OptionVoteResult::Defeated => "Defeated",
                }
                .to_owned(),
                transactions_executed: option.transactions_executed_count.to_string(),
                transactions_present: option.transactions_count.to_string(),
            })
        })
        .collect()
}

fn proposal_transaction_summaries(snapshot: &Snapshot) -> Vec<ProposalTransactionSummary> {
    let mut summaries: Vec<_> = snapshot
        .transactions
        .iter()
        .map(|item| ProposalTransactionSummary {
            address: item.address.to_string(),
            option_index: item.transaction.option_index,
            transaction_index: item.transaction.transaction_index,
            status: match item.transaction.execution_status {
                TransactionExecutionStatus::None => "None",
                TransactionExecutionStatus::Success => "Success",
                TransactionExecutionStatus::Error => "Error",
            }
            .to_owned(),
            executed_at: decimal_option(item.transaction.executed_at),
        })
        .collect();
    summaries.sort_by_key(|item| (item.option_index, item.transaction_index));
    summaries
}

fn validate_execution_consistency(
    snapshot: &Snapshot,
    selected: &BTreeSet<u8>,
    state: &mut AnalysisState,
) {
    let resolved = matches!(
        snapshot.proposal.state,
        ProposalState::Succeeded
            | ProposalState::Executing
            | ProposalState::Completed
            | ProposalState::Defeated
            | ProposalState::ExecutingWithErrors
            | ProposalState::Vetoed
    );
    if resolved
        && (snapshot.proposal.vote_threshold.is_none()
            || snapshot.proposal.max_vote_weight.is_none())
    {
        state.incomplete(
            "A resolved proposal is missing captured threshold evidence",
            None,
        );
    }
    if matches!(
        snapshot.proposal.state,
        ProposalState::Succeeded
            | ProposalState::Executing
            | ProposalState::Completed
            | ProposalState::ExecutingWithErrors
    ) && selected.is_empty()
    {
        state.incomplete(
            "The proposal state requires a succeeded option, but none is recorded",
            None,
        );
    }

    let mut successful = vec![0u16; snapshot.proposal.options.len()];
    for item in &snapshot.transactions {
        let transaction = &item.transaction;
        let timestamps_match = match transaction.execution_status {
            TransactionExecutionStatus::None => transaction.executed_at.is_none(),
            TransactionExecutionStatus::Success | TransactionExecutionStatus::Error => {
                transaction.executed_at.is_some()
            }
        };
        if !timestamps_match {
            state.incomplete(
                "A transaction execution status contradicts its timestamp",
                None,
            );
        }
        if transaction.execution_status == TransactionExecutionStatus::Success {
            if let Some(count) = successful.get_mut(transaction.option_index as usize) {
                *count = count.saturating_add(1);
            }
        }
        if transaction.execution_status != TransactionExecutionStatus::None
            && snapshot
                .proposal
                .options
                .get(transaction.option_index as usize)
                .is_none_or(|option| option.vote_result != OptionVoteResult::Succeeded)
        {
            state.incomplete(
                "An executed transaction does not belong to a succeeded option",
                None,
            );
        }
    }
    for (index, option) in snapshot.proposal.options.iter().enumerate() {
        if successful[index] != option.transactions_executed_count {
            state.incomplete(
                "Proposal and transaction execution counts are contradictory",
                None,
            );
        }
        if snapshot.proposal.state == ProposalState::Completed
            && option.vote_result == OptionVoteResult::Succeeded
            && successful[index] != option.transactions_count
        {
            state.incomplete(
                "A completed proposal contains an unexecuted successful transaction",
                None,
            );
        }
    }

    let successful_total: u32 = successful.iter().map(|count| u32::from(*count)).sum();
    let successful_expected: u32 = snapshot
        .proposal
        .options
        .iter()
        .filter(|option| option.vote_result == OptionVoteResult::Succeeded)
        .map(|option| u32::from(option.transactions_count))
        .sum();
    let state_matches_execution = match snapshot.proposal.state {
        ProposalState::Draft
        | ProposalState::SigningOff
        | ProposalState::Voting
        | ProposalState::Succeeded
        | ProposalState::Defeated
        | ProposalState::Cancelled
        | ProposalState::Vetoed => successful_total == 0,
        ProposalState::Executing => successful_total > 0 && successful_total < successful_expected,
        ProposalState::Completed => successful_total == successful_expected,
        ProposalState::ExecutingWithErrors => successful_total < successful_expected,
    };
    if !state_matches_execution {
        state.incomplete(
            "The proposal state contradicts transaction execution progress",
            None,
        );
    }

    let lifecycle_timestamps_valid = match snapshot.proposal.state {
        ProposalState::Succeeded => {
            snapshot.proposal.executing_at.is_none() && snapshot.proposal.closed_at.is_none()
        }
        ProposalState::Executing | ProposalState::ExecutingWithErrors => {
            snapshot.proposal.executing_at.is_some() && snapshot.proposal.closed_at.is_none()
        }
        ProposalState::Completed => {
            snapshot.proposal.executing_at.is_some() && snapshot.proposal.closed_at.is_some()
        }
        _ => true,
    };
    let timestamps_ordered = [
        snapshot.proposal.voting_at,
        snapshot.proposal.voting_completed_at,
        snapshot.proposal.executing_at,
        snapshot.proposal.closed_at,
    ]
    .into_iter()
    .flatten()
    .try_fold(None, |previous, timestamp| {
        if previous.is_some_and(|value| timestamp < value) {
            None
        } else {
            Some(Some(timestamp))
        }
    })
    .is_some();
    if !lifecycle_timestamps_valid || !timestamps_ordered {
        state.incomplete("Proposal lifecycle timestamps are contradictory", None);
    }
}

fn incomplete_report(
    proposal_address: Pubkey,
    proposal: &ProposalV2,
    realm: Option<Pubkey>,
    evidence_slot: u64,
    code: &'static str,
    evidence: &'static str,
) -> Report {
    let mut report = Report {
        verdict: Verdict::Incomplete,
        complete: false,
        proposal: ProposalSummary {
            address: proposal_address.to_string(),
            state: proposal_state(proposal.state).to_owned(),
            governance: proposal.governance.to_string(),
            realm: realm.map(|value| value.to_string()).unwrap_or_default(),
            threshold_percent: match proposal.vote_threshold {
                Some(VoteThreshold::YesVotePercentage(value)) => Some(value),
                _ => None,
            },
            hold_up_seconds: String::new(),
            voting_at: decimal_option(proposal.voting_at),
            voting_completed_at: decimal_option(proposal.voting_completed_at),
            executing_at: decimal_option(proposal.executing_at),
            closed_at: decimal_option(proposal.closed_at),
            max_vote_weight: proposal.max_vote_weight.map(|value| value.to_string()),
            deny_vote_weight: proposal.deny_vote_weight.map(|value| value.to_string()),
            abstain_vote_weight: proposal.abstain_vote_weight.map(|value| value.to_string()),
            veto_vote_weight: proposal.veto_vote_weight.to_string(),
            voting_deadline: None,
            analyzed_options: selected_options(proposal).into_iter().collect(),
            options: proposal_option_summaries(proposal),
            transactions: Vec::new(),
            transaction_count: "0".to_owned(),
            instruction_count: "0".to_owned(),
        },
        findings: vec![Finding {
            code: code.to_owned(),
            severity: Severity::Critical,
            evidence: evidence.to_owned(),
            location: None,
        }],
        unknown_instructions: Vec::new(),
        evidence_slot: evidence_slot.to_string(),
        links: vec![format!(
            "https://explorer.solana.com/address/{proposal_address}"
        )],
    };
    report.canonicalize();
    report
}

fn instruction_tag(data: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = data.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn decimal_option(value: Option<i64>) -> Option<String> {
    value.map(|item| item.to_string())
}

fn explorer_links(proposal: Pubkey, governance: Pubkey, realm: Pubkey) -> Vec<String> {
    [proposal, governance, realm]
        .into_iter()
        .map(|address| format!("https://explorer.solana.com/address/{address}"))
        .collect()
}

fn proposal_state(state: ProposalState) -> &'static str {
    match state {
        ProposalState::Draft => "Draft",
        ProposalState::SigningOff => "SigningOff",
        ProposalState::Voting => "Voting",
        ProposalState::Succeeded => "Succeeded",
        ProposalState::Executing => "Executing",
        ProposalState::Completed => "Completed",
        ProposalState::Cancelled => "Cancelled",
        ProposalState::Defeated => "Defeated",
        ProposalState::ExecutingWithErrors => "ExecutingWithErrors",
        ProposalState::Vetoed => "Vetoed",
    }
}
