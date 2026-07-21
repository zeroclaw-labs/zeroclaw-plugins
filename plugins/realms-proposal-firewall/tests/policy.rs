#[allow(dead_code)]
#[path = "../src/analysis.rs"]
mod analysis;
#[allow(dead_code)]
#[path = "../src/config.rs"]
mod config;
#[allow(dead_code)]
#[path = "../src/governance.rs"]
mod governance;
#[allow(dead_code)]
#[path = "../src/instructions.rs"]
mod instructions;
#[allow(dead_code)]
#[path = "../src/output.rs"]
mod output;
#[allow(dead_code)]
#[path = "../src/pubkey.rs"]
mod pubkey;
#[allow(dead_code)]
#[path = "../src/rpc.rs"]
mod rpc;

use analysis::{
    analyze_snapshot, governance_weakened, DependencyAccount, Snapshot, SnapshotTransaction,
};
use config::Config;
use governance::{
    AccountMetaData, GovernanceAccountType, GovernanceConfig, GovernanceV2, InstructionData,
    InstructionExecutionFlags, MintMaxVoterWeightSource, OptionVoteResult, ProposalOption,
    ProposalState, ProposalTransactionV2, ProposalV2, RealmConfig, RealmV2,
    TransactionExecutionStatus, VoteThreshold, VoteTipping, VoteType,
};
use output::Verdict;
use pubkey::{
    native_treasury_address, proposal_transaction_address, spl_governance_program_id,
    spl_token_program_id, Pubkey,
};
use rpc::Account;

fn key(value: u8) -> Pubkey {
    Pubkey::new([value; 32])
}

fn policy(mint: Pubkey) -> Config {
    Config {
        rpc_url: "https://rpc.example.invalid".to_owned(),
        expected_genesis_hash: key(99),
        governance_program_ids: vec![spl_governance_program_id()],
        allowed_destination_owners: vec![key(7)],
        allowed_mints: vec![mint],
        max_transactions: 64,
        max_instructions: 128,
        large_outflow_bps: 2_500,
        critical_outflow_bps: 9_000,
    }
}

fn governance_config() -> GovernanceConfig {
    GovernanceConfig {
        community_vote_threshold: VoteThreshold::YesVotePercentage(10),
        min_community_weight_to_create_proposal: 1,
        transactions_hold_up_time: 60,
        voting_base_time: 100,
        community_vote_tipping: VoteTipping::Strict,
        council_vote_threshold: VoteThreshold::YesVotePercentage(20),
        council_veto_vote_threshold: VoteThreshold::Disabled,
        min_council_weight_to_create_proposal: 1,
        council_vote_tipping: VoteTipping::Strict,
        community_veto_vote_threshold: VoteThreshold::Disabled,
        voting_cool_off_time: 10,
        deposit_exempt_proposal_count: 0,
    }
}

fn meta(pubkey: Pubkey, signer: bool, writable: bool) -> AccountMetaData {
    AccountMetaData {
        pubkey,
        is_signer: signer,
        is_writable: writable,
    }
}

fn token_account(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0; 165];
    data[0..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(owner.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1;
    data
}

fn token_mint(decimals: u8) -> Vec<u8> {
    let mut data = vec![0; 82];
    data[36..44].copy_from_slice(&1_000_000u64.to_le_bytes());
    data[44] = decimals;
    data[45] = 1;
    data
}

fn token_rpc_account(data: Vec<u8>) -> Account {
    Account {
        lamports: 1,
        owner: spl_token_program_id(),
        executable: false,
        data,
    }
}

fn transfer_checked(
    source: Pubkey,
    mint: Pubkey,
    destination: Pubkey,
    authority: Pubkey,
    amount: u64,
    decimals: u8,
) -> InstructionData {
    let mut data = vec![12];
    data.extend(amount.to_le_bytes());
    data.push(decimals);
    InstructionData {
        program_id: spl_token_program_id(),
        accounts: vec![
            meta(source, false, true),
            meta(mint, false, false),
            meta(destination, false, true),
            meta(authority, true, false),
        ],
        data,
    }
}

fn snapshot(amounts: &[u64], destination_owner: Pubkey) -> (Snapshot, Config) {
    let program = spl_governance_program_id();
    let proposal_address = key(20);
    let governance_address = key(21);
    let realm_address = key(22);
    let mint = key(23);
    let source = key(24);
    let destination = key(25);
    let treasury = native_treasury_address(&program, &governance_address)
        .unwrap()
        .0;
    let instructions = amounts
        .iter()
        .map(|amount| transfer_checked(source, mint, destination, treasury, *amount, 2))
        .collect::<Vec<_>>();
    let proposal = ProposalV2 {
        governance: governance_address,
        governing_token_mint: mint,
        state: ProposalState::Completed,
        token_owner_record: key(26),
        signatories_count: 1,
        signatories_signed_off_count: 1,
        vote_type: VoteType::SingleChoice,
        options: vec![ProposalOption {
            label: "Approve".to_owned(),
            vote_weight: 200,
            vote_result: OptionVoteResult::Succeeded,
            transactions_executed_count: 1,
            transactions_count: 1,
            transactions_next_index: 1,
        }],
        deny_vote_weight: Some(0),
        abstain_vote_weight: None,
        start_voting_at: None,
        draft_at: 1,
        signing_off_at: Some(2),
        voting_at: Some(3),
        voting_at_slot: Some(4),
        voting_completed_at: Some(5),
        executing_at: Some(65),
        closed_at: Some(66),
        execution_flags: InstructionExecutionFlags::None,
        max_vote_weight: Some(1_000),
        max_voting_time: None,
        vote_threshold: Some(VoteThreshold::YesVotePercentage(10)),
        name: "ignored proposal prose".to_owned(),
        description_link: "https://never.invalid".to_owned(),
        veto_vote_weight: 0,
    };
    let transaction = ProposalTransactionV2 {
        proposal: proposal_address,
        option_index: 0,
        transaction_index: 0,
        instructions,
        executed_at: Some(65),
        execution_status: TransactionExecutionStatus::Success,
    };
    let transaction_address = proposal_transaction_address(&program, &proposal_address, 0, 0)
        .unwrap()
        .0;
    let snapshot = Snapshot {
        proposal_address,
        governance_program_id: program,
        proposal,
        governance: GovernanceV2 {
            account_type: GovernanceAccountType::GovernanceV2,
            realm: realm_address,
            governance_seed: key(27),
            config: governance_config(),
            required_signatories_count: 0,
            active_proposal_count: 0,
        },
        realm: RealmV2 {
            community_mint: mint,
            config: RealmConfig {
                legacy_voter_weight_addin: false,
                legacy_max_voter_weight_addin: false,
                min_community_weight_to_create_governance: 1,
                community_mint_max_voter_weight_source: MintMaxVoterWeightSource::SupplyFraction(
                    10_000_000_000,
                ),
                council_mint: None,
            },
            authority: Some(key(28)),
            name: "ignored realm name".to_owned(),
        },
        realm_config: None,
        transactions: vec![SnapshotTransaction {
            address: transaction_address,
            transaction,
        }],
        dependencies: vec![
            DependencyAccount {
                address: source,
                account: Some(token_rpc_account(token_account(mint, treasury, 10_000))),
            },
            DependencyAccount {
                address: destination,
                account: Some(token_rpc_account(token_account(mint, destination_owner, 0))),
            },
            DependencyAccount {
                address: mint,
                account: Some(token_rpc_account(token_mint(2))),
            },
        ],
        evidence_slot: 123_456,
    };
    (snapshot, policy(mint))
}

fn codes(report: &output::Report) -> Vec<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect()
}

#[test]
fn policy_thresholds_include_exact_boundaries() {
    let (large_snapshot, config) = snapshot(&[2_500], key(7));
    let large = analyze_snapshot(&large_snapshot, &config);
    assert!(codes(&large).contains(&"LARGE_TREASURY_OUTFLOW"));
    assert!(!codes(&large).contains(&"TREASURY_DRAIN"));

    let (critical_snapshot, config) = snapshot(&[9_000], key(7));
    let critical = analyze_snapshot(&critical_snapshot, &config);
    assert!(codes(&critical).contains(&"TREASURY_DRAIN"));
    assert_eq!(critical.verdict, Verdict::Critical);
}

#[test]
fn split_transfers_are_aggregated_monotonically() {
    let (single_snapshot, config) = snapshot(&[2_499], key(7));
    let single = analyze_snapshot(&single_snapshot, &config);
    assert!(!codes(&single).contains(&"LARGE_TREASURY_OUTFLOW"));

    let (split_snapshot, config) = snapshot(&[1_250, 1_250], key(7));
    let split = analyze_snapshot(&split_snapshot, &config);
    assert!(codes(&split).contains(&"LARGE_TREASURY_OUTFLOW"));
}

#[test]
fn token_self_transfer_is_not_treasury_outflow() {
    let (mut snapshot, config) = snapshot(&[9_000], key(7));
    let source = snapshot.dependencies[0].address;
    snapshot.transactions[0].transaction.instructions[0].accounts[2].pubkey = source;
    let report = analyze_snapshot(&snapshot, &config);
    assert!(!codes(&report).contains(&"TREASURY_DRAIN"));
    assert!(!codes(&report).contains(&"LARGE_TREASURY_OUTFLOW"));
}

#[test]
fn execution_status_contradictions_are_incomplete() {
    let (mut snapshot, config) = snapshot(&[100], key(7));
    snapshot.transactions[0].transaction.executed_at = None;
    let report = analyze_snapshot(&snapshot, &config);
    assert!(!report.complete);
    assert_eq!(report.verdict, Verdict::Incomplete);
}

#[test]
fn deny_weight_is_part_of_barely_above_threshold() {
    let (mut snapshot, config) = snapshot(&[100], key(7));
    snapshot.proposal.options[0].vote_weight = 200;
    snapshot.proposal.deny_vote_weight = Some(199);
    let report = analyze_snapshot(&snapshot, &config);
    assert!(codes(&report).contains(&"BARELY_ABOVE_THRESHOLD"));
}

#[test]
fn governance_weakening_includes_veto_and_tipping_changes() {
    let current = governance_config();
    let mut veto_removed = current.clone();
    veto_removed.community_veto_vote_threshold = VoteThreshold::YesVotePercentage(40);
    let mut proposed = veto_removed.clone();
    proposed.community_veto_vote_threshold = VoteThreshold::Disabled;
    assert!(governance_weakened(&veto_removed, &proposed));

    let mut early = current.clone();
    early.community_vote_tipping = VoteTipping::Early;
    assert!(governance_weakened(&current, &early));
}

#[test]
fn external_and_unapproved_mint_policy_is_additive() {
    let (snapshot, mut config) = snapshot(&[100], key(8));
    config.allowed_mints.clear();
    let report = analyze_snapshot(&snapshot, &config);
    assert!(codes(&report).contains(&"EXTERNAL_RECIPIENT"));
    assert!(codes(&report).contains(&"UNAPPROVED_MINT"));
}

#[test]
fn unknown_is_complete_critical_but_malformed_is_incomplete() {
    let (mut unknown_snapshot, config) = snapshot(&[], key(7));
    unknown_snapshot.transactions[0].transaction.instructions = vec![InstructionData {
        program_id: key(70),
        accounts: vec![],
        data: vec![1],
    }];
    let unknown = analyze_snapshot(&unknown_snapshot, &config);
    assert!(unknown.complete);
    assert_eq!(unknown.verdict, Verdict::Critical);
    assert!(codes(&unknown).contains(&"UNKNOWN_PROGRAM"));

    let (mut malformed_snapshot, config) = snapshot(&[], key(7));
    malformed_snapshot.transactions[0].transaction.instructions = vec![InstructionData {
        program_id: spl_token_program_id(),
        accounts: vec![],
        data: vec![12],
    }];
    let malformed = analyze_snapshot(&malformed_snapshot, &config);
    assert!(!malformed.complete);
    assert_eq!(malformed.verdict, Verdict::Incomplete);
    assert!(codes(&malformed).contains(&"MALFORMED_INSTRUCTION"));
}

#[test]
fn report_order_and_json_are_deterministic() {
    let (snapshot, config) = snapshot(&[9_000], key(8));
    let first = analyze_snapshot(&snapshot, &config);
    let second = analyze_snapshot(&snapshot, &config);
    assert_eq!(first, second);
    assert_eq!(first.to_json(), second.to_json());
    assert_eq!(first.findings[0].severity, output::Severity::Critical);
    assert!(first.to_json().len() <= output::MAX_REPORT_JSON_BYTES);
}

#[test]
fn defeated_instructions_do_not_inflate_historical_reports() {
    let (mut snapshot, config) = snapshot(&[100], key(7));
    snapshot.proposal.options.push(ProposalOption {
        label: "Defeated".to_owned(),
        vote_weight: 0,
        vote_result: OptionVoteResult::Defeated,
        transactions_executed_count: 0,
        transactions_count: 1,
        transactions_next_index: 1,
    });
    let address = proposal_transaction_address(
        &snapshot.governance_program_id,
        &snapshot.proposal_address,
        1,
        0,
    )
    .unwrap()
    .0;
    snapshot.transactions.push(SnapshotTransaction {
        address,
        transaction: ProposalTransactionV2 {
            proposal: snapshot.proposal_address,
            option_index: 1,
            transaction_index: 0,
            instructions: vec![InstructionData {
                program_id: key(70),
                accounts: vec![],
                data: vec![1],
            }],
            executed_at: None,
            execution_status: TransactionExecutionStatus::None,
        },
    });
    let report = analyze_snapshot(&snapshot, &config);
    assert!(report.complete);
    assert!(!codes(&report).contains(&"UNKNOWN_PROGRAM"));
    assert!(report.unknown_instructions.is_empty());
    assert_eq!(report.proposal.analyzed_options, [0]);
}

#[test]
fn decimal_rendering_and_output_overflow_are_bounded() {
    assert_eq!(
        analysis::decimal_quantity(1, 40),
        "0.0000000000000000000000000000000000000001"
    );
    assert_eq!(
        analysis::decimal_quantity(442_610_445_030_596_600, 5),
        "4426104450305.966"
    );

    let (snapshot, config) = snapshot(&[100], key(8));
    let mut report = analyze_snapshot(&snapshot, &config);
    let finding = report.findings[0].clone();
    report.findings = (0..500)
        .map(|index| output::Finding {
            code: format!("OVERSIZED_{index:03}"),
            severity: finding.severity,
            evidence: "x".repeat(1_000),
            location: finding.location.clone(),
        })
        .collect();
    let json = report.to_json();
    assert!(json.len() <= output::MAX_REPORT_JSON_BYTES);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["verdict"], "INCOMPLETE");
    assert_eq!(value["findings"][0]["code"], "OUTPUT_LIMIT_EXCEEDED");
}

fn wire_threshold(value: VoteThreshold, data: &mut Vec<u8>) {
    match value {
        VoteThreshold::YesVotePercentage(percent) => data.extend([0, percent]),
        VoteThreshold::QuorumPercentage(percent) => data.extend([1, percent]),
        VoteThreshold::Disabled => data.push(2),
    }
}

fn wire_option_i64(value: Option<i64>, data: &mut Vec<u8>) {
    match value {
        Some(value) => {
            data.push(1);
            data.extend(value.to_le_bytes());
        }
        None => data.push(0),
    }
}

fn wire_option_u64(value: Option<u64>, data: &mut Vec<u8>) {
    match value {
        Some(value) => {
            data.push(1);
            data.extend(value.to_le_bytes());
        }
        None => data.push(0),
    }
}

fn wire_string(value: &str, data: &mut Vec<u8>) {
    data.extend((value.len() as u32).to_le_bytes());
    data.extend(value.as_bytes());
}

fn proposal_wire(proposal: &ProposalV2) -> Vec<u8> {
    let mut data = vec![14];
    data.extend(proposal.governance.as_ref());
    data.extend(proposal.governing_token_mint.as_ref());
    data.push(match proposal.state {
        ProposalState::Draft => 0,
        ProposalState::SigningOff => 1,
        ProposalState::Voting => 2,
        ProposalState::Succeeded => 3,
        ProposalState::Executing => 4,
        ProposalState::Completed => 5,
        ProposalState::Cancelled => 6,
        ProposalState::Defeated => 7,
        ProposalState::ExecutingWithErrors => 8,
        ProposalState::Vetoed => 9,
    });
    data.extend(proposal.token_owner_record.as_ref());
    data.extend([
        proposal.signatories_count,
        proposal.signatories_signed_off_count,
        0,
    ]);
    data.extend((proposal.options.len() as u32).to_le_bytes());
    for option in &proposal.options {
        wire_string(&option.label, &mut data);
        data.extend(option.vote_weight.to_le_bytes());
        data.push(match option.vote_result {
            OptionVoteResult::None => 0,
            OptionVoteResult::Succeeded => 1,
            OptionVoteResult::Defeated => 2,
        });
        data.extend(option.transactions_executed_count.to_le_bytes());
        data.extend(option.transactions_count.to_le_bytes());
        data.extend(option.transactions_next_index.to_le_bytes());
    }
    wire_option_u64(proposal.deny_vote_weight, &mut data);
    data.push(0);
    wire_option_u64(proposal.abstain_vote_weight, &mut data);
    wire_option_i64(proposal.start_voting_at, &mut data);
    data.extend(proposal.draft_at.to_le_bytes());
    wire_option_i64(proposal.signing_off_at, &mut data);
    wire_option_i64(proposal.voting_at, &mut data);
    wire_option_u64(proposal.voting_at_slot, &mut data);
    wire_option_i64(proposal.voting_completed_at, &mut data);
    wire_option_i64(proposal.executing_at, &mut data);
    wire_option_i64(proposal.closed_at, &mut data);
    data.push(0);
    wire_option_u64(proposal.max_vote_weight, &mut data);
    data.push(0);
    match proposal.vote_threshold {
        Some(threshold) => {
            data.push(1);
            wire_threshold(threshold, &mut data);
        }
        None => data.push(0),
    }
    data.extend([0; 64]);
    wire_string(&proposal.name, &mut data);
    wire_string(&proposal.description_link, &mut data);
    data.extend(proposal.veto_vote_weight.to_le_bytes());
    data
}

fn governance_wire(governance: &GovernanceV2) -> Vec<u8> {
    let mut data = vec![18];
    data.extend(governance.realm.as_ref());
    data.extend(governance.governance_seed.as_ref());
    data.extend(0u32.to_le_bytes());
    let config = &governance.config;
    wire_threshold(config.community_vote_threshold, &mut data);
    data.extend(config.min_community_weight_to_create_proposal.to_le_bytes());
    data.extend(config.transactions_hold_up_time.to_le_bytes());
    data.extend(config.voting_base_time.to_le_bytes());
    data.push(0);
    wire_threshold(config.council_vote_threshold, &mut data);
    wire_threshold(config.council_veto_vote_threshold, &mut data);
    data.extend(config.min_council_weight_to_create_proposal.to_le_bytes());
    data.push(0);
    wire_threshold(config.community_veto_vote_threshold, &mut data);
    data.extend(config.voting_cool_off_time.to_le_bytes());
    data.push(config.deposit_exempt_proposal_count);
    data.extend([0; 119]);
    data.push(governance.required_signatories_count);
    data.extend(governance.active_proposal_count.to_le_bytes());
    data
}

fn realm_wire(realm: &RealmV2) -> Vec<u8> {
    let mut data = vec![16];
    data.extend(realm.community_mint.as_ref());
    data.extend([0, 0]);
    data.extend([0; 6]);
    data.extend(
        realm
            .config
            .min_community_weight_to_create_governance
            .to_le_bytes(),
    );
    data.push(0);
    data.extend(10_000_000_000u64.to_le_bytes());
    data.push(0);
    data.extend([0; 6]);
    data.extend(0u16.to_le_bytes());
    match realm.authority {
        Some(authority) => {
            data.push(1);
            data.extend(authority.as_ref());
        }
        None => data.push(0),
    }
    wire_string(&realm.name, &mut data);
    data.extend([0; 128]);
    data
}

fn transaction_wire(transaction: &ProposalTransactionV2) -> Vec<u8> {
    let mut data = vec![13];
    data.extend(transaction.proposal.as_ref());
    data.push(transaction.option_index);
    data.extend(transaction.transaction_index.to_le_bytes());
    data.extend(0u32.to_le_bytes());
    data.extend((transaction.instructions.len() as u32).to_le_bytes());
    for instruction in &transaction.instructions {
        data.extend(instruction.program_id.as_ref());
        data.extend((instruction.accounts.len() as u32).to_le_bytes());
        for account in &instruction.accounts {
            data.extend(account.pubkey.as_ref());
            data.extend([account.is_signer as u8, account.is_writable as u8]);
        }
        data.extend((instruction.data.len() as u32).to_le_bytes());
        data.extend(&instruction.data);
    }
    wire_option_i64(transaction.executed_at, &mut data);
    data.push(match transaction.execution_status {
        TransactionExecutionStatus::None => 0,
        TransactionExecutionStatus::Success => 1,
        TransactionExecutionStatus::Error => 2,
    });
    data.extend([0; 8]);
    data
}

#[derive(Clone)]
struct RaceTransport {
    replies: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    requests: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
}

impl rpc::Transport for RaceTransport {
    fn post(
        &self,
        _url: &str,
        body: &[u8],
        _max_response_bytes: usize,
    ) -> Result<rpc::TransportResponse, rpc::TransportError> {
        let request: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| rpc::TransportError::Other)?;
        self.requests.lock().unwrap().push(request);
        let reply = self.replies.lock().unwrap().remove(0);
        Ok(rpc::TransportResponse {
            status: 200,
            body: serde_json::to_vec(&reply).map_err(|_| rpc::TransportError::Other)?,
        })
    }
}

fn rpc_account_json(owner: Pubkey, data: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({
        "lamports": 1,
        "owner": owner,
        "executable": false,
        "data": [base64::engine::general_purpose::STANDARD.encode(data), "base64"]
    })
}

fn context_reply(id: u64, slot: u64, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"context": {"slot": slot}, "value": value}
    })
}

#[test]
fn mocked_rpc_snapshot_race_fails_incomplete_after_identity() {
    let (mut fixture, config) = snapshot(&[], key(7));
    fixture.transactions[0].transaction.instructions = vec![InstructionData {
        program_id: key(70),
        accounts: vec![],
        data: vec![1],
    }];
    let owner = fixture.governance_program_id;
    let proposal = proposal_wire(&fixture.proposal);
    let mut changed_proposal = proposal.clone();
    changed_proposal.push(0);
    let governance = governance_wire(&fixture.governance);
    let realm = realm_wire(&fixture.realm);
    let transaction = transaction_wire(&fixture.transactions[0].transaction);
    let mut final_accounts = std::collections::BTreeMap::new();
    final_accounts.insert(
        fixture.proposal_address,
        rpc_account_json(owner, &changed_proposal),
    );
    final_accounts.insert(
        fixture.proposal.governance,
        rpc_account_json(owner, &governance),
    );
    final_accounts.insert(fixture.governance.realm, rpc_account_json(owner, &realm));
    final_accounts.insert(
        pubkey::realm_config_address(&owner, &fixture.governance.realm)
            .unwrap()
            .0,
        serde_json::Value::Null,
    );
    final_accounts.insert(
        fixture.transactions[0].address,
        rpc_account_json(owner, &transaction),
    );
    let final_accounts: Vec<_> = final_accounts.into_values().collect();
    let replies = vec![
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": config.expected_genesis_hash}),
        context_reply(2, 50, rpc_account_json(owner, &proposal)),
        context_reply(3, 50, rpc_account_json(owner, &governance)),
        context_reply(
            4,
            50,
            serde_json::json!([rpc_account_json(owner, &realm), null]),
        ),
        context_reply(
            5,
            50,
            serde_json::json!([rpc_account_json(owner, &transaction)]),
        ),
        context_reply(6, 51, serde_json::Value::Array(final_accounts)),
    ];
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let transport = RaceTransport {
        replies: std::sync::Arc::new(std::sync::Mutex::new(replies)),
        requests: requests.clone(),
    };

    let report = analysis::analyze_proposal(&config, fixture.proposal_address, transport).unwrap();
    assert_eq!(report.verdict, Verdict::Incomplete);
    assert!(!report.complete);
    assert!(codes(&report).contains(&"SNAPSHOT_RACE"));
    assert_eq!(report.evidence_slot, "51");
    let requests = requests.lock().unwrap();
    assert!(requests[1]["params"][1].get("minContextSlot").is_none());
    assert!(requests[2..]
        .iter()
        .all(|request| request["params"][1]["minContextSlot"] == 50));
}

#[test]
fn mocked_rpc_complete_snapshot_reaches_instruction_analysis() {
    let (mut fixture, config) = snapshot(&[], key(7));
    fixture.transactions[0].transaction.instructions = vec![InstructionData {
        program_id: key(70),
        accounts: vec![],
        data: vec![1],
    }];
    let owner = fixture.governance_program_id;
    let proposal = proposal_wire(&fixture.proposal);
    let governance = governance_wire(&fixture.governance);
    let realm = realm_wire(&fixture.realm);
    let transaction = transaction_wire(&fixture.transactions[0].transaction);
    let mut final_accounts = std::collections::BTreeMap::new();
    final_accounts.insert(fixture.proposal_address, rpc_account_json(owner, &proposal));
    final_accounts.insert(
        fixture.proposal.governance,
        rpc_account_json(owner, &governance),
    );
    final_accounts.insert(fixture.governance.realm, rpc_account_json(owner, &realm));
    final_accounts.insert(
        pubkey::realm_config_address(&owner, &fixture.governance.realm)
            .unwrap()
            .0,
        serde_json::Value::Null,
    );
    final_accounts.insert(
        fixture.transactions[0].address,
        rpc_account_json(owner, &transaction),
    );
    let final_accounts: Vec<_> = final_accounts.into_values().collect();
    let replies = vec![
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": config.expected_genesis_hash}),
        context_reply(2, 50, rpc_account_json(owner, &proposal)),
        context_reply(3, 51, rpc_account_json(owner, &governance)),
        context_reply(
            4,
            52,
            serde_json::json!([rpc_account_json(owner, &realm), null]),
        ),
        context_reply(
            5,
            53,
            serde_json::json!([rpc_account_json(owner, &transaction)]),
        ),
        context_reply(6, 54, serde_json::Value::Array(final_accounts)),
    ];
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let transport = RaceTransport {
        replies: std::sync::Arc::new(std::sync::Mutex::new(replies)),
        requests: requests.clone(),
    };

    let report = analysis::analyze_proposal(&config, fixture.proposal_address, transport).unwrap();
    assert!(report.complete);
    assert_eq!(report.verdict, Verdict::Critical);
    assert!(codes(&report).contains(&"UNKNOWN_PROGRAM"));
    assert_eq!(report.evidence_slot, "54");

    let requests = requests.lock().unwrap();
    let minimum_slots: Vec<_> = requests[2..]
        .iter()
        .map(|request| request["params"][1]["minContextSlot"].as_u64().unwrap())
        .collect();
    assert_eq!(minimum_slots, [50, 51, 52, 53]);
}
