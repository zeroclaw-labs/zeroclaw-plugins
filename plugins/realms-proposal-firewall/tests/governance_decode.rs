#[allow(dead_code)]
#[path = "../src/governance.rs"]
mod governance;
#[allow(dead_code)]
#[path = "../src/pubkey.rs"]
mod pubkey;

use governance::*;
use pubkey::{proposal_transaction_address, spl_governance_program_id, Pubkey};

fn key(byte: u8) -> Pubkey {
    Pubkey::new([byte; 32])
}

fn bytes(value: &[u8], output: &mut Vec<u8>) {
    output.extend((value.len() as u32).to_le_bytes());
    output.extend(value);
}

fn string(value: &str, output: &mut Vec<u8>) {
    bytes(value.as_bytes(), output);
}

fn option_u64(value: Option<u64>, output: &mut Vec<u8>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend(value.to_le_bytes());
        }
        None => output.push(0),
    }
}

fn option_i64(value: Option<i64>, output: &mut Vec<u8>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend(value.to_le_bytes());
        }
        None => output.push(0),
    }
}

fn option_pubkey(value: Option<Pubkey>, output: &mut Vec<u8>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend(value.as_ref());
        }
        None => output.push(0),
    }
}

fn threshold(value: VoteThreshold, output: &mut Vec<u8>) {
    match value {
        VoteThreshold::YesVotePercentage(value) => output.extend([0, value]),
        VoteThreshold::QuorumPercentage(value) => output.extend([1, value]),
        VoteThreshold::Disabled => output.push(2),
    }
}

fn proposal_bytes() -> Vec<u8> {
    let mut data = vec![14];
    data.extend(key(1).as_ref());
    data.extend(key(2).as_ref());
    data.push(5); // Completed
    data.extend(key(3).as_ref());
    data.extend([1, 1]);
    data.push(0); // SingleChoice
    data.extend(1u32.to_le_bytes());
    string("Approve", &mut data);
    data.extend(101u64.to_le_bytes());
    data.push(1); // Succeeded
    data.extend(1u16.to_le_bytes());
    data.extend(2u16.to_le_bytes());
    data.extend(2u16.to_le_bytes());
    option_u64(Some(7), &mut data);
    data.push(0); // reserved1
    option_u64(None, &mut data);
    option_i64(None, &mut data); // start_voting_at
    data.extend(10i64.to_le_bytes());
    option_i64(Some(11), &mut data);
    option_i64(Some(20), &mut data);
    option_u64(Some(99), &mut data);
    option_i64(Some(30), &mut data);
    option_i64(Some(31), &mut data);
    option_i64(Some(40), &mut data);
    data.push(0); // execution flags
    option_u64(Some(1_000), &mut data);
    data.push(0); // max voting time
    data.push(1); // captured threshold option
    threshold(VoteThreshold::YesVotePercentage(10), &mut data);
    data.extend([0; 64]);
    string("Golden proposal", &mut data);
    string("https://example.test/proposal", &mut data);
    data.extend(5u64.to_le_bytes());
    data
}

fn transaction_bytes() -> Vec<u8> {
    let mut data = vec![13];
    data.extend(key(9).as_ref());
    data.push(0);
    data.extend(1u16.to_le_bytes());
    data.extend(0u32.to_le_bytes());
    data.extend(1u32.to_le_bytes());
    data.extend(key(8).as_ref());
    data.extend(1u32.to_le_bytes());
    data.extend(key(7).as_ref());
    data.extend([1, 0]);
    bytes(&[4, 5, 6], &mut data);
    option_i64(Some(50), &mut data);
    data.push(1);
    data.extend([0; 8]);
    data
}

fn governance_bytes(tag: u8) -> Vec<u8> {
    let mut data = vec![tag];
    data.extend(key(4).as_ref());
    data.extend(key(5).as_ref());
    data.extend(0u32.to_le_bytes());
    threshold(VoteThreshold::YesVotePercentage(10), &mut data);
    data.extend(1u64.to_le_bytes());
    data.extend(5u32.to_le_bytes());
    data.extend(100u32.to_le_bytes());
    data.push(0); // community tipping
    threshold(VoteThreshold::YesVotePercentage(20), &mut data);
    threshold(VoteThreshold::Disabled, &mut data);
    data.extend(2u64.to_le_bytes());
    data.push(1); // council tipping
    threshold(VoteThreshold::Disabled, &mut data);
    data.extend(10u32.to_le_bytes());
    data.push(3);
    data.extend([0; 119]);
    data.push(1);
    data.extend(4u64.to_le_bytes());
    data
}

fn realm_bytes() -> Vec<u8> {
    let mut data = vec![16];
    data.extend(key(1).as_ref());
    data.extend([0, 0]);
    data.extend([0; 6]);
    data.extend(10u64.to_le_bytes());
    data.push(0); // supply fraction
    data.extend(10_000_000_000u64.to_le_bytes());
    option_pubkey(Some(key(2)), &mut data);
    data.extend([0; 6]);
    data.extend(0u16.to_le_bytes());
    option_pubkey(Some(key(3)), &mut data);
    string("Golden realm", &mut data);
    data.extend([0; 128]);
    data
}

fn token_config(output: &mut Vec<u8>) {
    option_pubkey(None, output);
    option_pubkey(None, output);
    output.push(0);
    output.extend([0; 4]);
    output.extend(1u32.to_le_bytes());
    output.extend(key(7).as_ref());
}

fn realm_config_bytes() -> Vec<u8> {
    let mut data = vec![11];
    data.extend(key(6).as_ref());
    token_config(&mut data);
    token_config(&mut data);
    data.extend([0; 110]);
    data
}

#[test]
fn decodes_all_golden_v2_layouts_and_allows_trailing_allocation() {
    let mut proposal_data = proposal_bytes();
    proposal_data.extend([0xaa; 17]);
    let proposal = decode_proposal_v2(&proposal_data).unwrap();
    assert_eq!(proposal.name, "Golden proposal");
    assert_eq!(proposal.options[0].transactions_count, 2);
    assert_eq!(
        proposal.vote_threshold,
        Some(VoteThreshold::YesVotePercentage(10))
    );

    let transaction = decode_proposal_transaction_v2(&transaction_bytes()).unwrap();
    assert_eq!(transaction.instructions[0].data, [4, 5, 6]);
    assert!(transaction.instructions[0].accounts[0].is_signer);

    for tag in 18..=21 {
        let governance = decode_governance_v2(&governance_bytes(tag)).unwrap();
        assert_eq!(governance.realm, key(4));
        assert_eq!(governance.config.voting_base_time, 100);
    }

    let realm = decode_realm_v2(&realm_bytes()).unwrap();
    assert_eq!(realm.name, "Golden realm");
    assert_eq!(realm.config.council_mint, Some(key(2)));

    let config = decode_realm_config_account(&realm_config_bytes()).unwrap();
    assert_eq!(config.realm, key(6));
    assert_eq!(config.community_token_config.lock_authorities, [key(7)]);
}

#[test]
fn rejects_wrong_tags_and_malformed_enums() {
    let mut proposal = proposal_bytes();
    proposal[0] = 5;
    assert!(decode_proposal_v2(&proposal).is_err());

    let mut transaction = transaction_bytes();
    transaction[0] = 12;
    assert!(decode_proposal_transaction_v2(&transaction).is_err());

    assert!(decode_governance_v2(&governance_bytes(17)).is_err());

    let mut realm = realm_bytes();
    realm[0] = 1;
    assert!(decode_realm_v2(&realm).is_err());

    let mut config = realm_config_bytes();
    config[0] = 10;
    assert!(decode_realm_config_account(&config).is_err());
}

#[test]
fn rejects_noncanonical_bool_and_option_tags() {
    let mut transaction = transaction_bytes();
    // tag + proposal + option + index + legacy + ix count + program + account count + key
    let signer_offset = 1 + 32 + 1 + 2 + 4 + 4 + 32 + 4 + 32;
    transaction[signer_offset] = 2;
    assert_eq!(
        decode_proposal_transaction_v2(&transaction),
        Err(DecodeError::Invalid("bool"))
    );

    let mut config = realm_config_bytes();
    config[33] = 2; // first add-in option
    assert_eq!(
        decode_realm_config_account(&config),
        Err(DecodeError::Invalid("option tag"))
    );
}

#[test]
fn rejects_oversized_counts_before_allocation() {
    let mut proposal = proposal_bytes();
    let options_offset = 1 + 32 + 32 + 1 + 32 + 1 + 1 + 1;
    proposal[options_offset..options_offset + 4].copy_from_slice(&11u32.to_le_bytes());
    assert_eq!(
        decode_proposal_v2(&proposal),
        Err(DecodeError::LimitExceeded("proposal options"))
    );

    let mut transaction = transaction_bytes();
    let instructions_offset = 1 + 32 + 1 + 2 + 4;
    transaction[instructions_offset..instructions_offset + 4]
        .copy_from_slice(&129u32.to_le_bytes());
    assert_eq!(
        decode_proposal_transaction_v2(&transaction),
        Err(DecodeError::LimitExceeded("transaction instructions"))
    );

    let oversized_account = vec![0; MAX_ACCOUNT_DATA_LEN + 1];
    assert_eq!(
        decode_proposal_v2(&oversized_account),
        Err(DecodeError::LimitExceeded("account data"))
    );
}

#[test]
fn rejects_oversized_and_non_utf8_strings_before_use() {
    let options_offset = 1 + 32 + 32 + 1 + 32 + 1 + 1 + 1;
    let label_len_offset = options_offset + 4;

    let mut oversized = proposal_bytes();
    oversized[label_len_offset..label_len_offset + 4]
        .copy_from_slice(&((MAX_STRING_LEN + 1) as u32).to_le_bytes());
    assert_eq!(
        decode_proposal_v2(&oversized),
        Err(DecodeError::LimitExceeded("proposal option label"))
    );

    let mut invalid_utf8 = proposal_bytes();
    invalid_utf8[label_len_offset..label_len_offset + 4].copy_from_slice(&1u32.to_le_bytes());
    invalid_utf8[label_len_offset + 4] = 0xff;
    assert_eq!(
        decode_proposal_v2(&invalid_utf8),
        Err(DecodeError::Invalid("UTF-8 string"))
    );
}

#[test]
fn every_truncated_golden_account_is_rejected() {
    let proposal = proposal_bytes();
    for end in 0..proposal.len() {
        assert!(decode_proposal_v2(&proposal[..end]).is_err());
    }
    let transaction = transaction_bytes();
    for end in 0..transaction.len() {
        assert!(decode_proposal_transaction_v2(&transaction[..end]).is_err());
    }
    let governance = governance_bytes(18);
    for end in 0..governance.len() {
        assert!(decode_governance_v2(&governance[..end]).is_err());
    }
    let realm = realm_bytes();
    for end in 0..realm.len() {
        assert!(decode_realm_v2(&realm[..end]).is_err());
    }
    let config = realm_config_bytes();
    for end in 0..config.len() {
        assert!(decode_realm_config_account(&config[..end]).is_err());
    }
}

#[test]
fn rejects_legacy_markers_and_voter_weight_addins() {
    let mut governance = governance_bytes(18);
    // tag + realm + seed + reserved + community threshold + min weight + hold + voting + tipping
    let council_threshold_offset = 1 + 32 + 32 + 4 + 2 + 8 + 4 + 4 + 1;
    governance[council_threshold_offset..council_threshold_offset + 2].copy_from_slice(&[0, 0]);
    assert_eq!(
        decode_governance_v2(&governance),
        Err(DecodeError::Unsupported("legacy governance config marker"))
    );

    let mut realm = realm_bytes();
    realm[33] = 1;
    assert!(
        decode_realm_v2(&realm)
            .unwrap()
            .config
            .legacy_voter_weight_addin
    );

    let mut config = realm_config_bytes();
    config[33] = 1;
    config.splice(34..34, key(9).as_ref().iter().copied());
    assert_eq!(
        decode_realm_config_account(&config)
            .unwrap()
            .community_token_config
            .voter_weight_addin,
        Some(key(9))
    );
}

fn domain_objects() -> (ProposalV2, GovernanceV2, RealmV2) {
    (
        decode_proposal_v2(&proposal_bytes()).unwrap(),
        decode_governance_v2(&governance_bytes(18)).unwrap(),
        decode_realm_v2(&realm_bytes()).unwrap(),
    )
}

#[test]
fn threshold_and_timing_helpers_handle_exact_boundaries() {
    assert_eq!(
        minimum_vote_weight(VoteThreshold::YesVotePercentage(1), 1).unwrap(),
        1
    );
    assert_eq!(
        minimum_vote_weight(VoteThreshold::YesVotePercentage(1), 101).unwrap(),
        2
    );
    assert_eq!(
        minimum_vote_weight(VoteThreshold::YesVotePercentage(100), u64::MAX).unwrap(),
        u64::MAX
    );
    assert!(minimum_vote_weight(VoteThreshold::Disabled, 10).is_err());

    let (proposal, governance, realm) = domain_objects();
    assert_eq!(
        effective_vote_threshold(&proposal, &governance, &realm).unwrap(),
        VoteThreshold::YesVotePercentage(10)
    );
    assert_eq!(voting_deadline(&proposal, &governance).unwrap(), 130);
    assert!(!has_voting_ended(&proposal, &governance, 130).unwrap());
    assert!(has_voting_ended(&proposal, &governance, 131).unwrap());
    assert_eq!(execution_hold_up_end(&proposal, &governance).unwrap(), 35);
    assert!(!can_execute_at(&proposal, &governance, 35).unwrap());
    assert!(can_execute_at(&proposal, &governance, 36).unwrap());

    let mut overflow = proposal.clone();
    overflow.voting_at = Some(i64::MAX);
    assert_eq!(
        voting_deadline(&overflow, &governance),
        Err(DecodeError::ArithmeticOverflow)
    );
}

#[test]
fn derives_and_validates_expected_transaction_relationships() {
    let (proposal, _, _) = domain_objects();
    let proposal_address = key(9);
    let program = spl_governance_program_id();
    let expected =
        expected_proposal_transactions(&program, &proposal_address, &proposal, 2).unwrap();
    assert_eq!(expected.len(), 2);

    let transactions: Vec<_> = expected
        .iter()
        .map(|expected| {
            (
                expected.address,
                ProposalTransactionV2 {
                    proposal: proposal_address,
                    option_index: expected.option_index,
                    transaction_index: expected.transaction_index,
                    instructions: Vec::new(),
                    executed_at: None,
                    execution_status: TransactionExecutionStatus::None,
                },
            )
        })
        .collect();
    validate_proposal_transaction_set(&program, &proposal_address, &proposal, &transactions, 2)
        .unwrap();

    let mut wrong = transactions.clone();
    wrong[0].0 = key(99);
    assert!(
        validate_proposal_transaction_set(&program, &proposal_address, &proposal, &wrong, 2)
            .is_err()
    );

    let direct = proposal_transaction_address(&program, &proposal_address, 0, 0)
        .unwrap()
        .0;
    assert_eq!(expected[0].address, direct);
}

#[test]
fn transaction_holes_use_the_high_water_index_and_validate_present_count() {
    let (mut proposal, _, _) = domain_objects();
    proposal.options[0].transactions_count = 2;
    proposal.options[0].transactions_next_index = 3;
    let proposal_address = key(9);
    let program = spl_governance_program_id();
    let expected =
        expected_proposal_transactions(&program, &proposal_address, &proposal, 3).unwrap();
    assert_eq!(expected.len(), 3);

    let transactions: Vec<_> = [0usize, 2]
        .into_iter()
        .map(|index| {
            let item = expected[index];
            (
                item.address,
                ProposalTransactionV2 {
                    proposal: proposal_address,
                    option_index: item.option_index,
                    transaction_index: item.transaction_index,
                    instructions: Vec::new(),
                    executed_at: None,
                    execution_status: TransactionExecutionStatus::None,
                },
            )
        })
        .collect();
    validate_proposal_transaction_set(&program, &proposal_address, &proposal, &transactions, 3)
        .unwrap();
}
