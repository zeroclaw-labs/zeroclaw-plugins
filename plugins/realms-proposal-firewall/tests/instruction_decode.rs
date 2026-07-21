#[allow(dead_code)]
#[path = "../src/governance.rs"]
mod governance;
#[allow(dead_code)]
#[path = "../src/instructions.rs"]
mod instructions;
#[allow(dead_code)]
#[path = "../src/pubkey.rs"]
mod pubkey;

use governance::{AccountMetaData, GovernanceConfig, InstructionData, VoteThreshold, VoteTipping};
use instructions::*;
use pubkey::{
    associated_token_address, associated_token_program_id, bpf_upgradeable_loader_id,
    spl_governance_program_id, spl_token_program_id, system_program_id, token_2022_program_id,
    Pubkey,
};

fn key(value: u8) -> Pubkey {
    Pubkey::new([value; 32])
}

fn meta(value: u8, signer: bool, writable: bool) -> AccountMetaData {
    AccountMetaData {
        pubkey: key(value),
        is_signer: signer,
        is_writable: writable,
    }
}

fn exact_meta(pubkey: Pubkey, signer: bool, writable: bool) -> AccountMetaData {
    AccountMetaData {
        pubkey,
        is_signer: signer,
        is_writable: writable,
    }
}

fn ix(program_id: Pubkey, accounts: Vec<AccountMetaData>, data: Vec<u8>) -> InstructionData {
    InstructionData {
        program_id,
        accounts,
        data,
    }
}

fn amount_data(tag: u8, amount: u64) -> Vec<u8> {
    let mut data = vec![tag];
    data.extend(amount.to_le_bytes());
    data
}

fn decoded(instruction: InstructionData) -> Operation {
    match decode_instruction(&instruction, &[spl_governance_program_id()]) {
        DecodeOutcome::Decoded(operation) => operation,
        other => panic!("expected decoded operation, got {other:?}"),
    }
}

fn is_malformed(instruction: &InstructionData) -> bool {
    matches!(
        decode_instruction(instruction, &[spl_governance_program_id()]),
        DecodeOutcome::Malformed(_)
    )
}

#[test]
fn decodes_system_transfer_and_rejects_noncanonical_shapes() {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend(42u64.to_le_bytes());
    let instruction = ix(
        system_program_id(),
        vec![meta(1, true, true), meta(2, false, true)],
        data,
    );
    assert_eq!(
        decoded(instruction.clone()),
        Operation::SystemTransfer {
            source: key(1),
            destination: key(2),
            lamports: 42,
        }
    );

    let mut trailing = instruction.clone();
    trailing.data.push(0);
    assert!(is_malformed(&trailing));
    let mut bad_flag = instruction.clone();
    bad_flag.accounts[0].is_signer = false;
    assert!(is_malformed(&bad_flag));
    let mut extra_account = instruction;
    extra_account.accounts.push(meta(3, false, false));
    assert!(is_malformed(&extra_account));
}

#[test]
fn decodes_all_classic_token_operations() {
    let token = spl_token_program_id();
    let standard = || {
        vec![
            meta(1, false, true),
            meta(2, false, true),
            meta(3, true, false),
        ]
    };

    assert_eq!(
        decoded(ix(token, standard(), amount_data(3, 11))),
        Operation::TokenTransfer {
            source: key(1),
            destination: key(2),
            authority: key(3),
            amount: 11,
        }
    );
    assert_eq!(
        decoded(ix(
            token,
            vec![
                meta(1, false, true),
                meta(2, false, false),
                meta(3, true, false)
            ],
            amount_data(4, 12),
        )),
        Operation::TokenApprove {
            source: key(1),
            delegate: key(2),
            authority: key(3),
            amount: 12,
        }
    );

    let mut set_authority = vec![6, 2, 1];
    set_authority.extend(key(9).as_ref());
    assert_eq!(
        decoded(ix(
            token,
            vec![meta(1, false, true), meta(3, true, false)],
            set_authority,
        )),
        Operation::TokenSetAuthority {
            account: key(1),
            current_authority: key(3),
            authority_type: TokenAuthorityType::AccountOwner,
            new_authority: Some(key(9)),
        }
    );
    assert_eq!(
        decoded(ix(
            token,
            vec![meta(1, false, true), meta(3, true, false)],
            vec![6, 3, 0],
        )),
        Operation::TokenSetAuthority {
            account: key(1),
            current_authority: key(3),
            authority_type: TokenAuthorityType::CloseAccount,
            new_authority: None,
        }
    );
    assert_eq!(
        decoded(ix(token, standard(), amount_data(7, 13))),
        Operation::TokenMintTo {
            mint: key(1),
            destination: key(2),
            authority: key(3),
            amount: 13,
        }
    );
    assert_eq!(
        decoded(ix(token, standard(), amount_data(8, 14))),
        Operation::TokenBurn {
            source: key(1),
            mint: key(2),
            authority: key(3),
            amount: 14,
        }
    );
    assert_eq!(
        decoded(ix(token, standard(), vec![9])),
        Operation::TokenCloseAccount {
            account: key(1),
            destination: key(2),
            authority: key(3),
        }
    );

    let mut checked = amount_data(12, 15);
    checked.push(6);
    assert_eq!(
        decoded(ix(
            token,
            vec![
                meta(1, false, true),
                meta(2, false, false),
                meta(3, false, true),
                meta(4, true, false),
            ],
            checked,
        )),
        Operation::TokenTransferChecked {
            source: key(1),
            mint: key(2),
            destination: key(3),
            authority: key(4),
            amount: 15,
            decimals: 6,
        }
    );
}

#[test]
fn decodes_exact_bip76_transfer_checked_bytes() {
    let data = vec![12, 248, 31, 237, 205, 218, 119, 36, 6, 5];
    let operation = decoded(ix(
        spl_token_program_id(),
        vec![
            meta(1, false, true),
            meta(2, false, false),
            meta(3, false, true),
            meta(4, true, false),
        ],
        data,
    ));
    assert!(matches!(
        operation,
        Operation::TokenTransferChecked {
            amount: 442_610_445_030_596_600,
            decimals: 5,
            ..
        }
    ));
}

#[test]
fn token_rejects_flags_counts_and_trailing_data_but_not_multisig_as_malformed() {
    let base = ix(
        spl_token_program_id(),
        vec![
            meta(1, false, true),
            meta(2, false, true),
            meta(3, true, false),
        ],
        amount_data(3, 1),
    );
    let mut trailing = base.clone();
    trailing.data.push(0);
    assert!(is_malformed(&trailing));
    let mut missing = base.clone();
    missing.accounts.pop();
    assert!(is_malformed(&missing));
    let mut writable_authority = base.clone();
    writable_authority.accounts[2].is_writable = true;
    assert!(is_malformed(&writable_authority));

    let multisig = ix(
        spl_token_program_id(),
        vec![
            meta(1, false, true),
            meta(2, false, true),
            meta(3, false, false),
            meta(4, true, false),
        ],
        amount_data(3, 1),
    );
    assert!(matches!(
        decode_instruction(&multisig, &[]),
        DecodeOutcome::UnsupportedInstruction {
            tag: Some(3),
            reason: "token multisig authority",
            ..
        }
    ));
}

#[test]
fn decodes_current_and_legacy_associated_token_creation_with_bip76_derivation() {
    let owner: Pubkey = "9bxWkNf3BtJ6iehq9KbX9uCWMjem4TFiPZ19T2sYJHvQ"
        .parse()
        .unwrap();
    let mint: Pubkey = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
        .parse()
        .unwrap();
    let (account, _) = associated_token_address(&owner, &mint).unwrap();
    assert_eq!(
        account.to_string(),
        "28AymsqjJ6p312raqaNUNn8DADT4kyRAwT2nJ87scmPy"
    );
    let accounts = vec![
        meta(1, true, true),
        exact_meta(account, false, true),
        exact_meta(owner, false, false),
        exact_meta(mint, false, false),
        exact_meta(system_program_id(), false, false),
        exact_meta(spl_token_program_id(), false, false),
    ];
    assert_eq!(
        decoded(ix(associated_token_program_id(), accounts.clone(), vec![1])),
        Operation::AssociatedTokenCreate {
            kind: AssociatedTokenCreateKind::CreateIdempotent,
            payer: key(1),
            account,
            owner,
            mint,
        }
    );
    assert!(matches!(
        decoded(ix(associated_token_program_id(), accounts, vec![])),
        Operation::AssociatedTokenCreate {
            kind: AssociatedTokenCreateKind::Create,
            ..
        }
    ));
}

#[test]
fn associated_token_validates_legacy_rent_programs_flags_derivation_and_trailing() {
    let owner = key(2);
    let mint = key(3);
    let account = associated_token_address(&owner, &mint).unwrap().0;
    let base = vec![
        meta(1, true, true),
        exact_meta(account, false, true),
        exact_meta(owner, false, false),
        exact_meta(mint, false, false),
        exact_meta(system_program_id(), false, false),
        exact_meta(spl_token_program_id(), false, false),
        exact_meta(
            "SysvarRent111111111111111111111111111111111"
                .parse()
                .unwrap(),
            false,
            false,
        ),
    ];
    assert!(matches!(
        decoded(ix(associated_token_program_id(), base.clone(), vec![0])),
        Operation::AssociatedTokenCreate { .. }
    ));
    for mutate in 0..4 {
        let mut accounts = base.clone();
        match mutate {
            0 => accounts[0].is_signer = false,
            1 => accounts[1].pubkey = key(99),
            2 => accounts[5].pubkey = token_2022_program_id(),
            _ => accounts[6].pubkey = key(99),
        }
        assert!(is_malformed(&ix(
            associated_token_program_id(),
            accounts,
            vec![0],
        )));
    }
    assert!(is_malformed(&ix(
        associated_token_program_id(),
        base,
        vec![1, 0],
    )));
}

fn loader_upgrade_accounts() -> Vec<AccountMetaData> {
    vec![
        meta(1, false, true),
        meta(2, false, true),
        meta(3, false, true),
        meta(4, false, true),
        exact_meta(
            "SysvarRent111111111111111111111111111111111"
                .parse()
                .unwrap(),
            false,
            false,
        ),
        exact_meta(
            "SysvarC1ock11111111111111111111111111111111"
                .parse()
                .unwrap(),
            false,
            false,
        ),
        meta(7, true, false),
    ]
}

#[test]
fn decodes_loader_upgrade_and_authority_operations() {
    let loader = bpf_upgradeable_loader_id();
    assert_eq!(
        decoded(ix(
            loader,
            loader_upgrade_accounts(),
            3u32.to_le_bytes().to_vec()
        )),
        Operation::UpgradeableLoaderUpgrade {
            programdata: key(1),
            program: key(2),
            buffer: key(3),
            spill: key(4),
            current_authority: key(7),
            close_buffer: true,
            versioned: false,
        }
    );
    let mut versioned = 3u32.to_le_bytes().to_vec();
    versioned.push(0);
    assert!(matches!(
        decoded(ix(loader, loader_upgrade_accounts(), versioned)),
        Operation::UpgradeableLoaderUpgrade {
            close_buffer: false,
            versioned: true,
            ..
        }
    ));
    assert_eq!(
        decoded(ix(
            loader,
            vec![meta(1, false, true), meta(2, true, false)],
            4u32.to_le_bytes().to_vec(),
        )),
        Operation::UpgradeableLoaderSetAuthority {
            account: key(1),
            current_authority: key(2),
            new_authority: None,
            checked: false,
            remove: true,
        }
    );
    assert_eq!(
        decoded(ix(
            loader,
            vec![
                meta(1, false, true),
                meta(2, true, false),
                meta(3, false, false),
            ],
            4u32.to_le_bytes().to_vec(),
        )),
        Operation::UpgradeableLoaderSetAuthority {
            account: key(1),
            current_authority: key(2),
            new_authority: Some(key(3)),
            checked: false,
            remove: false,
        }
    );
    assert!(matches!(
        decoded(ix(
            loader,
            vec![
                meta(1, false, true),
                meta(2, true, false),
                meta(3, true, false),
            ],
            7u32.to_le_bytes().to_vec(),
        )),
        Operation::UpgradeableLoaderSetAuthority {
            checked: true,
            remove: false,
            ..
        }
    ));
}

#[test]
fn loader_rejects_bad_bool_accounts_flags_sysvars_and_trailing() {
    let loader = bpf_upgradeable_loader_id();
    for data in [vec![3, 0, 0, 0, 2], vec![3, 0, 0, 0, 1, 0]] {
        assert!(is_malformed(&ix(loader, loader_upgrade_accounts(), data)));
    }
    let mut bad_sysvar = loader_upgrade_accounts();
    bad_sysvar[4].pubkey = key(4);
    assert!(is_malformed(&ix(
        loader,
        bad_sysvar,
        3u32.to_le_bytes().to_vec(),
    )));
    let mut bad_flag = loader_upgrade_accounts();
    bad_flag[6].is_signer = false;
    assert!(is_malformed(&ix(
        loader,
        bad_flag,
        3u32.to_le_bytes().to_vec(),
    )));
    assert!(is_malformed(&ix(
        loader,
        vec![meta(1, false, true), meta(2, true, false)],
        vec![4, 0, 0, 0, 0],
    )));
}

fn threshold(value: VoteThreshold, output: &mut Vec<u8>) {
    match value {
        VoteThreshold::YesVotePercentage(value) => output.extend([0, value]),
        VoteThreshold::QuorumPercentage(value) => output.extend([1, value]),
        VoteThreshold::Disabled => output.push(2),
    }
}

fn governance_config_data() -> (GovernanceConfig, Vec<u8>) {
    let config = GovernanceConfig {
        community_vote_threshold: VoteThreshold::YesVotePercentage(60),
        min_community_weight_to_create_proposal: 10,
        transactions_hold_up_time: 20,
        voting_base_time: 30,
        community_vote_tipping: VoteTipping::Strict,
        council_vote_threshold: VoteThreshold::YesVotePercentage(40),
        council_veto_vote_threshold: VoteThreshold::Disabled,
        min_council_weight_to_create_proposal: 50,
        council_vote_tipping: VoteTipping::Early,
        community_veto_vote_threshold: VoteThreshold::Disabled,
        voting_cool_off_time: 60,
        deposit_exempt_proposal_count: 7,
    };
    let mut data = vec![19];
    threshold(config.community_vote_threshold, &mut data);
    data.extend(config.min_community_weight_to_create_proposal.to_le_bytes());
    data.extend(config.transactions_hold_up_time.to_le_bytes());
    data.extend(config.voting_base_time.to_le_bytes());
    data.push(0);
    threshold(config.council_vote_threshold, &mut data);
    threshold(config.council_veto_vote_threshold, &mut data);
    data.extend(config.min_council_weight_to_create_proposal.to_le_bytes());
    data.push(1);
    threshold(config.community_veto_vote_threshold, &mut data);
    data.extend(config.voting_cool_off_time.to_le_bytes());
    data.push(config.deposit_exempt_proposal_count);
    (config, data)
}

#[test]
fn decodes_governance_config_and_all_realm_authority_actions() {
    let governance_program = spl_governance_program_id();
    let (config, data) = governance_config_data();
    assert_eq!(
        decoded(ix(governance_program, vec![meta(1, true, true)], data)),
        Operation::SetGovernanceConfig {
            governance: key(1),
            config,
        }
    );
    for (wire, action, new_authority) in [
        (0, RealmAuthorityAction::SetUnchecked, Some(key(3))),
        (1, RealmAuthorityAction::SetChecked, Some(key(3))),
        (2, RealmAuthorityAction::Remove, None),
    ] {
        let mut accounts = vec![meta(1, false, true), meta(2, true, false)];
        if new_authority.is_some() {
            accounts.push(meta(3, false, false));
        }
        assert_eq!(
            decoded(ix(governance_program, accounts, vec![21, wire])),
            Operation::SetRealmAuthority {
                realm: key(1),
                current_authority: key(2),
                new_authority,
                action,
            }
        );
    }
}

#[test]
fn governance_rejects_invalid_config_actions_accounts_and_trailing_data() {
    let governance_program = spl_governance_program_id();
    let (_, data) = governance_config_data();
    let mut trailing = data.clone();
    trailing.push(0);
    assert!(is_malformed(&ix(
        governance_program,
        vec![meta(1, true, true)],
        trailing,
    )));
    let mut quorum = data.clone();
    quorum[1] = 1;
    assert!(is_malformed(&ix(
        governance_program,
        vec![meta(1, true, true)],
        quorum,
    )));
    let mut invalid_percentage = data.clone();
    invalid_percentage[2] = 0;
    assert!(is_malformed(&ix(
        governance_program,
        vec![meta(1, true, true)],
        invalid_percentage,
    )));
    assert!(is_malformed(&ix(
        governance_program,
        vec![meta(1, false, true)],
        data,
    )));
    for bad in [vec![21], vec![21, 3], vec![21, 2, 0]] {
        assert!(is_malformed(&ix(
            governance_program,
            vec![meta(1, false, true), meta(2, true, false)],
            bad,
        )));
    }
}

#[test]
fn only_operator_supplied_program_ids_are_governance_programs() {
    let (_, data) = governance_config_data();
    let instruction = ix(spl_governance_program_id(), vec![meta(1, true, true)], data);
    assert!(matches!(
        decode_instruction(&instruction, &[]),
        DecodeOutcome::UnsupportedProgram { .. }
    ));
    assert!(matches!(
        decode_instruction(&instruction, &[spl_governance_program_id()]),
        DecodeOutcome::Decoded(Operation::SetGovernanceConfig { .. })
    ));
}

#[test]
fn unsupported_programs_and_instruction_tags_are_explicit() {
    let token_2022 = ix(token_2022_program_id(), vec![], vec![3]);
    assert_eq!(
        decode_instruction(&token_2022, &[]),
        DecodeOutcome::UnsupportedProgram {
            program_id: token_2022_program_id(),
        }
    );
    assert!(matches!(
        decode_instruction(&token_2022, &[token_2022_program_id()]),
        DecodeOutcome::UnsupportedProgram { .. }
    ));
    let unknown_program = ix(key(200), vec![], vec![3]);
    assert!(matches!(
        decode_instruction(&unknown_program, &[]),
        DecodeOutcome::UnsupportedProgram { .. }
    ));
    for instruction in [
        ix(system_program_id(), vec![], 99u32.to_le_bytes().to_vec()),
        ix(spl_token_program_id(), vec![], vec![255]),
        ix(associated_token_program_id(), vec![], vec![2]),
        ix(
            bpf_upgradeable_loader_id(),
            vec![],
            99u32.to_le_bytes().to_vec(),
        ),
        ix(spl_governance_program_id(), vec![], vec![255]),
    ] {
        assert!(matches!(
            decode_instruction(&instruction, &[spl_governance_program_id()]),
            DecodeOutcome::UnsupportedInstruction { .. }
        ));
    }
}

#[test]
fn strictly_parses_classic_token_mint_and_account_states() {
    let mut mint = vec![0; 82];
    mint[0..4].copy_from_slice(&1u32.to_le_bytes());
    mint[4..36].copy_from_slice(key(1).as_ref());
    mint[36..44].copy_from_slice(&123u64.to_le_bytes());
    mint[44] = 5;
    mint[45] = 1;
    mint[46..50].copy_from_slice(&1u32.to_le_bytes());
    mint[50..82].copy_from_slice(key(2).as_ref());
    assert_eq!(
        parse_token_mint(&mint).unwrap(),
        TokenMintState {
            mint_authority: Some(key(1)),
            supply: 123,
            decimals: 5,
            is_initialized: true,
            freeze_authority: Some(key(2)),
        }
    );

    let mut account = vec![0; 165];
    account[0..32].copy_from_slice(key(1).as_ref());
    account[32..64].copy_from_slice(key(2).as_ref());
    account[64..72].copy_from_slice(&456u64.to_le_bytes());
    account[72..76].copy_from_slice(&1u32.to_le_bytes());
    account[76..108].copy_from_slice(key(3).as_ref());
    account[108] = 2;
    account[109..113].copy_from_slice(&1u32.to_le_bytes());
    account[113..121].copy_from_slice(&100u64.to_le_bytes());
    account[121..129].copy_from_slice(&12u64.to_le_bytes());
    account[129..133].copy_from_slice(&1u32.to_le_bytes());
    account[133..165].copy_from_slice(key(4).as_ref());
    assert_eq!(
        parse_token_account(&account).unwrap(),
        TokenAccountData {
            mint: key(1),
            owner: key(2),
            amount: 456,
            delegate: Some(key(3)),
            state: TokenAccountState::Frozen,
            is_native: Some(100),
            delegated_amount: 12,
            close_authority: Some(key(4)),
        }
    );

    let mut corrupt = mint.clone();
    corrupt[0] = 2;
    assert!(parse_token_mint(&corrupt).is_err());
    let mut corrupt = mint.clone();
    corrupt[45] = 2;
    assert!(parse_token_mint(&corrupt).is_err());
    let mut corrupt = mint.clone();
    corrupt[46] = 2;
    assert!(parse_token_mint(&corrupt).is_err());
    assert!(parse_token_mint(&mint[..81]).is_err());
    account[108] = 3;
    assert!(parse_token_account(&account).is_err());
    account[108] = 1;
    account[109] = 2;
    assert!(parse_token_account(&account).is_err());
    assert!(parse_token_account(&account[..164]).is_err());
}

#[test]
fn strictly_parses_loader_state_prefixes_and_rejects_corruption() {
    let mut buffer = vec![0; 40];
    buffer[0..4].copy_from_slice(&1u32.to_le_bytes());
    buffer[4] = 1;
    buffer[5..37].copy_from_slice(key(1).as_ref());
    assert_eq!(
        parse_upgradeable_loader_state(&buffer).unwrap(),
        UpgradeableLoaderState::Buffer {
            authority: Some(key(1)),
            data_offset: 37,
        }
    );
    let mut program = vec![0; 36];
    program[0..4].copy_from_slice(&2u32.to_le_bytes());
    program[4..36].copy_from_slice(key(2).as_ref());
    assert_eq!(
        parse_upgradeable_loader_state(&program).unwrap(),
        UpgradeableLoaderState::Program {
            programdata_address: key(2),
        }
    );
    let mut programdata = vec![0; 48];
    programdata[0..4].copy_from_slice(&3u32.to_le_bytes());
    programdata[4..12].copy_from_slice(&99u64.to_le_bytes());
    programdata[12] = 1;
    programdata[13..45].copy_from_slice(key(3).as_ref());
    assert_eq!(
        parse_upgradeable_loader_state(&programdata).unwrap(),
        UpgradeableLoaderState::ProgramData {
            slot: 99,
            upgrade_authority: Some(key(3)),
            data_offset: 45,
        }
    );

    buffer[4] = 2;
    assert!(parse_upgradeable_loader_state(&buffer).is_err());
    programdata[12] = 2;
    assert!(parse_upgradeable_loader_state(&programdata).is_err());
    assert!(parse_upgradeable_loader_state(&program[..35]).is_err());
    assert!(parse_upgradeable_loader_state(&[9, 0, 0, 0]).is_err());
}

#[test]
fn arbitrary_short_instruction_and_state_data_never_panics() {
    let programs = [
        system_program_id(),
        spl_token_program_id(),
        associated_token_program_id(),
        bpf_upgradeable_loader_id(),
        spl_governance_program_id(),
        token_2022_program_id(),
        key(222),
    ];
    for program in programs {
        for length in 0..16 {
            for byte in [0, 1, 2, 3, 4, 6, 7, 9, 12, 19, 21, 255] {
                let instruction = ix(program, vec![], vec![byte; length]);
                assert!(std::panic::catch_unwind(|| {
                    decode_instruction(&instruction, &[spl_governance_program_id()])
                })
                .is_ok());
            }
        }
    }
    for length in 0..200 {
        let data = vec![255; length];
        assert!(std::panic::catch_unwind(|| parse_token_mint(&data)).is_ok());
        assert!(std::panic::catch_unwind(|| parse_token_account(&data)).is_ok());
        assert!(std::panic::catch_unwind(|| parse_upgradeable_loader_state(&data)).is_ok());
    }
}
