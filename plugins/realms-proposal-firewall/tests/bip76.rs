include!("policy.rs");

#[test]
fn synthetic_bip76_equivalent_snapshot_has_exact_effects() {
    let proposal_address: Pubkey = "6wR1jdhhJ31bbdRNXva8MxqsgsNLKTxargcdAyZ7FcRj"
        .parse()
        .unwrap();
    let governance_address: Pubkey = "Uq5BRkVfdBpMknZJHw6huS3dunEgJpUDv3M2DG3BfQg"
        .parse()
        .unwrap();
    let realm_address: Pubkey = "84pGFuy1Y27ApK67ApethaPvexeDWA66zNV8gm38TVeQ"
        .parse()
        .unwrap();
    let mint: Pubkey = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
        .parse()
        .unwrap();
    let source: Pubkey = "F8FqZuUKfoy58aHLW6bfeEhfW9sTtJyqFTqnxVmGZ6dU"
        .parse()
        .unwrap();
    let recipient: Pubkey = "9bxWkNf3BtJ6iehq9KbX9uCWMjem4TFiPZ19T2sYJHvQ"
        .parse()
        .unwrap();
    let destination: Pubkey = "28AymsqjJ6p312raqaNUNn8DADT4kyRAwT2nJ87scmPy"
        .parse()
        .unwrap();
    assert_eq!(
        pubkey::associated_token_address(&recipient, &mint)
            .unwrap()
            .0,
        destination
    );

    let (mut snapshot, mut config) = snapshot(&[], recipient);
    let program = spl_governance_program_id();
    let treasury = native_treasury_address(&program, &governance_address)
        .unwrap()
        .0;
    snapshot.proposal_address = proposal_address;
    snapshot.proposal.governance = governance_address;
    snapshot.proposal.governing_token_mint = mint;
    snapshot.proposal.vote_threshold = Some(VoteThreshold::YesVotePercentage(1));
    snapshot.proposal.max_vote_weight = Some(1_000);
    snapshot.proposal.options[0].vote_weight = 10;
    snapshot.governance.realm = realm_address;
    snapshot.governance.config.community_vote_threshold = VoteThreshold::YesVotePercentage(1);
    snapshot.governance.config.transactions_hold_up_time = 0;
    snapshot.realm.community_mint = mint;
    snapshot.transactions[0].address =
        proposal_transaction_address(&program, &proposal_address, 0, 0)
            .unwrap()
            .0;
    snapshot.transactions[0].transaction.proposal = proposal_address;
    let ata_create = InstructionData {
        program_id: pubkey::associated_token_program_id(),
        accounts: vec![
            meta(treasury, true, true),
            meta(destination, false, true),
            meta(recipient, false, false),
            meta(mint, false, false),
            meta(pubkey::system_program_id(), false, false),
            meta(spl_token_program_id(), false, false),
        ],
        data: vec![0],
    };
    snapshot.transactions[0].transaction.instructions = vec![
        ata_create,
        transfer_checked(
            source,
            mint,
            destination,
            treasury,
            442_610_445_030_596_600,
            5,
        ),
        InstructionData {
            program_id: key(70),
            accounts: vec![],
            data: vec![1],
        },
    ];
    snapshot.dependencies = vec![
        DependencyAccount {
            address: source,
            account: Some(token_rpc_account(token_account(
                mint,
                treasury,
                450_000_000_000_000_000,
            ))),
        },
        DependencyAccount {
            address: destination,
            account: Some(token_rpc_account(token_account(mint, recipient, 0))),
        },
        DependencyAccount {
            address: mint,
            account: Some(token_rpc_account(token_mint(5))),
        },
    ];
    config.allowed_destination_owners.clear();
    config.allowed_mints = vec![mint];

    let report = analyze_snapshot(&snapshot, &config);
    let finding_codes = codes(&report);
    for expected in [
        "TREASURY_DRAIN",
        "EXTERNAL_RECIPIENT",
        "FRESH_DESTINATION_ACCOUNT",
        "LOW_APPROVAL_THRESHOLD",
        "BARELY_ABOVE_THRESHOLD",
        "ZERO_EXECUTION_HOLDUP",
        "UNKNOWN_PROGRAM",
    ] {
        assert!(finding_codes.contains(&expected), "missing {expected}");
    }
    assert!(report.complete);
    assert_eq!(report.verdict, Verdict::Critical, "{report:#?}");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.evidence.contains("4426104450305.966")));
    assert_eq!(report.proposal.address, proposal_address.to_string());
}

#[test]
fn frozen_bip76_mainnet_accounts_decode_to_expected_report() {
    use base64::Engine as _;

    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/bip76/accounts.json")).unwrap();
    let values = fixture["result"]["value"].as_array().unwrap();
    assert_eq!(values.len(), 11);
    let account = |index: usize| {
        let value = &values[index];
        Account {
            lamports: value["lamports"].as_u64().unwrap(),
            owner: value["owner"].as_str().unwrap().parse().unwrap(),
            executable: value["executable"].as_bool().unwrap(),
            data: base64::engine::general_purpose::STANDARD
                .decode(value["data"][0].as_str().unwrap())
                .unwrap(),
        }
    };

    let proposal_address: Pubkey = "6wR1jdhhJ31bbdRNXva8MxqsgsNLKTxargcdAyZ7FcRj"
        .parse()
        .unwrap();
    let proposal = governance::decode_proposal_v2(&account(0).data).unwrap();
    let governance = governance::decode_governance_v2(&account(1).data).unwrap();
    let realm = governance::decode_realm_v2(&account(2).data).unwrap();
    let realm_config = governance::decode_realm_config_account(&account(3).data).unwrap();
    let transaction_addresses: [Pubkey; 4] = [
        "4oZNDZdVDGy68vnErEynTqsJqfHH6A6PDEUWBxz6QpLr",
        "6zvWWwTopzfwabrv3EXHYoMRreJX2ayWmWaVFq6UsipU",
        "FMe1f7weHQ83Mvj9TEjTZGPdesm1m2f1uUprwXGUgRyM",
        "5y9dZT4nELdqrpQY4Zfm3ZUXgeANr5tABB8vphkKv2u7",
    ]
    .map(|value| value.parse().unwrap());
    let transactions = transaction_addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| SnapshotTransaction {
            address,
            transaction: governance::decode_proposal_transaction_v2(&account(index + 4).data)
                .unwrap(),
        })
        .collect();
    let dependency_addresses: [Pubkey; 3] = [
        "F8FqZuUKfoy58aHLW6bfeEhfW9sTtJyqFTqnxVmGZ6dU",
        "28AymsqjJ6p312raqaNUNn8DADT4kyRAwT2nJ87scmPy",
        "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
    ]
    .map(|value| value.parse().unwrap());
    let dependencies = dependency_addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| DependencyAccount {
            address,
            account: Some(account(index + 8)),
        })
        .collect();
    let snapshot = Snapshot {
        proposal_address,
        governance_program_id: spl_governance_program_id(),
        proposal,
        governance,
        realm,
        realm_config: Some(realm_config),
        transactions,
        dependencies,
        evidence_slot: fixture["result"]["context"]["slot"].as_u64().unwrap(),
    };
    let mint = dependency_addresses[2];
    let mut config = policy(mint);
    config.allowed_destination_owners.clear();
    let report = analyze_snapshot(&snapshot, &config);

    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/bip76/expected.json")).unwrap();
    assert_eq!(report.verdict, Verdict::Critical, "{report:#?}");
    assert!(report.complete);
    for code in expected["required_findings"].as_array().unwrap() {
        let code = code.as_str().unwrap();
        assert!(codes(&report).contains(&code), "missing {code}");
    }
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.evidence.contains("4426104450305.966")));

    let transaction: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/bip76/transaction.json")).unwrap();
    assert_eq!(
        transaction["result"]["meta"]["err"],
        serde_json::Value::Null
    );
    assert_eq!(
        transaction["result"]["meta"]["postTokenBalances"][1]["uiTokenAmount"]["amount"],
        "442610445030596600"
    );
}
