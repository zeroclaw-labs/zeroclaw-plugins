#[allow(dead_code)]
#[path = "../src/pubkey.rs"]
mod pubkey;

use pubkey::{
    associated_token_address, associated_token_program_id, bpf_upgradeable_loader_id,
    create_program_address, find_program_address, native_treasury_address,
    proposal_transaction_address, realm_config_address, spl_governance_program_id,
    spl_token_program_id, system_program_id, token_2022_program_id, Pubkey, PubkeyError,
    ASSOCIATED_TOKEN_PROGRAM_ID, BPF_UPGRADEABLE_LOADER_ID, MAX_SEEDS, SPL_GOVERNANCE_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
};

const PROPOSAL: &str = "6wR1jdhhJ31bbdRNXva8MxqsgsNLKTxargcdAyZ7FcRj";

#[test]
fn pubkey_base58_and_serde_are_exact() {
    let address: Pubkey = PROPOSAL.parse().unwrap();
    assert_eq!(address.to_string(), PROPOSAL);
    assert_eq!(
        serde_json::to_string(&address).unwrap(),
        format!("\"{PROPOSAL}\"")
    );
    assert_eq!(
        serde_json::from_str::<Pubkey>(&format!("\"{PROPOSAL}\"")).unwrap(),
        address
    );

    assert_eq!("0OIl".parse::<Pubkey>(), Err(PubkeyError::InvalidBase58));
    assert_eq!("1111".parse::<Pubkey>(), Err(PubkeyError::InvalidLength));
}

#[test]
fn program_id_helpers_match_their_canonical_strings() {
    for (parsed, expected) in [
        (spl_governance_program_id(), SPL_GOVERNANCE_PROGRAM_ID),
        (system_program_id(), SYSTEM_PROGRAM_ID),
        (spl_token_program_id(), SPL_TOKEN_PROGRAM_ID),
        (token_2022_program_id(), TOKEN_2022_PROGRAM_ID),
        (associated_token_program_id(), ASSOCIATED_TOKEN_PROGRAM_ID),
        (bpf_upgradeable_loader_id(), BPF_UPGRADEABLE_LOADER_ID),
    ] {
        assert_eq!(parsed.to_string(), expected);
    }
}

#[test]
fn pda_creation_enforces_seed_limits_and_curve_rejection() {
    let program = Pubkey::default();
    let long = [0u8; 33];
    assert_eq!(
        create_program_address(&[&long], &program),
        Err(PubkeyError::SeedTooLong)
    );
    let empty = [0u8; 0];
    let too_many = vec![empty.as_slice(); MAX_SEEDS + 1];
    assert_eq!(
        create_program_address(&too_many, &program),
        Err(PubkeyError::TooManySeeds)
    );
    let max_for_find = vec![empty.as_slice(); MAX_SEEDS];
    assert_eq!(
        find_program_address(&max_for_find, &program),
        Err(PubkeyError::TooManySeeds)
    );

    // SHA256([0] || zero program || marker) decompresses as an Ed25519 point.
    assert_eq!(
        create_program_address(&[&[0]], &program),
        Err(PubkeyError::InvalidSeeds)
    );
    let (derived, _) = find_program_address(&[b"off-curve"], &program).unwrap();
    assert!(!derived.is_on_curve());
}

#[test]
fn derives_all_four_bip76_transaction_pdas() {
    let proposal: Pubkey = PROPOSAL.parse().unwrap();
    let expected = [
        ("4oZNDZdVDGy68vnErEynTqsJqfHH6A6PDEUWBxz6QpLr", 255),
        ("6zvWWwTopzfwabrv3EXHYoMRreJX2ayWmWaVFq6UsipU", 254),
        ("FMe1f7weHQ83Mvj9TEjTZGPdesm1m2f1uUprwXGUgRyM", 253),
        ("5y9dZT4nELdqrpQY4Zfm3ZUXgeANr5tABB8vphkKv2u7", 254),
    ];

    for (index, (address, bump)) in expected.into_iter().enumerate() {
        let actual =
            proposal_transaction_address(&spl_governance_program_id(), &proposal, 0, index as u16)
                .unwrap();
        assert_eq!(actual.0.to_string(), address);
        assert_eq!(actual.1, bump);
    }
}

#[test]
fn derives_bip76_recipient_associated_token_account() {
    let owner = "9bxWkNf3BtJ6iehq9KbX9uCWMjem4TFiPZ19T2sYJHvQ"
        .parse()
        .unwrap();
    let mint = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
        .parse()
        .unwrap();
    let (address, bump) = associated_token_address(&owner, &mint).unwrap();
    assert_eq!(
        address.to_string(),
        "28AymsqjJ6p312raqaNUNn8DADT4kyRAwT2nJ87scmPy"
    );
    assert_eq!(bump, 254);
}

#[test]
fn derives_bip76_realm_config_and_native_treasury() {
    let program = spl_governance_program_id();
    let realm = "84pGFuy1Y27ApK67ApethaPvexeDWA66zNV8gm38TVeQ"
        .parse()
        .unwrap();
    let governance = "Uq5BRkVfdBpMknZJHw6huS3dunEgJpUDv3M2DG3BfQg"
        .parse()
        .unwrap();

    let realm_config = realm_config_address(&program, &realm).unwrap();
    assert_eq!(
        realm_config,
        (
            "4XCcPHj6GuSMg8vgGGGE56DQyNPXG4b9B1jdrz1PYkNr"
                .parse()
                .unwrap(),
            254
        )
    );
    let treasury = native_treasury_address(&program, &governance).unwrap();
    assert_eq!(
        treasury,
        (
            "AGkGWK1R669KDT4FCqgDgK7PgahGJPjD4J9xmVjuL9kn"
                .parse()
                .unwrap(),
            255
        )
    );
}
