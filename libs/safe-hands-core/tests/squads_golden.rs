//! Golden test: our Squads v4 encoding must match the OFFICIAL @sqds/multisig
//! SDK byte-for-byte (fixture captured via scratch/golden-gen/squads-gen.js).

use safe_hands_core::crypto::parse_pubkey;
use safe_hands_core::ix;
use safe_hands_core::squads;

const CREATE_KEY: &str = "J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf"; // kp(9)
const CREATOR: &str = "5Z6Ay5NEcbg3xhopc522sBCRXQujkTiuDRnHGfQdcnSf"; // kp(10)
const DEST: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"; // kp(2)

const SDK_MULTISIG_PDA: &str = "7jmBsJmAV5aAwEQkw3AybYgTMHVUzbWgWMGvyMjhSEDQ";
const SDK_TRANSACTION_PDA: &str = "83n2y3xvVFQtK4pHgUGzbAwK6ovjWm6PV5WopRhSPdEz";
const SDK_PROPOSAL_PDA: &str = "uUzFXso65jxn5uGvzvSaQsLFF2dBzLjXoMAwCWJa4jv";
const SDK_VAULT_PDA: &str = "46t5cnapyYC1RNVCgezqxNssv65qnF3FgddyG86egHL1";

const SDK_CREATE_IX_HEX: &str = "30fa4ea8d0e2dad3000078000000010101032e14b880da9065be9ed5f2f51025cc13fc83461a6dcd5001d58b4fe54bcfb3568139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394000000000000000000000000000000000000000000000000000000000000000001020200010c000200000000ca9a3b00000000000106000000676f6c64656e";
const SDK_PROPOSAL_IX_HEX: &str = "dc3c49e01e6c4f9f2a0000000000000000";
const SDK_INNER_MESSAGE_HEX: &str = "010101032e14b880da9065be9ed5f2f51025cc13fc83461a6dcd5001d58b4fe54bcfb3568139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394000000000000000000000000000000000000000000000000000000000000000001020200010c000200000000ca9a3b0000000000";

#[test]
fn pdas_match_sdk() {
    let create_key = parse_pubkey(CREATE_KEY).expect("create key");
    let (multisig, bump) = squads::multisig_pda_with_bump(&create_key);
    assert_eq!(multisig, squads::multisig_pda(&create_key));
    assert_ne!(bump, 0);
    assert_eq!(multisig.to_string(), SDK_MULTISIG_PDA, "multisig PDA");
    assert_eq!(
        squads::transaction_pda(&multisig, 42).to_string(),
        SDK_TRANSACTION_PDA,
        "transaction PDA"
    );
    assert_eq!(
        squads::proposal_pda(&multisig, 42).to_string(),
        SDK_PROPOSAL_PDA,
        "proposal PDA"
    );
    assert_eq!(
        squads::vault_pda(&multisig, 0).to_string(),
        SDK_VAULT_PDA,
        "vault PDA"
    );
}

#[test]
fn inner_message_matches_sdk_byte_for_byte() {
    let vault = parse_pubkey(SDK_VAULT_PDA).expect("vault");
    let dest = parse_pubkey(DEST).expect("dest");
    // SDK scenario: 1 SOL transfer from vault to dest, no blockhash (Squads format).
    let transfer = ix::system_transfer(&vault, &dest, 1_000_000_000);
    let ours = squads::compile_inner_message(&[transfer], &vault).expect("compile inner message");
    assert_eq!(
        hex::encode(&ours),
        SDK_INNER_MESSAGE_HEX,
        "inner message must match the official SDK compilation"
    );
}

#[test]
fn vault_transaction_create_matches_sdk_byte_for_byte() {
    let multisig = parse_pubkey(SDK_MULTISIG_PDA).expect("multisig");
    let transaction = parse_pubkey(SDK_TRANSACTION_PDA).expect("transaction");
    let creator = parse_pubkey(CREATOR).expect("creator");
    let inner = hex::decode(SDK_INNER_MESSAGE_HEX).expect("inner hex");
    let ix = squads::vault_transaction_create(
        &multisig,
        &transaction,
        &creator,
        &creator,
        0,
        0,
        &inner,
        Some("golden"),
    );
    assert_eq!(
        hex::encode(&ix.data),
        SDK_CREATE_IX_HEX,
        "vaultTransactionCreate encoding must match the official SDK"
    );
}

#[test]
fn proposal_create_matches_sdk_byte_for_byte() {
    let multisig = parse_pubkey(SDK_MULTISIG_PDA).expect("multisig");
    let proposal = parse_pubkey(SDK_PROPOSAL_PDA).expect("proposal");
    let creator = parse_pubkey(CREATOR).expect("creator");
    let ix = squads::proposal_create(&multisig, &proposal, &creator, &creator, 42, false);
    assert_eq!(
        hex::encode(&ix.data),
        SDK_PROPOSAL_IX_HEX,
        "proposalCreate encoding must match the official SDK"
    );
}
