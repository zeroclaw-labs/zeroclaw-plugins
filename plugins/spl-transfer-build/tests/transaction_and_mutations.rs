mod common;

use nanosol::{
    inspect::{decode_ata_create_idempotent, decode_transfer_checked},
    instruction::TokenProgram,
    message::{MessageVersion, Transaction},
    pubkey::Pubkey,
    reference::derive_payment_reference,
};
use serde_json::json;
use spl_transfer_build::transfer::{
    build_unsigned_bytes, execute_component_input, verify_final_bytes, TransferOutput,
    VerificationPolicy,
};

use common::{
    config_for, host_inject, pubkey, valid_args, valid_config, MockTransport, BLOCKHASH, MINT,
    RECIPIENT, SENDER,
};

type TransactionMutation = (&'static str, Box<dyn Fn(&mut Transaction)>);

fn policy() -> VerificationPolicy {
    let sender = pubkey(SENDER);
    let recipient = pubkey(RECIPIENT);
    let mint = pubkey(MINT);
    let reference = derive_payment_reference(&recipient, Some(&mint), "25.01", "412");
    VerificationPolicy {
        sender,
        recipient,
        mint,
        token_program: TokenProgram::Legacy,
        raw_amount: 25_010_000,
        decimals: 6,
        recent_blockhash: pubkey(BLOCKHASH).to_bytes(),
        reference: Some(reference),
        memo: Some("invoice 412".to_string()),
    }
}

fn mutated_transaction(bytes: &[u8], mutate: impl FnOnce(&mut Transaction)) -> Option<Vec<u8>> {
    let mut transaction = Transaction::deserialize(bytes).expect("valid fixture");
    mutate(&mut transaction);
    transaction.serialize().ok()
}

#[test]
fn supported_transaction_has_exact_v0_unsigned_static_shape() {
    let policy = policy();
    let bytes = build_unsigned_bytes(&policy).expect("transaction");
    let verified = verify_final_bytes(&bytes, &policy).expect("verified bytes");
    let transaction = Transaction::deserialize(&bytes).expect("decoded transaction");
    assert_eq!(transaction.message.version, MessageVersion::V0);
    assert_eq!(transaction.signatures, vec![[0; 64]]);
    assert_eq!(transaction.message.header.num_required_signatures, 1);
    assert_eq!(transaction.message.header.num_readonly_signed_accounts, 0);
    assert_eq!(transaction.message.instructions.len(), 3);

    let create = decode_ata_create_idempotent(&transaction.message, 0).expect("CreateIdempotent");
    assert_eq!(transaction.message.instructions[0].data, [1]);
    assert_eq!(create.payer, policy.sender);
    assert_eq!(create.owner, policy.recipient);
    assert_eq!(create.mint, policy.mint);
    assert_eq!(create.ata, verified.destination_ata);

    let transfer = decode_transfer_checked(&transaction.message, 1).expect("TransferChecked");
    assert_eq!(transaction.message.instructions[1].data[0], 12);
    assert_eq!(
        &transaction.message.instructions[1].data[1..9],
        &25_010_000_u64.to_le_bytes()
    );
    assert_eq!(transaction.message.instructions[1].data[9], 6);
    assert_eq!(transfer.source, verified.source_ata);
    assert_eq!(transfer.destination, verified.destination_ata);
    assert_eq!(transfer.authority, policy.sender);
    assert_eq!(transfer.reference, policy.reference);
}

#[test]
fn final_byte_mutations_are_all_rejected_instead_of_reusing_the_original_summary() {
    let policy = policy();
    let bytes = build_unsigned_bytes(&policy).expect("transaction");
    let original = verify_final_bytes(&bytes, &policy).expect("baseline");

    let mutations: Vec<TransactionMutation> = vec![
        (
            "amount bytes",
            Box::new(|tx| tx.message.instructions[1].data[1] ^= 1),
        ),
        (
            "decimal byte",
            Box::new(|tx| tx.message.instructions[1].data[9] ^= 1),
        ),
        (
            "mint index",
            Box::new(|tx| tx.message.instructions[1].account_indexes[1] = 0),
        ),
        (
            "destination index",
            Box::new(|tx| tx.message.instructions[1].account_indexes[2] = 0),
        ),
        (
            "source index",
            Box::new(|tx| tx.message.instructions[1].account_indexes[0] = 0),
        ),
        (
            "authority index",
            Box::new(|tx| tx.message.instructions[1].account_indexes[3] = 1),
        ),
        (
            "program id index",
            Box::new(|tx| tx.message.instructions[1].program_id_index = 0),
        ),
        (
            "fee payer",
            Box::new(|tx| tx.message.account_keys[0] = Pubkey::new([42; 32])),
        ),
        (
            "reference index",
            Box::new(|tx| tx.message.instructions[1].account_indexes[4] = 0),
        ),
        (
            "memo",
            Box::new(|tx| tx.message.instructions[2].data[0] ^= 1),
        ),
        (
            "instruction order",
            Box::new(|tx| tx.message.instructions.swap(0, 1)),
        ),
        (
            "instruction count",
            Box::new(|tx| {
                tx.message.instructions.pop();
            }),
        ),
        (
            "appended duplicate instruction",
            Box::new(|tx| {
                let extra = tx.message.instructions[2].clone();
                tx.message.instructions.push(extra);
            }),
        ),
        (
            "appended unknown instruction",
            Box::new(|tx| {
                let mut extra = tx.message.instructions[2].clone();
                extra.program_id_index = 0;
                extra.account_indexes.clear();
                extra.data = vec![0xde, 0xad];
                tx.message.instructions.push(extra);
            }),
        ),
        (
            "signer count",
            Box::new(|tx| {
                tx.message.header.num_required_signatures = 2;
                tx.signatures.push([0; 64]);
            }),
        ),
        (
            "account flags",
            Box::new(|tx| {
                tx.message.header.num_readonly_unsigned_accounts = tx
                    .message
                    .header
                    .num_readonly_unsigned_accounts
                    .saturating_sub(1);
            }),
        ),
    ];

    for (name, mutation) in mutations {
        let mutated = mutated_transaction(&bytes, mutation).expect("serializable mutation");
        assert!(
            verify_final_bytes(&mutated, &policy).is_err(),
            "mutation accepted: {name}; baseline {original:?}"
        );
    }

    let mut nonzero_signature = bytes.clone();
    nonzero_signature[1] = 1;
    assert!(verify_final_bytes(&nonzero_signature, &policy).is_err());

    let mut address_lookup = bytes.clone();
    *address_lookup.last_mut().expect("lookup count") = 1;
    assert!(verify_final_bytes(&address_lookup, &policy).is_err());

    let mut trailing = bytes;
    trailing.push(0);
    assert!(verify_final_bytes(&trailing, &policy).is_err());
}

#[test]
fn returned_base64_is_exactly_the_verified_bytes_and_summary_comes_after_decode() {
    let result = execute_component_input(
        &host_inject(valid_args(), &valid_config()),
        &MockTransport::valid(6),
    );
    assert!(result.success, "{:?}", result.error);
    let output: TransferOutput = serde_json::from_str(&result.output).expect("output");
    let transaction = Transaction::from_base64(&output.transaction_base64).expect("base64 bytes");
    let policy = policy();
    let expected = build_unsigned_bytes(&policy).expect("expected bytes");
    assert_eq!(transaction.serialize().expect("reserialized"), expected);
    let decoded = verify_final_bytes(&expected, &policy).expect("verified");
    assert!(output.summary.contains(&decoded.recipient.to_string()));
    assert!(output.summary.contains("25.01"));
    assert!(output.summary.contains("invoice 412"));
    assert!(output
        .summary
        .contains("external approval and signing required"));
}

#[test]
fn m2_reference_golden_is_identical_when_the_same_invoice_tuple_is_used() {
    let mut args = valid_args();
    args["recipient"] = json!(SENDER);
    args.as_object_mut().expect("object").remove("memo");
    let config = config_for(RECIPIENT, SENDER, "1000");
    let result = execute_component_input(&host_inject(args, &config), &MockTransport::valid(6));
    assert!(result.success, "{:?}", result.error);
    let output: TransferOutput = serde_json::from_str(&result.output).expect("output");
    assert_eq!(
        output.reference.as_deref(),
        Some("ECvLKMSgRzVdJjZsdiGAPcRSjwVjS9f7HxizfC256Kei")
    );
}
