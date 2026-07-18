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

fn remap_index(index: &mut u8, first: u8, second: u8) {
    if *index == first {
        *index = second;
    } else if *index == second {
        *index = first;
    }
}

fn remap_all_instruction_indexes(transaction: &mut Transaction, first: u8, second: u8) {
    for instruction in &mut transaction.message.instructions {
        remap_index(&mut instruction.program_id_index, first, second);
        for index in &mut instruction.account_indexes {
            remap_index(index, first, second);
        }
    }
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
fn audit_mutation_unreferenced_extra_static_key_is_rejected() {
    let policy = policy();
    let bytes = build_unsigned_bytes(&policy).expect("transaction");
    let mutated = mutated_transaction(&bytes, |transaction| {
        transaction
            .message
            .account_keys
            .push(Pubkey::new([201; 32]));
        transaction.message.header.num_readonly_unsigned_accounts += 1;
    })
    .expect("serializable unused-key mutation");
    assert!(verify_final_bytes(&mutated, &policy).is_err());
}

#[test]
fn audit_mutation_six_account_transfer_checked_is_rejected() {
    let policy = policy();
    let bytes = build_unsigned_bytes(&policy).expect("transaction");
    let mutated = mutated_transaction(&bytes, |transaction| {
        let extra_index =
            u8::try_from(transaction.message.account_keys.len()).expect("fixture index");
        transaction
            .message
            .account_keys
            .push(Pubkey::new([202; 32]));
        transaction.message.header.num_readonly_unsigned_accounts += 1;
        transaction.message.instructions[1]
            .account_indexes
            .push(extra_index);
    })
    .expect("serializable six-account mutation");
    assert_eq!(
        Transaction::deserialize(&mutated)
            .expect("wire-decodable mutation")
            .message
            .instructions[1]
            .account_indexes
            .len(),
        6
    );
    assert!(verify_final_bytes(&mutated, &policy).is_err());
}

#[test]
fn audit_mutation_reference_direction_mismatches_are_rejected() {
    let with_reference_policy = policy();
    let bytes_with_reference =
        build_unsigned_bytes(&with_reference_policy).expect("referenced transaction");
    let mut expects_none = with_reference_policy.clone();
    expects_none.reference = None;
    assert!(verify_final_bytes(&bytes_with_reference, &expects_none).is_err());

    let mut without_reference_policy = policy();
    without_reference_policy.reference = None;
    let bytes_without_reference =
        build_unsigned_bytes(&without_reference_policy).expect("unreferenced transaction");
    assert!(verify_final_bytes(&bytes_without_reference, &with_reference_policy).is_err());
}

#[test]
fn audit_mutation_noncanonical_static_key_order_with_remapped_indexes_is_rejected() {
    let policy = policy();
    let bytes = build_unsigned_bytes(&policy).expect("transaction");
    let mutated = mutated_transaction(&bytes, |transaction| {
        let key_count = transaction.message.account_keys.len();
        let readonly_count = usize::from(transaction.message.header.num_readonly_unsigned_accounts);
        assert!(
            readonly_count >= 2,
            "fixture has two readonly unsigned keys"
        );
        let first = key_count - readonly_count;
        let second = first + 1;
        transaction.message.account_keys.swap(first, second);
        remap_all_instruction_indexes(
            transaction,
            u8::try_from(first).expect("first fixture index"),
            u8::try_from(second).expect("second fixture index"),
        );
    })
    .expect("serializable canonical-order mutation");

    let decoded = Transaction::deserialize(&mutated).expect("wire-decodable mutation");
    assert_eq!(
        decode_transfer_checked(&decoded.message, 1)
            .expect("semantically decodable transfer")
            .amount,
        policy.raw_amount
    );
    assert!(verify_final_bytes(&mutated, &policy).is_err());
}

#[test]
fn audit_mutation_separate_readonly_signer_authority_is_rejected() {
    let policy = policy();
    let bytes = build_unsigned_bytes(&policy).expect("transaction");
    let separate_authority = Pubkey::new([203; 32]);
    let mutated = mutated_transaction(&bytes, |transaction| {
        transaction
            .message
            .account_keys
            .insert(1, separate_authority);
        transaction.message.header.num_required_signatures = 2;
        transaction.message.header.num_readonly_signed_accounts = 1;
        transaction.signatures.push([0; 64]);
        for instruction in &mut transaction.message.instructions {
            if instruction.program_id_index >= 1 {
                instruction.program_id_index += 1;
            }
            for index in &mut instruction.account_indexes {
                if *index >= 1 {
                    *index += 1;
                }
            }
        }
        transaction.message.instructions[1].account_indexes[3] = 1;
    })
    .expect("serializable signer mutation");

    let decoded = Transaction::deserialize(&mutated).expect("wire-decodable mutation");
    assert_eq!(decoded.message.header.num_required_signatures, 2);
    assert_eq!(decoded.message.header.num_readonly_signed_accounts, 1);
    assert_eq!(
        decode_transfer_checked(&decoded.message, 1)
            .expect("semantically decodable transfer")
            .authority,
        separate_authority
    );
    assert!(verify_final_bytes(&mutated, &policy).is_err());
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
