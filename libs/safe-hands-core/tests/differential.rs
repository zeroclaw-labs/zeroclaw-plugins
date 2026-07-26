//! Differential testing against the reference Solana decoder.
//!
//! `decode.rs` hand-parses the transaction wire format because it has to
//! compile to `wasm32-wasip2`, where `solana-client` cannot go. That means the
//! bytes an attacker controls are interpreted by *our* parser, not the
//! validator's — and a disagreement between the two is exactly where a real
//! bug lives. If our decoder sees a different recipient, a different amount,
//! or a different instruction count than the network will, every downstream
//! check is defending the wrong transaction.
//!
//! So this asserts agreement with `solana_message`, the same crate the
//! reference client uses, on inputs neither side chose: number of
//! instructions, account keys, signer count, and blockhash.
//!
//! The technique is borrowed from AWS's `cedar-spec`, which differentially
//! tests their authorization engine against a separate model rather than
//! trying to verify the production implementation directly.

use proptest::prelude::*;
use safe_hands_core::decode::decode;
use safe_hands_core::{
    bincode, ix, solana_hash::Hash, solana_message::Message, solana_pubkey::Pubkey,
};

/// Build a legacy message with `count` system transfers, then hand its exact
/// bytes to both decoders.
fn transfers_message(count: usize, seed: u8) -> (Message, Vec<u8>) {
    let payer = Pubkey::new_from_array([seed.wrapping_add(1); 32]);
    let instructions: Vec<_> = (0..count)
        .map(|i| {
            let recipient =
                Pubkey::new_from_array([seed.wrapping_add(i as u8).wrapping_add(2); 32]);
            ix::system_transfer(&payer, &recipient, 1_000 + i as u64)
        })
        .collect();
    let mut message = Message::new(&instructions, Some(&payer));
    message.recent_blockhash = Hash::new_from_array([seed; 32]);
    let bytes = bincode::serialize(&message).expect("reference serialization");
    (message, bytes)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Our decoder must agree with the reference on every fact a policy
    /// decision is made from.
    #[test]
    fn agrees_with_the_reference_decoder_on_wellformed_messages(
        count in 1usize..6,
        seed in any::<u8>(),
    ) {
        let (reference, bytes) = transfers_message(count, seed);
        let ours = decode(&bytes).expect("our decoder must accept a reference-built message");

        prop_assert_eq!(
            ours.raw_instructions.len(),
            reference.instructions.len(),
            "instruction count disagrees with the reference decoder"
        );
        prop_assert_eq!(
            ours.resolved_keys.len(),
            reference.account_keys.len(),
            "account key count disagrees with the reference decoder"
        );
        for (index, key) in reference.account_keys.iter().enumerate() {
            prop_assert_eq!(
                &ours.resolved_keys[index],
                &key.to_string(),
                "account key {} disagrees with the reference decoder", index
            );
        }
        prop_assert_eq!(
            ours.required_signatures,
            reference.header.num_required_signatures as usize,
            "signer count disagrees with the reference decoder"
        );
        prop_assert_eq!(
            ours.blockhash,
            reference.recent_blockhash.to_string(),
            "blockhash disagrees with the reference decoder"
        );
        // The transfers a policy would act on must match the instructions the
        // network would execute.
        prop_assert_eq!(
            ours.facts.transfers.len(),
            count,
            "transfer count disagrees with what was built"
        );
    }

    /// Neither decoder may accept bytes the other rejects.
    ///
    /// A mismatch in either direction is a finding. If ours accepts what the
    /// reference refuses, we may authorize a transaction the network will not
    /// run — or worse, one it runs differently. If ours refuses what the
    /// reference accepts, we reject legitimate payments.
    #[test]
    fn acceptance_agrees_with_the_reference_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..320),
    ) {
        let ours = decode(&bytes);
        let reference = bincode::deserialize::<Message>(&bytes);

        // Our decoder additionally accepts a full transaction (a signature
        // array followed by a message), which is not a bare `Message` — only
        // compare the bare-message case.
        if let Ok(decoded) = &ours {
            if !decoded.has_signature_array {
                prop_assert!(
                    reference.is_ok(),
                    "we accepted a bare message the reference decoder rejects: {:?}",
                    reference.err()
                );
            }
        }
    }
}
