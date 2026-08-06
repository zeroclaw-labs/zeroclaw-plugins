//! The chain is only useful if tampering is *detected*, so most of these tests
//! tamper. Each one performs an edit an operator might actually want to make —
//! drop an inconvenient decision, swap two, rewrite one, quietly shorten the
//! tail — and asserts the log stops verifying.

use super::*;
use crate::crypto::parse_pubkey;
use proptest::prelude::*;

const AUTHORITY: &str = "5Z6Ay5NEcbg3xhopc522sBCRXQujkTiuDRnHGfQdcnSf";
const OTHER_AUTHORITY: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";

fn authority() -> Pubkey {
    parse_pubkey(AUTHORITY).expect("test authority")
}

fn decision(n: u8) -> Head {
    Head([n; 32])
}

/// Build a well-formed chain of `count` entries.
fn chain(authority: &Pubkey, count: u8) -> Vec<Link> {
    let mut head = genesis_head(authority);
    let mut links = Vec::new();
    for n in 0..count {
        let decision_id = decision(n);
        let seq = n as u64;
        head = next_head(&head, seq, &decision_id);
        links.push(Link {
            seq,
            decision_id,
            head,
        });
    }
    links
}

#[test]
fn a_well_formed_chain_verifies() {
    let authority = authority();
    let links = chain(&authority, 8);
    let head = verify_chain(&authority, &links).expect("chain verifies");
    assert_eq!(head, links.last().expect("non-empty").head);
}

#[test]
fn an_empty_log_verifies_to_its_genesis() {
    let authority = authority();
    assert_eq!(
        verify_chain(&authority, &[]).expect("empty verifies"),
        genesis_head(&authority)
    );
}

/// Two operators must not share a starting point, or entries could be moved
/// between their logs and still verify.
#[test]
fn the_genesis_is_bound_to_the_authority() {
    let a = parse_pubkey(AUTHORITY).expect("a");
    let b = parse_pubkey(OTHER_AUTHORITY).expect("b");
    assert_ne!(genesis_head(&a), genesis_head(&b));

    // The same entries under a different authority produce a different head,
    // so one operator's log cannot be presented as another's.
    let links = chain(&a, 4);
    assert!(matches!(
        verify_chain(&b, &links),
        Err(ChainError::HeadMismatch { seq: 0, .. })
    ));
}

/// The edit an operator most wants to make: remove the decision that looks bad.
#[test]
fn deleting_an_entry_breaks_the_chain() {
    let authority = authority();
    let mut links = chain(&authority, 6);
    links.remove(3);
    assert_eq!(
        verify_chain(&authority, &links),
        Err(ChainError::SequenceBroken {
            expected: 3,
            found: 4
        })
    );
}

/// Renumbering after a deletion does not help: the heads no longer line up.
#[test]
fn deleting_and_renumbering_breaks_the_chain_too() {
    let authority = authority();
    let mut links = chain(&authority, 6);
    links.remove(3);
    for (index, link) in links.iter_mut().enumerate() {
        link.seq = index as u64;
    }
    assert!(matches!(
        verify_chain(&authority, &links),
        Err(ChainError::HeadMismatch { seq: 3, .. })
    ));
}

#[test]
fn rewriting_a_decision_breaks_the_chain() {
    let authority = authority();
    let mut links = chain(&authority, 6);
    links[2].decision_id = decision(200);
    assert!(matches!(
        verify_chain(&authority, &links),
        Err(ChainError::HeadMismatch { seq: 2, .. })
    ));
}

/// Rewriting an entry *and* recomputing its head is not enough either — every
/// later head depends on it.
#[test]
fn rewriting_an_entry_and_its_own_head_still_breaks_the_next_one() {
    let authority = authority();
    let mut links = chain(&authority, 6);
    let previous = links[1].head;
    links[2].decision_id = decision(200);
    links[2].head = next_head(&previous, 2, &links[2].decision_id);
    assert!(matches!(
        verify_chain(&authority, &links),
        Err(ChainError::HeadMismatch { seq: 3, .. })
    ));
}

#[test]
fn reordering_two_entries_breaks_the_chain() {
    let authority = authority();
    let mut links = chain(&authority, 6);
    links.swap(2, 4);
    assert!(matches!(
        verify_chain(&authority, &links),
        Err(ChainError::SequenceBroken { expected: 2, .. })
    ));
}

/// Truncating the tail leaves a self-consistent chain. Only an anchor catches
/// it — which is exactly why anchoring exists.
#[test]
fn truncation_is_invisible_to_the_chain_and_caught_by_the_anchor() {
    let authority = authority();
    let full = chain(&authority, 6);
    let published = Anchor {
        count: 6,
        head: full[5].head,
    };

    let mut shortened = full.clone();
    shortened.truncate(4);
    assert!(
        verify_chain(&authority, &shortened).is_ok(),
        "a truncated chain is internally consistent — the chain alone cannot see this"
    );

    assert_eq!(
        check_anchor(&authority, &shortened, &published),
        AnchorVerdict::Truncated {
            anchored: 6,
            held: 4
        }
    );
}

#[test]
fn a_matching_anchor_is_consistent() {
    let authority = authority();
    let links = chain(&authority, 6);
    let anchor = Anchor {
        count: 6,
        head: links[5].head,
    };
    assert!(check_anchor(&authority, &links, &anchor).is_consistent());
}

/// An anchor from earlier still pins its prefix once the log has grown.
#[test]
fn an_older_anchor_still_checks_against_a_longer_log() {
    let authority = authority();
    let links = chain(&authority, 10);
    let anchor = Anchor {
        count: 4,
        head: links[3].head,
    };
    assert_eq!(
        check_anchor(&authority, &links, &anchor),
        AnchorVerdict::Consistent {
            count: 4,
            head: links[3].head
        }
    );
}

/// Rebuilding history under a published head is the attack anchoring exists to
/// name.
#[test]
fn a_rewritten_history_is_reported_as_a_fork() {
    let authority = authority();
    let honest = chain(&authority, 5);
    let anchor = Anchor {
        count: 5,
        head: honest[4].head,
    };

    // Rebuild the log with entry 1 replaced, recomputing every head so the
    // chain itself verifies cleanly.
    let mut forged = Vec::new();
    let mut head = genesis_head(&authority);
    for n in 0..5u8 {
        let decision_id = if n == 1 { decision(99) } else { decision(n) };
        head = next_head(&head, n as u64, &decision_id);
        forged.push(Link {
            seq: n as u64,
            decision_id,
            head,
        });
    }
    assert!(
        verify_chain(&authority, &forged).is_ok(),
        "the forgery is internally consistent by construction"
    );

    let verdict = check_anchor(&authority, &forged, &anchor);
    assert!(matches!(verdict, AnchorVerdict::Forked { count: 5, .. }));
    assert!(verdict.to_string().contains("FORKED"));
}

#[test]
fn head_after_refuses_to_invent_entries_it_does_not_have() {
    let authority = authority();
    let links = chain(&authority, 3);
    assert!(head_after(&authority, &links, 4).is_none());
    assert_eq!(
        head_after(&authority, &links, 0),
        Some(genesis_head(&authority))
    );
}

// ── memo encoding ────────────────────────────────────────────────────────────

#[test]
fn an_anchor_memo_round_trips() {
    let anchor = Anchor {
        count: 41,
        head: Head([0xab; 32]),
    };
    let memo = anchor_memo(&anchor);
    assert_eq!(memo, format!("sh1 n=41 head={}", "ab".repeat(32)));
    assert_eq!(parse_anchor_memo(&memo), Some(anchor));
}

/// Memos are a shared, unauthenticated namespace. Anything that is not ours
/// must be ignored rather than misread.
#[test]
fn foreign_memos_are_not_mistaken_for_anchors() {
    for memo in [
        "",
        "hello world",
        "sh2 n=1 head=00",
        "sh1",
        "sh1 n=1",
        "sh1 head=00",
        "sh1 n=notanumber head=00",
        "order-42",
    ] {
        assert_eq!(parse_anchor_memo(memo), None, "memo {memo:?} parsed");
    }
}

#[test]
fn an_anchor_memo_fits_comfortably_in_a_transaction() {
    let memo = anchor_memo(&Anchor {
        count: u64::MAX,
        head: Head([0xff; 32]),
    });
    assert!(memo.len() < 128, "memo is {} bytes", memo.len());
}

// ── the unsigned anchor transaction ─────────────────────────────────────────

#[test]
fn the_anchor_transaction_is_a_single_attributable_memo() {
    let authority = authority();
    let blockhash = Hash::new_from_array([7u8; 32]);
    let anchor = Anchor {
        count: 3,
        head: Head([0x5a; 32]),
    };
    let message = anchor_message(&authority, &blockhash, &anchor).expect("built");

    assert_eq!(message.instructions.len(), 1, "one memo, nothing else");
    assert_eq!(message.account_keys[0], authority, "authority pays");
    assert_eq!(
        message.header.num_required_signatures, 1,
        "only the authority signs"
    );
    assert!(
        message.account_keys.contains(&memo_program()),
        "memo program is present"
    );
    assert_eq!(message.recent_blockhash, blockhash);

    let data = &message.instructions[0].data;
    assert_eq!(
        String::from_utf8(data.clone()).expect("memo is utf-8"),
        anchor_memo(&anchor)
    );
}

/// The anchor must be attributable, not merely paid for: the authority signs
/// the memo itself, which is what lets an auditor filter chain history by
/// signer and know the head came from the operator.
#[test]
fn the_authority_co_signs_the_memo_content() {
    let authority = authority();
    let message = anchor_message(
        &authority,
        &Hash::new_from_array([1u8; 32]),
        &Anchor {
            count: 1,
            head: Head([2u8; 32]),
        },
    )
    .expect("built");
    let memo_index = message
        .instructions
        .iter()
        .position(|i| message.account_keys[i.program_id_index as usize] == memo_program())
        .expect("memo instruction");
    let signers: Vec<_> = message.instructions[memo_index]
        .accounts
        .iter()
        .map(|index| message.account_keys[*index as usize])
        .collect();
    assert_eq!(signers, vec![authority]);
}

// ── head encoding ────────────────────────────────────────────────────────────

#[test]
fn heads_round_trip_through_hex_and_json() {
    let head = Head([0x0f; 32]);
    assert_eq!(Head::from_hex(&head.to_hex()), Ok(head));
    assert_eq!(Head::from_hex(&format!("sha256:{head}")), Ok(head));
    let json = serde_json::to_string(&head).expect("serialize");
    assert_eq!(json, format!("\"{}\"", "0f".repeat(32)));
    assert_eq!(
        serde_json::from_str::<Head>(&json).expect("deserialize"),
        head
    );
}

#[test]
fn malformed_heads_are_rejected() {
    assert!(Head::from_hex("").is_err());
    assert!(Head::from_hex("ab").is_err());
    assert!(Head::from_hex(&"zz".repeat(32)).is_err());
    assert!(Head::from_hex(&"ab".repeat(33)).is_err());
    assert!(serde_json::from_str::<Head>("\"nope\"").is_err());
}

// ── properties ───────────────────────────────────────────────────────────────

fn build(authority: &Pubkey, ids: &[[u8; 32]]) -> Vec<Link> {
    let mut head = genesis_head(authority);
    ids.iter()
        .enumerate()
        .map(|(index, id)| {
            let seq = index as u64;
            let decision_id = Head(*id);
            head = next_head(&head, seq, &decision_id);
            Link {
                seq,
                decision_id,
                head,
            }
        })
        .collect()
}

proptest! {
    /// Whatever is appended, in whatever quantity, verifies.
    #[test]
    fn every_appended_chain_verifies(
        ids in proptest::collection::vec(any::<[u8; 32]>(), 0..32)
    ) {
        let authority = authority();
        let links = build(&authority, &ids);
        let head = verify_chain(&authority, &links).expect("verifies");
        prop_assert_eq!(head, links.last().map_or(genesis_head(&authority), |l| l.head));
    }

    /// Flipping a single bit anywhere in any recorded decision is always
    /// caught. This is the property the whole design rests on, asserted over
    /// arbitrary chains rather than the handful above.
    #[test]
    fn any_single_bit_flipped_in_any_decision_is_caught(
        ids in proptest::collection::vec(any::<[u8; 32]>(), 1..24),
        target in 0usize..24,
        byte in 0usize..32,
        bit in 0u8..8,
    ) {
        let authority = authority();
        let mut links = build(&authority, &ids);
        let target = target % links.len();
        links[target].decision_id.0[byte] ^= 1 << bit;
        prop_assert!(
            verify_chain(&authority, &links).is_err(),
            "a flipped bit in entry {} went undetected", target
        );
    }

    /// Appending is order-sensitive: the same decisions in a different order
    /// give a different head, so a log cannot be quietly resorted.
    #[test]
    fn order_changes_the_head(
        ids in proptest::collection::vec(any::<[u8; 32]>(), 2..16)
    ) {
        prop_assume!(ids[0] != ids[ids.len() - 1]);
        let authority = authority();
        let forward = build(&authority, &ids);
        let mut reversed_ids = ids.clone();
        reversed_ids.reverse();
        let reversed = build(&authority, &reversed_ids);
        prop_assert_ne!(
            forward.last().expect("non-empty").head,
            reversed.last().expect("non-empty").head
        );
    }

    /// Every honest anchor over an honest log is consistent, at any prefix.
    #[test]
    fn any_prefix_anchor_is_consistent(
        ids in proptest::collection::vec(any::<[u8; 32]>(), 1..24),
        at in 0usize..24,
    ) {
        let authority = authority();
        let links = build(&authority, &ids);
        let count = (at % (links.len() + 1)) as u64;
        let head = head_after(&authority, &links, count).expect("in range");
        let verdict = check_anchor(&authority, &links, &Anchor { count, head });
        prop_assert!(verdict.is_consistent(), "{verdict}");
    }

    /// Any anchor claiming more entries than the log holds is a truncation,
    /// never anything softer.
    #[test]
    fn an_anchor_beyond_the_log_is_always_a_truncation(
        ids in proptest::collection::vec(any::<[u8; 32]>(), 0..16),
        extra in 1u64..16,
        head in any::<[u8; 32]>(),
    ) {
        let authority = authority();
        let links = build(&authority, &ids);
        let count = links.len() as u64 + extra;
        prop_assert_eq!(
            check_anchor(&authority, &links, &Anchor { count, head: Head(head) }),
            AnchorVerdict::Truncated { anchored: count, held: links.len() as u64 }
        );
    }

    /// Memo encoding survives every value it can carry.
    #[test]
    fn anchor_memos_round_trip_for_any_value(count in any::<u64>(), head in any::<[u8; 32]>()) {
        let anchor = Anchor { count, head: Head(head) };
        prop_assert_eq!(parse_anchor_memo(&anchor_memo(&anchor)), Some(anchor));
    }
}

// ── the verdicts have to say what they mean ─────────────────────────────────
//
// Mutation testing found `is_consistent` could be replaced with `true` and no
// test noticed — which would have made the audit approve every tampered log it
// was shown. These pin the parts that are read by a human or branched on by
// the auditor.

/// The single predicate the whole audit branches on.
#[test]
fn only_a_consistent_verdict_reports_itself_as_consistent() {
    let head = Head([1u8; 32]);
    assert!(AnchorVerdict::Consistent { count: 3, head }.is_consistent());
    assert!(!AnchorVerdict::Truncated {
        anchored: 5,
        held: 3
    }
    .is_consistent());
    assert!(!AnchorVerdict::Forked {
        count: 3,
        anchored: head,
        computed: Head([2u8; 32]),
    }
    .is_consistent());
}

/// The counts in a truncation message are what an operator acts on, so the
/// arithmetic and the grammar both have to be right.
#[test]
fn a_truncation_names_how_many_entries_are_missing() {
    let two = AnchorVerdict::Truncated {
        anchored: 22,
        held: 20,
    }
    .to_string();
    assert!(two.contains("2 published entries are gone"), "{two}");
    assert!(two.contains("covers 22 entries"), "{two}");
    assert!(two.contains("holds 20"), "{two}");

    let one = AnchorVerdict::Truncated {
        anchored: 22,
        held: 21,
    }
    .to_string();
    assert!(one.contains("1 published entry is gone"), "{one}");
}

#[test]
fn a_fork_shows_both_heads() {
    let anchored = Head([0xaa; 32]);
    let computed = Head([0xbb; 32]);
    let message = AnchorVerdict::Forked {
        count: 7,
        anchored,
        computed,
    }
    .to_string();
    assert!(message.contains(&anchored.to_hex()), "{message}");
    assert!(message.contains(&computed.to_hex()), "{message}");
    assert!(message.contains('7'), "{message}");
}

#[test]
fn a_consistent_verdict_reports_what_it_covers() {
    let head = Head([0x11; 32]);
    let message = AnchorVerdict::Consistent { count: 41, head }.to_string();
    assert!(message.contains("41"), "{message}");
    assert!(message.contains(&head.to_hex()), "{message}");
}

/// Chain errors are the whole output of a failed verification. An error that
/// renders to nothing would report tampering as an unexplained failure.
#[test]
fn chain_errors_explain_themselves() {
    let broken = ChainError::SequenceBroken {
        expected: 3,
        found: 4,
    }
    .to_string();
    assert!(broken.contains("expected seq 3"), "{broken}");
    assert!(broken.contains("removed or reordered"), "{broken}");

    let expected = Head([1u8; 32]);
    let found = Head([2u8; 32]);
    let mismatch = ChainError::HeadMismatch {
        seq: 9,
        expected,
        found,
    }
    .to_string();
    assert!(mismatch.contains("seq 9"), "{mismatch}");
    assert!(mismatch.contains(&expected.to_hex()), "{mismatch}");
    assert!(mismatch.contains(&found.to_hex()), "{mismatch}");
}

#[test]
fn the_debug_form_of_a_head_shows_the_head() {
    let head = Head([0x7f; 32]);
    assert_eq!(format!("{head:?}"), format!("Head({})", "7f".repeat(32)));
}
