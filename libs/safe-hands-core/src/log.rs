//! A tamper-evident log of authorization decisions, anchored to Solana.
//!
//! # Why a log at all
//!
//! `solana-tx-authorize` returns a `decision_id` that commits to the exact
//! transaction bytes, the exact policy, the verdict, and the reason codes, and
//! `conformance --verify` re-derives it. That makes any *single* decision
//! checkable by someone who does not trust us.
//!
//! It says nothing about the decisions you were not shown.
//!
//! An operator whose agent moved money can hand over four clean receipts and
//! keep the fifth. Worse, they can widen the policy, take the money, narrow it
//! back, and hand over receipts that are individually perfect — every one of
//! them re-derives, because each commits only to the policy that produced it.
//! Nothing in a bag of receipts records what was *missing* from the bag.
//!
//! This module closes that gap the way Certificate Transparency does: entries
//! are chained, so the head of the chain commits to the entire history, and the
//! head is periodically written to a public place the operator does not
//! control. Afterwards, any edit to any past entry — a substitution, a
//! reordering, a deletion, a quiet truncation of the tail — changes the head
//! and no longer matches what the chain says.
//!
//! ```text
//! head[0] = H( DOMAIN | 0x00 | authority )
//! head[n] = H( DOMAIN | 0x01 | head[n-1] | seq | decision_id[n] )
//! ```
//!
//! # What is and is not proven
//!
//! The chain does not stop an operator from lying. It makes a specific lie —
//! *"that decision never happened" / "the log always said this"* — impossible
//! to tell consistently once a later head is anchored. That is the property
//! transparency systems actually provide, and it is worth stating precisely
//! rather than overselling.
//!
//! Two design choices carry that weight:
//!
//! **The genesis binds the authority.** `head[0]` is derived from the pubkey
//! that will sign the anchors, so an operator running two agents cannot splice
//! entries from one log into the other, and a log cannot be re-attributed to
//! someone else's anchor after the fact.
//!
//! **The sequence number is inside the hash.** Without it an attacker who
//! obtained two entries could replay one at the other's position. With it,
//! every entry is bound to where it sits.
//!
//! # Why this lives outside the component
//!
//! A `wasm32-wasip2` tool component cannot persist a byte — `tool-plugin`
//! imports `logging` and nothing else. It could not append to a log if we asked
//! it to.
//!
//! That constraint turns out to be the right architecture rather than a
//! limitation to work around. In Certificate Transparency the log is a separate
//! entity from the CA precisely so that the party making decisions is not the
//! party recording them. Here the plugin decides and signs nothing; the
//! operator's host appends; an auditor with the file and the chain can check
//! both without trusting either. Threading a caller-supplied `prev_head`
//! through the component would have put the agent — the untrusted party — in
//! charge of its own audit trail.
//!
//! # Anchoring
//!
//! [`anchor_memo`] renders a head as an SPL Memo payload and
//! [`parse_anchor_memo`] reads it back. Safe Hands never holds a key, so
//! [`anchor_message`] returns an *unsigned* message for the operator to sign
//! the same way they sign everything else.

use crate::crypto::parse_pubkey;
use crate::ix;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use solana_message::Message;
use solana_pubkey::Pubkey;
use std::fmt;
use std::str::FromStr;

/// Domain separator. Present in every hash so a digest from this chain can
/// never be mistaken for — or replayed as — a digest from anything else.
pub const DOMAIN: &[u8] = b"safe-hands/transparency-log/v1";

/// Tag byte for the genesis head.
const TAG_GENESIS: u8 = 0x00;
/// Tag byte for an appended entry.
const TAG_ENTRY: u8 = 0x01;

/// Prefix identifying a Safe Hands anchor memo on chain. Short enough to keep
/// the memo cheap, distinctive enough to search for.
pub const ANCHOR_PREFIX: &str = "sh1";

/// A 32-byte chain head. Serialises as lowercase hex so a log file stays
/// readable and diffable.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Head(pub [u8; 32]);

impl Head {
    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse from lowercase or uppercase hex, with or without a `sha256:`
    /// prefix.
    pub fn from_hex(input: &str) -> Result<Self, String> {
        let input = input.strip_prefix("sha256:").unwrap_or(input).trim();
        if input.len() != 64 {
            return Err(format!("expected 64 hex characters, got {}", input.len()));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&input[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("{input:?} is not hex"))?;
        }
        Ok(Head(out))
    }
}

impl fmt::Display for Head {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Head {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Head({})", self.to_hex())
    }
}

impl FromStr for Head {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Head::from_hex(s)
    }
}

impl Serialize for Head {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Head {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Head::from_hex(&text).map_err(D::Error::custom)
    }
}

/// The head of an empty log, bound to the authority that will anchor it.
///
/// Binding matters: without it, two logs kept by different operators would
/// start from the same value, and entries could be moved between them.
pub fn genesis_head(authority: &Pubkey) -> Head {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update([TAG_GENESIS]);
    hasher.update(authority.as_ref());
    Head(hasher.finalize().into())
}

/// Extend a chain by one decision.
///
/// `seq` is inside the hash so an entry cannot be replayed at a different
/// position, and `decision_id` is the value `solana-tx-authorize` already
/// commits to — bytes, policy, verdict, reason codes.
pub fn next_head(previous: &Head, seq: u64, decision_id: &Head) -> Head {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update([TAG_ENTRY]);
    hasher.update(previous.as_bytes());
    hasher.update(seq.to_be_bytes());
    hasher.update(decision_id.as_bytes());
    Head(hasher.finalize().into())
}

/// One link in the chain, as a verifier sees it.
///
/// This is deliberately not the on-disk format: the file stores the whole
/// receipt and the verifier re-derives `decision_id` from it, so editing any
/// field of a logged decision breaks verification rather than silently
/// producing a log that disagrees with itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub seq: u64,
    pub decision_id: Head,
    pub head: Head,
}

/// Why a chain failed to verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// Sequence numbers must be 0, 1, 2, … with no gaps and no repeats.
    /// A gap is the signature of a deleted entry.
    SequenceBroken { expected: u64, found: u64 },
    /// The stored head is not what the previous head and this decision produce.
    HeadMismatch {
        seq: u64,
        expected: Head,
        found: Head,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::SequenceBroken { expected, found } => write!(
                f,
                "sequence broken at entry {found}: expected seq {expected}. \
                 An entry has been removed or reordered."
            ),
            ChainError::HeadMismatch {
                seq,
                expected,
                found,
            } => write!(
                f,
                "head mismatch at seq {seq}: chain computes {expected}, log claims {found}. \
                 This entry or one before it has been altered."
            ),
        }
    }
}

/// Recompute every head from the genesis and check the log agrees.
///
/// Returns the head of the verified chain — the single value that stands in
/// for the whole history, and the value an anchor commits to.
pub fn verify_chain(authority: &Pubkey, links: &[Link]) -> Result<Head, ChainError> {
    let mut head = genesis_head(authority);
    for (index, link) in links.iter().enumerate() {
        let expected_seq = index as u64;
        if link.seq != expected_seq {
            return Err(ChainError::SequenceBroken {
                expected: expected_seq,
                found: link.seq,
            });
        }
        let computed = next_head(&head, link.seq, &link.decision_id);
        if computed != link.head {
            return Err(ChainError::HeadMismatch {
                seq: link.seq,
                expected: computed,
                found: link.head,
            });
        }
        head = computed;
    }
    Ok(head)
}

/// The head after the first `count` entries, recomputed from the genesis.
///
/// Used to check a historical anchor against a log that has grown since.
pub fn head_after(authority: &Pubkey, links: &[Link], count: u64) -> Option<Head> {
    if count as usize > links.len() {
        return None;
    }
    let mut head = genesis_head(authority);
    for link in links.iter().take(count as usize) {
        head = next_head(&head, link.seq, &link.decision_id);
    }
    Some(head)
}

/// A head published on chain: `count` entries hashing to `head`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// Number of entries covered — the log length at the moment of anchoring.
    pub count: u64,
    pub head: Head,
}

/// Render an anchor as an SPL Memo payload.
///
/// Fixed shape, ~76 bytes, well inside the memo limit, and greppable in a
/// block explorer without any Safe Hands tooling.
pub fn anchor_memo(anchor: &Anchor) -> String {
    format!(
        "{ANCHOR_PREFIX} n={} head={}",
        anchor.count,
        anchor.head.to_hex()
    )
}

/// Read an anchor back out of a memo, ignoring anything that is not ours.
pub fn parse_anchor_memo(memo: &str) -> Option<Anchor> {
    let rest = memo.trim().strip_prefix(ANCHOR_PREFIX)?;
    let mut count: Option<u64> = None;
    let mut head: Option<Head> = None;
    for field in rest.split_whitespace() {
        if let Some(value) = field.strip_prefix("n=") {
            count = value.parse().ok();
        } else if let Some(value) = field.strip_prefix("head=") {
            head = Head::from_hex(value).ok();
        }
    }
    Some(Anchor {
        count: count?,
        head: head?,
    })
}

/// What an on-chain anchor says about a log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// The log reproduces the anchored head exactly. The anchored prefix is
    /// pinned: it cannot be changed now without the change being visible.
    Consistent { count: u64, head: Head },
    /// The anchor covers more entries than the log holds. Entries that were
    /// once published have since gone missing.
    Truncated { anchored: u64, held: u64 },
    /// The log has the right number of entries and the wrong head. Two
    /// different histories were published under one authority.
    Forked {
        count: u64,
        anchored: Head,
        computed: Head,
    },
}

impl AnchorVerdict {
    pub fn is_consistent(&self) -> bool {
        matches!(self, AnchorVerdict::Consistent { .. })
    }
}

impl fmt::Display for AnchorVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnchorVerdict::Consistent { count, head } => write!(
                f,
                "consistent: {count} entries hash to {head}, as published"
            ),
            AnchorVerdict::Truncated { anchored, held } => {
                let missing = anchored - held;
                let (noun, verb) = if missing == 1 {
                    ("entry", "is")
                } else {
                    ("entries", "are")
                };
                write!(
                    f,
                    "TRUNCATED: an anchor covers {anchored} entries, the log holds {held}. \
                     {missing} published {noun} {verb} gone."
                )
            }
            AnchorVerdict::Forked {
                count,
                anchored,
                computed,
            } => write!(
                f,
                "FORKED at {count} entries: chain published {anchored}, this log computes \
                 {computed}. Two histories exist under one authority."
            ),
        }
    }
}

/// Check a log against one anchor read from chain.
pub fn check_anchor(authority: &Pubkey, links: &[Link], anchor: &Anchor) -> AnchorVerdict {
    match head_after(authority, links, anchor.count) {
        None => AnchorVerdict::Truncated {
            anchored: anchor.count,
            held: links.len() as u64,
        },
        Some(computed) if computed == anchor.head => AnchorVerdict::Consistent {
            count: anchor.count,
            head: computed,
        },
        Some(computed) => AnchorVerdict::Forked {
            count: anchor.count,
            anchored: anchor.head,
            computed,
        },
    }
}

/// Build the unsigned transaction that publishes a head.
///
/// A single memo instruction, payer-signed, nothing else — the smallest thing
/// that can carry a commitment. Safe Hands holds no key, so this is handed
/// back for the operator to sign exactly like every other transaction the
/// suite produces.
pub fn anchor_message(
    authority: &Pubkey,
    recent_blockhash: &Hash,
    anchor: &Anchor,
) -> Result<Message, String> {
    let memo_text = anchor_memo(anchor);
    let mut instruction = ix::memo(&memo_text);
    // The memo program treats signer accounts as co-signers of the memo's
    // content. Naming the authority makes the anchor attributable on chain
    // rather than merely present in a transaction it happened to pay for.
    instruction
        .accounts
        .push(solana_instruction::AccountMeta::new_readonly(
            *authority, true,
        ));
    let mut message = Message::new(&[instruction], Some(authority));
    message.recent_blockhash = *recent_blockhash;
    if message.account_keys.first() != Some(authority) {
        return Err("authority must be the fee payer of its own anchor".into());
    }
    Ok(message)
}

/// The memo program id as a `Pubkey`.
pub fn memo_program() -> Pubkey {
    parse_pubkey(ix::MEMO_PROGRAM).expect("constant program id is valid")
}

#[cfg(test)]
mod tests;
