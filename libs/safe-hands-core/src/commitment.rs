//! What a decision commits to, including the decisions made before the engine
//! could run.
//!
//! Every verdict `solana-tx-authorize` returns carries a `decision_id`:
//!
//! ```text
//! decision_id = sha256( message_digest | policy_digest | verdict | reason_codes )
//! ```
//!
//! For an ordinary decision both digests are obvious: the canonical unsigned
//! transaction, and the canonicalised policy.
//!
//! The interesting cases are the refusals that happen *before* either exists —
//! no policy is configured, the policy does not parse, the payload is not
//! base64, the transaction does not decode. Those used to return a verdict with
//! no `decision_id` at all, which meant they could not be re-derived and could
//! not be entered in the transparency log.
//!
//! That gap mattered more than it looked. A refusal nobody can audit is exactly
//! the refusal an operator would most like to make quietly — *"the policy was
//! broken that day"* is unfalsifiable if the resulting decisions leave no
//! checkable trace. So every terminal verdict now commits to something, and the
//! stand-in digests below are domain-separated so they can never be confused
//! with the real thing.

use crate::policy::hex_sha256;

/// Digest of a payload that never became a canonical transaction.
///
/// The `raw:` prefix guarantees this can never collide with
/// `hex_sha256(canonical_unsigned)`, so a receipt cannot claim an undecodable
/// payload was a real transaction, or the reverse.
pub fn uncanonical_message_digest(payload: &str) -> String {
    hex_sha256(format!("raw:{payload}").as_bytes())
}

/// Digest standing in for a policy that could not be loaded.
///
/// `None` means no policy was configured at all; `Some` means one was
/// configured and did not parse. The two are distinct commitments because they
/// are distinct operator failures, and the reason codes differ.
pub fn unusable_policy_digest(configured: Option<&str>) -> String {
    match configured {
        Some(text) => hex_sha256(format!("unparseable:{text}").as_bytes()),
        None => hex_sha256(b"absent:"),
    }
}

/// The decision id itself.
///
/// Kept in one place so the authorizer and the verifier cannot drift: if this
/// formula ever changes, every receipt fails to re-derive at once and loudly,
/// rather than a subset failing subtly.
pub fn decision_id(
    message_digest: &str,
    policy_digest: &str,
    verdict: &str,
    reason_codes: &[String],
) -> String {
    hex_sha256(format!("{message_digest}|{policy_digest}|{verdict}|{reason_codes:?}").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three digest spaces must not overlap. If they did, a receipt could
    /// present a fail-closed refusal as a decision over real bytes.
    #[test]
    fn the_stand_in_digests_are_domain_separated() {
        let payload = "AQAB";
        assert_ne!(
            uncanonical_message_digest(payload),
            hex_sha256(payload.as_bytes())
        );
        assert_ne!(
            unusable_policy_digest(Some("{}")),
            hex_sha256("{}".as_bytes())
        );
        assert_ne!(
            unusable_policy_digest(None),
            unusable_policy_digest(Some(""))
        );
    }

    /// Domain separation alone is not enough: the digest must actually depend
    /// on the payload. A constant would satisfy every `assert_ne!` above and
    /// make every undecodable input commit to the same thing.
    #[test]
    fn the_message_digest_depends_on_the_payload() {
        let a = uncanonical_message_digest("AQAB");
        let b = uncanonical_message_digest("AQAC");
        assert_ne!(a, b);
        assert_eq!(a.len(), 64, "a sha256 in hex is 64 characters");
        assert_eq!(a, hex_sha256(b"raw:AQAB"), "the domain prefix is `raw:`");
        assert_ne!(uncanonical_message_digest(""), String::new());
    }

    /// Different failures are different commitments.
    #[test]
    fn different_unusable_policies_commit_differently() {
        assert_ne!(
            unusable_policy_digest(Some("{not json")),
            unusable_policy_digest(Some("{also not json"))
        );
    }

    /// The formula is the one every existing receipt was built with. Changing
    /// it silently would invalidate every recorded decision, so it is pinned.
    #[test]
    fn the_decision_id_formula_is_pinned() {
        let codes = vec!["SH-DENY-CONFIG-060".to_string()];
        let expected = hex_sha256(format!("{}|{}|{}|{:?}", "aa", "bb", "DENY", codes).as_bytes());
        assert_eq!(decision_id("aa", "bb", "DENY", &codes), expected);
    }

    /// Reason-code order is part of the commitment: two refusals for different
    /// reasons, or the same reasons in a different order, are different
    /// decisions.
    #[test]
    fn reason_codes_are_part_of_the_commitment() {
        let a = vec!["A".to_string(), "B".to_string()];
        let b = vec!["B".to_string(), "A".to_string()];
        assert_ne!(
            decision_id("m", "p", "DENY", &a),
            decision_id("m", "p", "DENY", &b)
        );
        assert_ne!(
            decision_id("m", "p", "DENY", &a),
            decision_id("m", "p", "REVIEW", &a)
        );
    }
}
