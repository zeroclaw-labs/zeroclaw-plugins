//! Independent re-derivation of an authorization decision.
//!
//! `solana-tx-authorize` returns a `decision_id`, which commits to the exact
//! transaction bytes, the exact policy, the verdict, and the reason codes:
//!
//! ```text
//! decision_id = sha256( sha256(message) | sha256(policy) | verdict | reason_codes )
//! ```
//!
//! The verdict is a pure function of four inputs: the transaction bytes, the
//! policy, the caller-declared intent, and whether simulation succeeded. The
//! first two are self-evidencing — you hold them. The last two are attested by
//! the receipt: intent is what the caller claimed it was asking for, and
//! `simulation_ok` is external RPC evidence that cannot be recreated offline.
//! Recording them makes the decision reproducible; omitting them would let a
//! receipt claim a verdict its inputs do not support.
//! That is the point of this command: **a reviewer does not have to trust our
//! ALLOW, and does not have to trust us either.** They re-derive it.
//!
//! It is the individual counterpart to the Kani proofs. Those establish that
//! the engine can never allow what policy forbids, for any input; this
//! establishes that one specific decision really was computed from the bytes
//! and policy it claims.
//!
//! ```sh
//! cargo run --release --manifest-path conformance/Cargo.toml -- \
//!     --verify path/to/receipt.json
//! ```
//!
//! The receipt is what the plugin already emits at `detail_level: "full"`,
//! plus the transaction and policy it was computed over:
//!
//! ```json
//! {
//!   "transaction_base64": "…",
//!   "policy_json": "{…}",
//!   "intent": { "action": "spl_transfer", "amount_raw": "…", "recipient": "…" },
//!   "simulation_ok": true,
//!   "decision": {
//!     "verdict": "ALLOW",
//!     "reason_codes": [],
//!     "decision_id": "sha256:…",
//!     "message_sha256": "sha256:…",
//!     "policy_sha256": "sha256:…"
//!   }
//! }
//! ```

use safe_hands_core::codec::base64_decode;
use safe_hands_core::decode::decode;
use safe_hands_core::policy::{evaluate, Policy};
use serde_json::Value;
use sha2::{Digest, Sha256};

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Strip a leading `sha256:` so receipts read either way.
fn bare<'a>(digest: &'a str) -> &'a str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

impl Check {
    fn new(name: &'static str, ok: bool, detail: impl Into<String>) -> Self {
        Self {
            name,
            ok,
            detail: detail.into(),
        }
    }
}

pub fn verify(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let receipt: Value =
        serde_json::from_str(&text).map_err(|e| format!("{path} is not valid JSON: {e}"))?;

    let field = |key: &str| -> Result<String, String> {
        receipt
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("receipt is missing a string `{key}`"))
    };
    let claimed = |key: &str| -> Result<String, String> {
        receipt
            .pointer(&format!("/decision/{key}"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("receipt is missing `decision.{key}`"))
    };

    let transaction_b64 = field("transaction_base64")?;
    let policy_json = field("policy_json")?;
    let claimed_verdict = claimed("verdict")?;
    let simulation_ok = receipt
        .get("simulation_ok")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let claimed_decision_id = claimed("decision_id")?;

    let claimed_reasons: Vec<String> = receipt
        .pointer("/decision/reason_codes")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // ── 1. The bytes are what the receipt says they are ──────────────────
    let wire = base64_decode(&transaction_b64, 8192)
        .map_err(|e| format!("transaction_base64 does not decode: {e}"))?;
    let mut decoded = decode(&wire).map_err(|e| format!("transaction does not decode: {e}"))?;
    // The authorizer digests the canonical unsigned transaction it was handed,
    // not the inner message — match it exactly or the commitment is meaningless.
    let message_digest = sha256_hex(&wire);

    let mut checks = vec![Check::new(
        "transaction decodes to the claimed message",
        receipt
            .pointer("/decision/message_sha256")
            .and_then(Value::as_str)
            .map(|claimed| bare(claimed) == message_digest)
            .unwrap_or(true),
        format!("sha256:{message_digest}"),
    )];

    // ── 2. The policy is what the receipt says it is ──────────────────────
    let policy = Policy::from_json(&policy_json).map_err(|e| format!("policy is invalid: {e}"))?;
    // Canonical over the parsed policy, so reformatting the file cannot change
    // the digest while changing a rule always does.
    let policy_digest = policy.sha256();
    checks.push(Check::new(
        "policy canonicalises to the claimed digest",
        receipt
            .pointer("/decision/policy_sha256")
            .and_then(Value::as_str)
            .map(|claimed| bare(claimed) == policy_digest)
            .unwrap_or(true),
        format!("sha256:{policy_digest}"),
    ));

    // ── 3. Re-run the engine on those exact inputs ────────────────────────
    decoded.facts.intent = receipt
        .get("intent")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| format!("receipt intent is malformed: {e}"))?;
    decoded.facts.simulation_ok = simulation_ok;
    let report = evaluate(&policy, &decoded.facts);
    let recomputed_verdict = report.verdict.as_str().to_string();

    checks.push(Check::new(
        "re-derived verdict matches the receipt",
        recomputed_verdict == claimed_verdict,
        format!("claimed {claimed_verdict}, re-derived {recomputed_verdict}"),
    ));

    let mut recomputed_reasons = report.reason_codes.clone();
    let mut sorted_claimed = claimed_reasons.clone();
    recomputed_reasons.sort();
    sorted_claimed.sort();
    checks.push(Check::new(
        "re-derived reason codes match the receipt",
        recomputed_reasons == sorted_claimed,
        format!("{:?}", report.reason_codes),
    ));

    // ── 4. The decision id commits to all of it ───────────────────────────
    let recomputed_id = sha256_hex(
        format!(
            "{message_digest}|{policy_digest}|{recomputed_verdict}|{:?}",
            report.reason_codes
        )
        .as_bytes(),
    );
    checks.push(Check::new(
        "decision id re-derives from bytes + policy + verdict",
        bare(&claimed_decision_id) == recomputed_id,
        format!("sha256:{recomputed_id}"),
    ));

    // ── Report ────────────────────────────────────────────────────────────
    println!("\nSafe Hands — independent decision verification");
    println!("{DIM}receipt: {path}{RESET}\n");
    let mut failed = 0;
    for check in &checks {
        if check.ok {
            println!("  {GREEN}PASS{RESET}  {}\n        {DIM}{}{RESET}", check.name, check.detail);
        } else {
            failed += 1;
            println!("  {RED}FAIL{RESET}  {}\n        {DIM}{}{RESET}", check.name, check.detail);
        }
    }

    if failed > 0 {
        return Err(format!(
            "{failed} of {} checks failed — this receipt does not describe the decision the \
             engine actually produces for these inputs",
            checks.len()
        ));
    }

    println!(
        "\n  {GREEN}All {} checks passed.{RESET} The verdict {claimed_verdict} re-derives from \
         the declared inputs: these exact transaction bytes, this exact policy, this intent, \
         and simulation_ok={simulation_ok}.\n",
        checks.len()
    );
    println!(
        "  {DIM}Simulation is external RPC evidence and is attested by the receipt rather than \
         recomputed here. Everything else was recomputed from scratch.{RESET}"
    );
    if claimed_verdict != "ALLOW" {
        println!(
            "  {DIM}Note: this receipt records a refusal. Verifying it proves the refusal was \
             computed, not asserted.{RESET}\n"
        );
    }
    Ok(())
}
