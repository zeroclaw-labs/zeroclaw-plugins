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

use safe_hands_core::codec::{base64_decode, unsigned_transaction_bytes};
use safe_hands_core::commitment;
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
fn bare(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

pub struct Check {
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

/// Everything re-derivation establishes about one receipt.
///
/// Separated from the printing so the transparency log can chain over the
/// re-derived `decision_id` rather than the one the receipt claims. A log that
/// chained the claimed value would happily record a decision that never
/// happened.
pub struct Rederived {
    pub decision_id: String,
    pub verdict: String,
    pub reason_codes: Vec<String>,
    pub checks: Vec<Check>,
}

impl Rederived {
    /// Every check passed: the receipt describes the decision the engine
    /// actually produces for its declared inputs.
    pub fn is_sound(&self) -> bool {
        self.checks.iter().all(|check| check.ok)
    }

    /// The checks that failed, ready to print.
    pub fn failures(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|check| !check.ok)
    }
}

impl Check {
    /// Rendered as one line, for callers that report many receipts at once.
    pub fn line(&self) -> String {
        format!("{}: {}", self.name, self.detail)
    }
}

/// The reason code implied by evidence that stopped the decision early.
///
/// `None` means the evidence let the engine run, whether or not simulation
/// succeeded. The plugin writes this at `detail_level: "full"`; a receipt that
/// predates the field, or that records only `simulation_ok`, still verifies —
/// it simply cannot distinguish the three UNKNOWN shapes, and says so by
/// returning `None` and letting the engine re-run.
fn evidence_reason_code(receipt: &Value) -> Option<&'static str> {
    let evidence = receipt
        .get("evidence")
        .or_else(|| receipt.pointer("/decision/evidence"))
        .and_then(Value::as_str)?;
    match evidence {
        "simulation_unavailable" => Some("SH-UNKNOWN-RPC-050"),
        "simulation_stale" => Some("SH-UNKNOWN-SIM-STALE-052"),
        "mint_evidence_missing" => Some("SH-UNKNOWN-MINT-EVIDENCE-053"),
        _ => None,
    }
}

/// Re-derive a refusal that happened before the engine could run.
///
/// There is nothing to evaluate — the verdict is fixed by which input was
/// unusable — so the checks are that the receipt claims that same refusal, for
/// that same reason, with an id that commits to both.
fn fail_closed(
    receipt: &Value,
    reason_code: &str,
    message_digest: &str,
    policy_digest: &str,
) -> Result<Rederived, String> {
    let reason_codes = vec![reason_code.to_string()];
    let decision_id = commitment::decision_id(message_digest, policy_digest, "DENY", &reason_codes);

    let claimed_verdict = receipt
        .pointer("/decision/verdict")
        .and_then(Value::as_str)
        .unwrap_or("");
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
    let claimed_id = receipt
        .pointer("/decision/decision_id")
        .and_then(Value::as_str)
        .ok_or("receipt is missing `decision.decision_id`")?;

    let checks = vec![
        Check::new(
            "re-derived verdict matches the receipt",
            claimed_verdict == "DENY",
            format!("claimed {claimed_verdict}, re-derived DENY (fail closed before evaluation)"),
        ),
        Check::new(
            "re-derived reason codes match the receipt",
            claimed_reasons == reason_codes,
            format!("{reason_codes:?}"),
        ),
        Check::new(
            "decision id re-derives from bytes + policy + verdict",
            bare(claimed_id) == decision_id,
            format!("sha256:{decision_id}"),
        ),
    ];

    Ok(Rederived {
        decision_id,
        verdict: "DENY".into(),
        reason_codes,
        checks,
    })
}

/// Recompute a decision from the inputs its receipt declares.
///
/// The returned `decision_id` is what the engine produces now, not what the
/// receipt asserts; comparing the two is one of the checks.
pub fn rederive(receipt: &Value) -> Result<Rederived, String> {
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
    // A receipt for a fail-closed refusal legitimately has no policy: `null`
    // means none was configured, a string that will not parse means one was and
    // it was broken. Both are re-derivable; neither is an excuse to give up.
    let policy_json: Option<String> = match receipt.get("policy_json") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(other) => {
            return Err(format!(
                "`policy_json` must be a string or null, got {other}"
            ))
        }
    };
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

    // ── 0. Does the engine ever get to run on these inputs? ──────────────
    //
    // Four failures end a decision before the engine is reached. Re-derivation
    // has to reproduce them exactly, or the refusals produced when an
    // operator's configuration is broken would be the one class of decision
    // nobody could check — and those are the ones an auditor most wants.
    let parsed_policy = policy_json
        .as_deref()
        .and_then(|t| Policy::from_json(t).ok());
    let Some(policy) = parsed_policy else {
        let code = if policy_json.is_some() {
            "SH-DENY-CONFIG-061" // configured and unparseable
        } else {
            "SH-DENY-CONFIG-060" // not configured at all
        };
        return fail_closed(
            receipt,
            code,
            &commitment::uncanonical_message_digest(transaction_b64.trim()),
            &commitment::unusable_policy_digest(policy_json.as_deref()),
        );
    };
    // Canonical over the parsed policy, so reformatting the file cannot change
    // the digest while changing a rule always does.
    let policy_digest = policy.sha256();

    let wire = match base64_decode(&transaction_b64, 8192) {
        Ok(wire) => wire,
        Err(_) => {
            return fail_closed(
                receipt,
                "SH-DENY-INPUT-061",
                &commitment::uncanonical_message_digest(transaction_b64.trim()),
                &policy_digest,
            )
        }
    };
    let mut decoded = match decode(&wire) {
        Ok(decoded) => decoded,
        Err(_) => {
            return fail_closed(
                receipt,
                "SH-DENY-DECODE-062",
                &commitment::uncanonical_message_digest(transaction_b64.trim()),
                &policy_digest,
            )
        }
    };

    // ── 1. The bytes are what the receipt says they are ──────────────────
    //
    // The authorizer digests the *canonical* unsigned transaction, not the
    // bytes it was handed: a bare message and a fully-formed transaction with
    // empty signature slots describe the same instructions and must produce the
    // same decision id. Re-deriving from the raw input instead would make every
    // non-canonical submission unverifiable.
    let canonical =
        unsigned_transaction_bytes(&decoded.serialized_message, decoded.required_signatures)
            .map_err(|e| format!("transaction does not canonicalise: {e}"))?;
    let message_digest = sha256_hex(&canonical);

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
    checks.push(Check::new(
        "policy canonicalises to the claimed digest",
        receipt
            .pointer("/decision/policy_sha256")
            .and_then(Value::as_str)
            .map(|claimed| bare(claimed) == policy_digest)
            .unwrap_or(true),
        format!("sha256:{policy_digest}"),
    ));

    // ── 3. Evidence that ends the decision before the engine runs ──────
    //
    // Three outcomes are not "simulation said no": the node did not answer, the
    // answer was too old, or a mint could not be evidenced. Each produces its
    // own reason code, so a receipt that recorded only a boolean could not
    // re-derive any of them.
    if let Some(code) = evidence_reason_code(receipt) {
        let reason_codes = vec![code.to_string()];
        let decision_id =
            commitment::decision_id(&message_digest, &policy_digest, "UNKNOWN", &reason_codes);
        checks.push(Check::new(
            "re-derived verdict matches the receipt",
            claimed_verdict == "UNKNOWN",
            format!("claimed {claimed_verdict}, re-derived UNKNOWN from the recorded evidence"),
        ));
        checks.push(Check::new(
            "re-derived reason codes match the receipt",
            claimed_reasons == reason_codes,
            format!("{reason_codes:?}"),
        ));
        checks.push(Check::new(
            "decision id re-derives from bytes + policy + verdict",
            bare(&claimed_decision_id) == decision_id,
            format!("sha256:{decision_id}"),
        ));
        return Ok(Rederived {
            decision_id,
            verdict: "UNKNOWN".into(),
            reason_codes,
            checks,
        });
    }

    // ── 4. Re-run the engine on those exact inputs ────────────────────
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

    // ── 5. The decision id commits to all of it ───────────────────────
    let recomputed_id = commitment::decision_id(
        &message_digest,
        &policy_digest,
        &recomputed_verdict,
        &report.reason_codes,
    );
    checks.push(Check::new(
        "decision id re-derives from bytes + policy + verdict",
        bare(&claimed_decision_id) == recomputed_id,
        format!("sha256:{recomputed_id}"),
    ));

    Ok(Rederived {
        decision_id: recomputed_id,
        verdict: recomputed_verdict,
        reason_codes: report.reason_codes,
        checks,
    })
}

pub fn verify(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let receipt: Value =
        serde_json::from_str(&text).map_err(|e| format!("{path} is not valid JSON: {e}"))?;

    let claimed_verdict = receipt
        .pointer("/decision/verdict")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let simulation_ok = receipt
        .get("simulation_ok")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let rederived = rederive(&receipt)?;
    let checks = &rederived.checks;

    // ── Report ────────────────────────────────────────────────────────────
    println!("\nSafe Hands — independent decision verification");
    println!("{DIM}receipt: {path}{RESET}\n");
    let mut failed = 0;
    for check in checks {
        if check.ok {
            println!(
                "  {GREEN}PASS{RESET}  {}\n        {DIM}{}{RESET}",
                check.name, check.detail
            );
        } else {
            failed += 1;
            println!(
                "  {RED}FAIL{RESET}  {}\n        {DIM}{}{RESET}",
                check.name, check.detail
            );
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
