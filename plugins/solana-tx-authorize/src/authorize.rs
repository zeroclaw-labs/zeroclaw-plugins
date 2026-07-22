//! The authorization flow: args → policy → decode → facts → simulate → verdict.
//!
//! Pure logic, zero wasm dependency — the component shim in `lib.rs` calls
//! [`run`] with a real transport; host tests call it with mocks. Every failure
//! path produces a verdict, never a panic: malformed input → DENY, missing
//! evidence → UNKNOWN (fail closed), anything unexpected → DENY.

use safe_hands_core::codec::{base64_decode, base64_encode, shortvec_encode};
use safe_hands_core::decode::decode;
use safe_hands_core::policy::{evaluate, hex_sha256, policy_from_config, Intent, Report, Verdict};
use safe_hands_core::rpc::RpcTransport;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Largest accepted base64 payload (1,232-byte tx + margin).
const MAX_B64_CHARS: usize = 2_048;

#[derive(Debug, Deserialize)]
struct Args {
    transaction_base64: String,
    #[serde(default)]
    intent: Option<Intent>,
    #[serde(default)]
    detail_level: Option<String>,
    /// Free-form context from the agent. Accepted for future policy
    /// conditions but NEVER trusted and never read today — the verdict comes
    /// from bytes and chain state only.
    #[serde(default)]
    #[allow(dead_code)]
    context: Option<String>,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

/// What the shim returns to the host: (success, output, error).
pub struct ExecuteOutput {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

impl ExecuteOutput {
    fn verdict(value: Value) -> Self {
        Self {
            success: true,
            output: value.to_string(),
            error: None,
        }
    }
    fn tool_error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            output: String::new(),
            error: Some(message.into()),
        }
    }
}

/// Run one authorization. `transport` is None only when the caller cannot do
/// RPC at all (unprivileged host, offline tests) — simulation then reports
/// UNKNOWN per the policy's own simulation gate.
pub fn run(args_json: &str, transport: Option<&dyn RpcTransport>) -> ExecuteOutput {
    let args: Args = match serde_json::from_str(args_json) {
        Ok(a) => a,
        Err(e) => return ExecuteOutput::tool_error(format!("invalid arguments: {e}")),
    };

    // 1. Policy: host-injected config only. Empty config = DENY (fail closed).
    let policy = match policy_from_config(&args.config) {
        Ok(p) => p,
        Err(e) => {
            let code = if args.config.contains_key("policy_json") {
                "SH-DENY-CONFIG-061" // present but unparseable (malformed)
            } else {
                "SH-DENY-CONFIG-060" // missing entirely
            };
            return ExecuteOutput::verdict(json!({
                "verdict": "DENY",
                "summary": format!("No valid spend policy is configured — fail closed ({e})."),
                "reason_codes": [code],
                "next_action": "CONFIGURE_POLICY"
            }));
        }
    };
    let policy_sha256 = policy.sha256();

    // 2. Decode the wire transaction. Malformed = DENY.
    let tx_b64 = args.transaction_base64.trim();
    let tx_bytes = match base64_decode(tx_b64, MAX_B64_CHARS) {
        Ok(b) => b,
        Err(e) => {
            return ExecuteOutput::verdict(json!({
                "verdict": "DENY",
                "summary": format!("The transaction payload is not valid base64 within the canonical size bound. ({e})"),
                "reason_codes": ["SH-DENY-INPUT-061"],
                "next_action": "DO_NOT_SIGN"
            }));
        }
    };
    let message_digest = hex_sha256(&tx_bytes);
    let decoded = match decode(&tx_bytes) {
        Ok(d) => d,
        Err(e) => {
            return ExecuteOutput::verdict(json!({
                "verdict": "DENY",
                "summary": format!("The transaction could not be fully decoded; unexplainable input is denied. ({e})"),
                "reason_codes": ["SH-DENY-DECODE-062"],
                "next_action": "DO_NOT_SIGN"
            }));
        }
    };

    let mut facts = decoded.facts.clone();
    facts.intent = args.intent.clone();

    // 3. Simulation: mandatory when policy requires it. Evidence problems =
    //    UNKNOWN, never silent.
    if policy.simulation.required {
        facts.simulation_ok = match simulate(
            transport,
            &decoded,
            &tx_bytes,
            tx_b64,
            policy.simulation.max_slot_age,
        ) {
            SimOutcome::Ok => true,
            SimOutcome::Stale => {
                return ExecuteOutput::verdict(verdict_json(
                    &Report {
                        verdict: Verdict::Unknown,
                        reason_codes: vec!["SH-UNKNOWN-SIM-STALE-052".to_string()],
                        matched_rules: vec!["SIMULATION_FRESHNESS".to_string()],
                    },
                    &decoded_summary(&decoded.facts),
                    &message_digest,
                    &policy_sha256,
                    "RETRY_OR_ALERT_OPERATOR",
                    args.detail_level.as_deref(),
                ));
            }
            SimOutcome::Unavailable => {
                return ExecuteOutput::verdict(verdict_json(
                    &Report {
                        verdict: Verdict::Unknown,
                        reason_codes: vec!["SH-UNKNOWN-RPC-050".to_string()],
                        matched_rules: vec!["SIMULATION_REQUIRED".to_string()],
                    },
                    &decoded_summary(&decoded.facts),
                    &message_digest,
                    &policy_sha256,
                    "RETRY_OR_ALERT_OPERATOR",
                    args.detail_level.as_deref(),
                ));
            }
            SimOutcome::Failed => false,
        };
    }

    // --- 4. Token-2022 mint risk (delegate / hook / fee / default-frozen) --
    // Fetch every involved mint once; classic SPL mints are a single cheap read.
    if let Some(rpc) = transport {
        for tr in &decoded.facts.transfers {
            if let Some(mint) = &tr.mint {
                if let Some(risk) = fetch_mint_risk(rpc, mint) {
                    facts.token2022.permanent_delegate |= risk.permanent_delegate;
                    facts.token2022.transfer_hook |= risk.transfer_hook;
                    facts.token2022.transfer_fee |= risk.transfer_fee;
                    facts.token2022.default_frozen |= risk.default_frozen;
                }
            }
        }
    }

    // --- 5. Evaluate -------------------------------------------------------
    let report = evaluate(&policy, &facts);

    // 5. Shape the verdict (slim by default; full evidence on request).
    let next_action = next_action_for(&report);
    ExecuteOutput::verdict(verdict_json(
        &report,
        &decoded_summary(&decoded.facts),
        &message_digest,
        &policy_sha256,
        next_action,
        args.detail_level.as_deref(),
    ))
}

/// Simulation outcomes, mapped to fail-closed semantics.
enum SimOutcome {
    Ok,
    Stale,
    Failed,
    Unavailable,
}

/// Simulate a canonical unsigned transaction and require fresh, structurally
/// complete RPC evidence. Missing fields never count as successful evidence.
fn simulate(
    transport: Option<&dyn RpcTransport>,
    decoded: &safe_hands_core::decode::DecodedTx,
    tx_bytes: &[u8],
    tx_b64: &str,
    max_slot_age: u64,
) -> SimOutcome {
    let Some(rpc) = transport else {
        return SimOutcome::Unavailable;
    };
    let simulation_tx = if decoded.has_signature_array {
        tx_b64.to_string()
    } else {
        wrap_unsigned_tx(tx_bytes, decoded.required_signatures)
    };
    let params = json!([
        simulation_tx,
        {"encoding": "base64", "sigVerify": false, "replaceRecentBlockhash": true}
    ]);
    let response = match rpc.call("simulateTransaction", params) {
        Ok(response) => response,
        Err(_) => return SimOutcome::Unavailable,
    };
    match response.pointer("/result/value/err") {
        Some(Value::Null) => {}
        Some(_) => return SimOutcome::Failed,
        None => return SimOutcome::Unavailable,
    }
    let Some(simulation_slot) = response
        .pointer("/result/context/slot")
        .and_then(Value::as_u64)
    else {
        return SimOutcome::Unavailable;
    };
    let current_slot = match rpc.call("getSlot", json!([{"commitment": "confirmed"}])) {
        Ok(response) => match response.get("result").and_then(Value::as_u64) {
            Some(slot) => slot,
            None => return SimOutcome::Unavailable,
        },
        Err(_) => return SimOutcome::Unavailable,
    };
    if current_slot < simulation_slot {
        return SimOutcome::Unavailable;
    }
    if current_slot - simulation_slot > max_slot_age {
        return SimOutcome::Stale;
    }
    SimOutcome::Ok
}

/// One-paragraph human narration of the decoded transaction.
fn decoded_summary(facts: &safe_hands_core::policy::TxFacts) -> String {
    let mut parts = Vec::new();
    for tr in &facts.transfers {
        let asset = match &tr.mint {
            None => "SOL".to_string(),
            Some(m) => {
                if m.len() > 8 {
                    format!("{}…", &m[..4])
                } else {
                    m.clone()
                }
            }
        };
        parts.push(format!(
            "sends {} raw {} to {}",
            tr.amount_raw,
            asset,
            short_key(&tr.recipient)
        ));
    }
    let ix_names: Vec<String> = facts
        .instructions
        .iter()
        .map(|i| {
            format!(
                "{}.{}",
                i.program,
                i.name.clone().unwrap_or_else(|| "?".into())
            )
        })
        .collect();
    let mut s = String::new();
    if !parts.is_empty() {
        s.push_str(&parts.join("; "));
        s.push_str(". ");
    }
    if !ix_names.is_empty() {
        s.push_str(&format!("Instructions: {}.", ix_names.join(", ")));
    }
    if s.is_empty() {
        s.push_str("No value movement decoded.");
    }
    s
}

fn short_key(key: &str) -> String {
    if key.len() > 8 {
        format!("{}…{}", &key[..4], &key[key.len() - 4..])
    } else {
        key.to_string()
    }
}

/// Fetch a mint account and parse Token-2022 risk signals. Unavailable RPC or
/// missing account yields None — evaluation continues with the signals that
/// exist (the simulation gate still fail-closes independently).
fn fetch_mint_risk(rpc: &dyn RpcTransport, mint: &str) -> Option<safe_hands_core::tlv::MintRisk> {
    let resp = rpc
        .call("getAccountInfo", json!([mint, {"encoding": "base64"}]))
        .ok()?;
    let owner = resp
        .pointer("/result/value/owner")
        .and_then(Value::as_str)?
        .to_string();
    let data = resp
        .pointer("/result/value/data/0")
        .and_then(Value::as_str)?;
    let bytes = base64_decode(data, 65_536).ok()?;
    Some(safe_hands_core::tlv::parse_mint_risk(&owner, &bytes))
}

/// Verdict → the next tool the agent should call (routing, never a dead end).
fn next_action_for(report: &Report) -> &'static str {
    match report.verdict {
        Verdict::Allow => "SIGN_OR_SQUADS_PROPOSE",
        Verdict::Review => "squads-proposal-build",
        Verdict::Deny => "DO_NOT_SIGN",
        Verdict::Unknown => "RETRY_OR_ALERT_OPERATOR",
    }
}

/// The verdict object. Slim (~150 tokens) unless detail_level=full.
fn verdict_json(
    report: &Report,
    tx_summary: &str,
    message_digest: &str,
    policy_sha256: &str,
    next_action: &str,
    detail_level: Option<&str>,
) -> Value {
    let summary = format!(
        "{} — {}",
        report.verdict.as_str(),
        if tx_summary.is_empty() {
            "no decodable value movement".to_string()
        } else {
            tx_summary.to_string()
        }
    );
    let decision_id = hex_sha256(
        format!(
            "{message_digest}|{policy_sha256}|{}|{:?}",
            report.verdict.as_str(),
            report.reason_codes
        )
        .as_bytes(),
    );
    let mut out = json!({
        "verdict": report.verdict.as_str(),
        "summary": summary,
        "reason_codes": report.reason_codes,
        "next_action": next_action,
        "decision_id": format!("sha256:{decision_id}"),
    });
    if detail_level == Some("full") {
        out["matched_rules"] = json!(report.matched_rules);
        out["message_sha256"] = json!(format!("sha256:{message_digest}"));
        out["policy_sha256"] = json!(format!("sha256:{policy_sha256}"));
    }
    out
}

/// Wrap bare message bytes as an unsigned transaction (zeroed sig slots) —
/// needed by simulateTransaction when callers pass a bare message.
pub fn wrap_unsigned_tx(message_bytes: &[u8], num_signatures: usize) -> String {
    let mut tx = shortvec_encode(num_signatures);
    for _ in 0..num_signatures {
        tx.extend_from_slice(&[0u8; 64]);
    }
    tx.extend_from_slice(message_bytes);
    base64_encode(&tx)
}

#[cfg(test)]
mod tests;
