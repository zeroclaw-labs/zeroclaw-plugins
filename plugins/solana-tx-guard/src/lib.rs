//! A ZeroClaw WIT tool plugin: `solana-tx-guard`.
//!
//! The safety layer the whole field skips. Before a wallet signs a Solana
//! transaction, this decodes it and flags the instructions that cost you control
//! or funds (SetAuthority, delegate Approve, CloseAccount, owner Assign, drains),
//! then simulates it LIVE against mainnet (`simulateTransaction`, `sigVerify=false`)
//! to report whether it succeeds and what it actually does. It signs nothing and
//! sends nothing — it is the "should the agent sign this?" check.
//!
//! The decode + verdict core ([`decode`]) is pure Rust, host-tested. Only the
//! simulate call is wasm-only (waki); the dispatch takes the fetcher as a
//! parameter so tests drive the identical path with a mock RPC.

pub mod decode;

pub mod handler {
    use crate::decode::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::{json, Value};

    pub const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

    /// One JSON-RPC call: (rpc_url, method, params) -> result Value or error.
    pub type Fetcher<'a> = dyn Fn(&str, &str, Value) -> Result<Value, String> + 'a;

    fn err(msg: &str) -> String {
        json!({ "ok": false, "error": msg }).to_string()
    }

    /// Run the `guard` op: decode a base64 transaction, classify it, and (best
    /// effort) simulate it live. `ok` is false only for malformed input; a
    /// DANGEROUS verdict is a successful call.
    pub fn run(args: &str, fetch: &Fetcher) -> (String, bool) {
        let v: Value = match serde_json::from_str(args) {
            Ok(v) => v,
            Err(e) => return (err(&format!("invalid JSON args: {e}")), false),
        };
        let op = v.get("op").and_then(|o| o.as_str()).unwrap_or("guard");
        if op != "guard" {
            return (err(&format!("unknown op '{op}' (only 'guard')")), false);
        }
        let tx_b64 = match v.get("transaction").and_then(|t| t.as_str()) {
            Some(t) if !t.is_empty() => t,
            _ => return (err("missing 'transaction' (a base64-encoded Solana transaction)"), false),
        };
        let raw = match STANDARD.decode(tx_b64.trim()) {
            Ok(b) => b,
            Err(e) => return (err(&format!("'transaction' is not valid base64: {e}")), false),
        };
        let decoded = match decode_tx(&raw) {
            Ok(d) => d,
            Err(e) => return (err(&format!("could not decode transaction: {e}")), false),
        };
        let rpc = v.get("rpc_url").and_then(|r| r.as_str()).unwrap_or(DEFAULT_RPC);

        // Writable accounts whose balance a signature could change — cap the list so the
        // RPC payload stays bounded. The fee payer is always first.
        let watch: Vec<String> = decoded.writable_accounts.iter().take(24).cloned().collect();

        // Pre-state: the writable accounts' current lamports, straight from chain.
        let pre = fetch_lamports(fetch, rpc, "getMultipleAccounts", json!([watch, {"encoding": "base64"}]));

        // Live simulation, asking for the post-execution state of the same accounts so we
        // can show the agent the exact balance effect of signing.
        let mut sim = json!(null);
        let mut sim_failed = false;
        let mut balance_changes = json!(null);
        let mut fee_payer_delta: Option<i128> = None;
        let params = json!([
            tx_b64,
            {"sigVerify": false, "replaceRecentBlockhash": true, "encoding": "base64",
             "accounts": {"encoding": "base64", "addresses": watch}}
        ]);
        match fetch(rpc, "simulateTransaction", params) {
            Ok(resp) => {
                let value = resp.get("result").and_then(|r| r.get("value")).or_else(|| resp.get("value"));
                if let Some(value) = value {
                    let err_field = value.get("err").cloned().unwrap_or(Value::Null);
                    sim_failed = !err_field.is_null();
                    sim = json!({
                        "err": err_field,
                        "units_consumed": value.get("unitsConsumed"),
                        "logs": value.get("logs"),
                    });
                    // Post-state lamports come back in `accounts`, in the order we asked.
                    let post = value.get("accounts").and_then(|a| a.as_array()).map(|arr| {
                        arr.iter().map(|a| a.get("lamports").and_then(|l| l.as_u64())).collect::<Vec<_>>()
                    });
                    if let (Some(pre), Some(post)) = (&pre, &post) {
                        let (changes, fp) = diff_balances(&watch, pre, post, &decoded.fee_payer);
                        balance_changes = changes;
                        fee_payer_delta = fp;
                    }
                }
            }
            Err(_) => { /* leave sim null; static verdict carries */ }
        }

        (report_json(tx_b64, rpc, &decoded, sim, sim_failed, balance_changes, fee_payer_delta), true)
    }

    /// Fetch `getMultipleAccounts` and return each account's lamports (None if the
    /// account does not exist), in request order. Returns None on any RPC/shape error so
    /// the guard degrades to a static + simulation verdict rather than fabricating deltas.
    fn fetch_lamports(fetch: &Fetcher, rpc: &str, method: &str, params: Value) -> Option<Vec<Option<u64>>> {
        let resp = fetch(rpc, method, params).ok()?;
        let value = resp.get("result").and_then(|r| r.get("value")).or_else(|| resp.get("value"))?;
        let arr = value.as_array()?;
        Some(arr.iter().map(|a| a.get("lamports").and_then(|l| l.as_u64())).collect())
    }

    /// Per-account lamport delta (post − pre). Flags outflows; returns the fee payer's
    /// net change so the verdict can escalate on a real drain.
    fn diff_balances(
        watch: &[String],
        pre: &[Option<u64>],
        post: &[Option<u64>],
        fee_payer: &str,
    ) -> (Value, Option<i128>) {
        let mut rows = Vec::new();
        let mut fp_delta = None;
        for (i, acct) in watch.iter().enumerate() {
            let before = pre.get(i).copied().flatten();
            let after = post.get(i).copied().flatten();
            let (b, a) = match (before, after) {
                (Some(b), Some(a)) => (b as i128, a as i128),
                // account created (None→Some) or closed (Some→None): still informative.
                (None, Some(a)) => (0, a as i128),
                (Some(b), None) => (b as i128, 0),
                (None, None) => continue,
            };
            let delta = a - b;
            if acct == fee_payer {
                fp_delta = Some(delta);
            }
            if delta != 0 {
                rows.push(json!({
                    "account": acct,
                    "is_fee_payer": acct == fee_payer,
                    "pre_lamports": b as i64,
                    "post_lamports": a as i64,
                    "delta_lamports": delta as i64,
                    "delta_sol": (delta as f64) / 1_000_000_000.0,
                }));
            }
        }
        (json!(rows), fp_delta)
    }

    /// Rank so the verdict can only ever move up (SAFE < REVIEW < DANGEROUS).
    fn rank(band: &str) -> u8 {
        match band { "DANGEROUS" => 2, "REVIEW" => 1, _ => 0 }
    }
    fn raise<'a>(cur: &'a str, to: &'a str) -> &'a str {
        if rank(to) > rank(cur) { to } else { cur }
    }

    #[allow(clippy::too_many_arguments)]
    fn report_json(
        _tx: &str,
        rpc: &str,
        d: &DecodedTx,
        sim: Value,
        sim_failed: bool,
        balance_changes: Value,
        fee_payer_delta: Option<i128>,
    ) -> String {
        let (mut band, score) = static_verdict(d);
        // The simulation refines the verdict: a tx that errors on-chain is at least
        // REVIEW even if the static decode saw nothing dangerous.
        if sim_failed && band == "SAFE" {
            band = "REVIEW";
        }
        // The strongest signal a guard can give: the simulated balance effect on the
        // fee payer. A signature-cost-only change (>= -5000 lamports) is normal; a real
        // net outflow escalates — a large drain is DANGEROUS regardless of static decode.
        let mut drain_note: Option<String> = None;
        if let Some(delta) = fee_payer_delta {
            const FEE_FLOOR: i128 = -5_000;          // ~a few signatures' fees
            const BIG_DRAIN: i128 = -100_000_000;    // 0.1 SOL
            if delta <= BIG_DRAIN {
                band = raise(band, "DANGEROUS");
                drain_note = Some(format!(
                    "Signing this SENDS {:.6} SOL out of your fee-payer account (simulated).",
                    (-delta as f64) / 1e9
                ));
            } else if delta < FEE_FLOOR {
                band = raise(band, "REVIEW");
                drain_note = Some(format!(
                    "Signing this moves {:.6} SOL out of your fee-payer account beyond fees (simulated).",
                    (-delta as f64) / 1e9
                ));
            }
        }
        let band = band.to_string();
        let findings: Vec<Value> = d
            .findings
            .iter()
            .map(|f| {
                json!({
                    "ix_index": f.ix_index,
                    "program": f.program,
                    "program_name": f.program_name,
                    "instruction": f.instruction,
                    "severity": f.severity.as_str(),
                    "detail": f.detail,
                })
            })
            .collect();
        let dangerous: Vec<&str> = d
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .map(|f| f.instruction.as_str())
            .collect();
        let mut summary = if dangerous.is_empty() {
            format!(
                "{} transaction, {} instruction(s): no dangerous instruction detected.",
                d.version, d.num_instructions
            )
        } else {
            format!(
                "{} transaction: {} dangerous instruction(s) — {}.",
                d.version,
                dangerous.len(),
                dangerous.join(", ")
            )
        };
        if let Some(note) = &drain_note {
            summary = format!("{note} {summary}");
        }
        json!({
            "ok": true,
            "op": "guard",
            "rpc": rpc,
            "verdict": band,
            // Standard cross-plugin verdict so an agent gets the same shape from every tool.
            "agent_verdict": match band.as_str() { "DANGEROUS" => "RED", "REVIEW" => "AMBER", _ => "GREEN" },
            "reason": summary.clone(),
            "static_risk_score": score,
            "version": d.version,
            "num_required_signatures": d.num_required_signatures,
            "num_instructions": d.num_instructions,
            "num_accounts": d.account_keys.len(),
            "summary": summary,
            "findings": findings,
            "unknown_programs": d.unknown_programs,
            "simulation": sim,
            "fee_payer": d.fee_payer,
            "balance_changes": balance_changes,
            "fee_payer_net_lamports": fee_payer_delta.map(|x| x as i64),
            "drain_warning": drain_note,
            "notes": d.notes,
            "disclaimer": "Static decode + live simulation of on-chain effect, not financial advice. Signs nothing.",
        })
        .to_string()
    }

    pub const SCHEMA: &str = r#"{
      "type": "object",
      "properties": {
        "op": {"type": "string", "enum": ["guard"], "default": "guard",
               "description": "Decode and simulate a transaction before it is signed."},
        "transaction": {"type": "string", "description": "A base64-encoded Solana transaction (signed or unsigned; simulation uses sigVerify=false)."},
        "rpc_url": {"type": "string", "description": "Optional Solana JSON-RPC endpoint; defaults to mainnet-beta."}
      },
      "required": ["transaction"]
    }"#;
}

// ── the wasm component: same handler, waki-backed simulateTransaction ────────
#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::handler;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde_json::{json, Value};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaTxGuard;

    impl PluginInfo for SolanaTxGuard {
        fn plugin_name() -> String { "solana-tx-guard".to_string() }
        fn plugin_version() -> String { env!("CARGO_PKG_VERSION").to_string() }
    }

    fn rpc_fetch(url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        let resp = waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(bytes)
            .send()
            .map_err(|e| format!("wasi:http send failed: {e}"))?;
        let raw = resp.body().map_err(|e| format!("read response body: {e}"))?;
        let v: Value = serde_json::from_slice(&raw).map_err(|e| format!("RPC returned non-JSON: {e}"))?;
        Ok(v)
    }

    impl Tool for SolanaTxGuard {
        fn name() -> String { "solana_tx_guard".to_string() }

        fn description() -> String {
            "Decode a Solana transaction an agent is about to sign and judge whether it is safe. \
             Statically flags dangerous instructions (authority changes, delegate approvals, \
             account closes, owner reassignments) AND simulates the transaction live against \
             mainnet to compute the real balance effect — it reports exactly how many lamports \
             the fee payer would lose, escalating to DANGEROUS on a genuine drain even when the \
             static decode looks benign. Signs nothing. Pass {\"transaction\":\"<base64>\"} \
             (optionally \"rpc_url\")."
                .to_string()
        }

        fn parameters_schema() -> String { handler::SCHEMA.to_string() }

        fn execute(args: String) -> Result<ToolResult, String> {
            let (output, ok) = handler::run(&args, &rpc_fetch);
            log_record(
                LogLevel::Info,
                &PluginEvent {
                    function_name: "solana_tx_guard::tool::execute".to_string(),
                    action: if ok { PluginAction::Complete } else { PluginAction::Fail },
                    outcome: Some(if ok { PluginOutcome::Success } else { PluginOutcome::Failure }),
                    duration_ms: None,
                    attrs: None,
                    message: "solana-tx-guard".to_string(),
                },
            );
            Ok(ToolResult { success: ok, output, error: None })
        }
    }

    export!(SolanaTxGuard);
}
