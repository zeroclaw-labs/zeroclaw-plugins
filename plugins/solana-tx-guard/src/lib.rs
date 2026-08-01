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

        // Live simulation (best-effort — a static verdict still stands without it).
        let mut sim = json!(null);
        let mut sim_failed = false;
        let params = json!([
            tx_b64,
            {"sigVerify": false, "replaceRecentBlockhash": true, "encoding": "base64"}
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
                }
            }
            Err(_) => { /* leave sim null; static verdict carries */ }
        }

        (report_json(tx_b64, rpc, &decoded, sim, sim_failed), true)
    }

    fn report_json(
        _tx: &str,
        rpc: &str,
        d: &DecodedTx,
        sim: Value,
        sim_failed: bool,
    ) -> String {
        let (mut band, score) = static_verdict(d);
        // The simulation refines the verdict: a tx that errors on-chain is at least
        // REVIEW even if the static decode saw nothing dangerous.
        if sim_failed && band == "SAFE" {
            band = "REVIEW";
        }
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
        let summary = if dangerous.is_empty() {
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
        json!({
            "ok": true,
            "op": "guard",
            "rpc": rpc,
            "verdict": band,
            "static_risk_score": score,
            "version": d.version,
            "num_required_signatures": d.num_required_signatures,
            "num_instructions": d.num_instructions,
            "num_accounts": d.account_keys.len(),
            "summary": summary,
            "findings": findings,
            "unknown_programs": d.unknown_programs,
            "simulation": sim,
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
             account closes, owner reassignments, wallet drains) and simulates the transaction \
             live against mainnet to report whether it succeeds and what it actually does. \
             Signs nothing. Pass {\"transaction\":\"<base64>\"} (optionally \"rpc_url\")."
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
