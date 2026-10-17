//! A ZeroClaw WIT tool plugin: `payment-watch`.
//!
//! Watches a Solana address for an expected payment — amount, optional SPL
//! mint, optional reference/memo ("Invoice #412") — and reports the matching
//! signature when it lands. This is the component that closes the loop on
//! Solana Pay / invoice flows: "charge table 4 for 25 USDC" → this tool
//! confirms "Invoice #412 paid <- 25 USDC from 7xK…".
//!
//! CUSTODY TIER: T0 (read-only RPC). The plugin never builds, signs, or
//! submits a transaction and holds no key material. The only possible secret
//! is an RPC API key embedded in the configured endpoint URL.
//!
//! The pure matching core lives in [`payment_watch`] with no wasm dependency,
//! so it compiles and tests on the host with `cargo test`; this file is the
//! I/O shim (wasi:http via `waki`).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod payment_watch;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use crate::payment_watch::{
        match_transaction, signatures_from_response, signatures_request, transaction_request,
        PaymentHit, WatchSpec,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "payment-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "payment-watch";
    const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    struct PaymentWatch;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        /// Address to watch (receiving account, base58).
        address: String,
        /// Expected amount in token units (SOL or SPL ui amount).
        expected_amount: f64,
        /// SPL mint address; omit or "SOL" for native SOL.
        #[serde(default)]
        mint: Option<String>,
        /// Optional memo/reference substring that must appear in the tx.
        #[serde(default)]
        reference: Option<String>,
        /// Only consider transactions at least this recent (unix seconds).
        #[serde(default)]
        since_unix: Option<u64>,
        /// Relative amount tolerance (default 0.005 = 0.5%).
        #[serde(default)]
        tolerance: Option<f64>,
        /// Max recent signatures to scan (default 25, max 50).
        #[serde(default)]
        scan_limit: Option<u32>,
        /// RPC endpoint override; config `rpc_url` wins over this.
        #[serde(default)]
        rpc_url: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for PaymentWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    fn rpc_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .connect_timeout(CONNECT_TIMEOUT)
            .json(body)
            .send()
            .map_err(|e| format!("rpc POST failed: {e}"))?
            .json::<serde_json::Value>()
            .map_err(|e| format!("rpc: bad JSON response: {e}"))
    }

    fn fail(msg: &str) -> ToolResult {
        emit(PluginAction::Fail, PluginOutcome::Failure, msg, None);
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg.to_string()),
        }
    }

    impl Tool for PaymentWatch {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Watch a Solana address for an expected payment (amount + optional mint + optional \
             reference/memo) and report the matching transaction when it has landed. Read-only \
             (T0): no keys, no signing. Use after creating a Solana Pay / invoice request to \
             confirm payment: 'Invoice #412 paid <- 25 USDC'."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Receiving address to watch (base58)."},
                    "expected_amount": {"type": "number", "description": "Expected amount in SOL or SPL ui units."},
                    "mint": {"type": "string", "description": "SPL mint address. Omit or 'SOL' for native SOL."},
                    "reference": {"type": "string", "description": "Memo/reference substring that must appear (e.g. 'Invoice #412')."},
                    "since_unix": {"type": "integer", "description": "Ignore transactions older than this unix timestamp."},
                    "tolerance": {"type": "number", "description": "Relative amount tolerance (default 0.005)."},
                    "scan_limit": {"type": "integer", "description": "Recent signatures to scan (default 25, max 50)."}
                },
                "required": ["address", "expected_amount"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(fail(&format!("invalid arguments: {e}"))),
            };

            let rpc = parsed
                .config
                .get("rpc_url")
                .cloned()
                .or(parsed.rpc_url)
                .unwrap_or_else(|| DEFAULT_RPC.to_string());

            let spec = WatchSpec {
                address: parsed.address.clone(),
                expected_amount: parsed.expected_amount,
                mint: parsed.mint.clone(),
                reference: parsed.reference.clone(),
                since_unix: parsed.since_unix.unwrap_or(0),
                tolerance: parsed.tolerance.unwrap_or(0.005),
            };
            let limit = parsed.scan_limit.unwrap_or(25).min(50);

            // 1. recent signatures for the watched address
            let sig_resp = match rpc_post(&rpc, &signatures_request(&spec.address, limit)) {
                Ok(r) => r,
                Err(e) => return Ok(fail(&e)),
            };
            let sigs = signatures_from_response(&sig_resp);

            // 2. fetch + match each transaction until one satisfies the spec
            let mut checked = 0usize;
            for sig in &sigs {
                checked += 1;
                let tx_resp = match rpc_post(&rpc, &transaction_request(sig)) {
                    Ok(r) => r,
                    Err(_) => continue, // transient RPC error — keep scanning
                };
                let tx = match tx_resp.get("result") {
                    Some(t) if !t.is_null() => t.clone(),
                    _ => continue,
                };
                if let Some(hit) = match_transaction(&tx, &spec) {
                    return Ok(found(hit, checked));
                }
            }

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                &format!("no matching payment yet ({checked} recent txs checked)"),
                None,
            );
            Ok(ToolResult {
                success: true,
                output: serde_json::json!({
                    "found": false,
                    "checked": checked,
                    "watching": {
                        "address": spec.address,
                        "expected_amount": spec.expected_amount,
                        "mint": spec.mint.unwrap_or_else(|| "SOL".into()),
                        "reference": spec.reference,
                    }
                })
                .to_string(),
                error: None,
            })
        }
    }

    fn found(hit: PaymentHit, checked: usize) -> ToolResult {
        let kind = if hit.is_spl { "SPL" } else { "SOL" };
        emit(
            PluginAction::Complete,
            PluginOutcome::Success,
            &format!("payment found: {} ({})", hit.signature, kind),
            Some(hit.amount),
        );
        ToolResult {
            success: true,
            output: serde_json::json!({
                "found": true,
                "signature": hit.signature,
                "amount": hit.amount,
                "kind": kind,
                "memo": hit.memo,
                "block_time": hit.block_time,
                "checked": checked,
            })
            .to_string(),
            error: None,
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, amount: Option<f64>) {
        let attrs = amount.map(|a| format!("{{\"amount\":{a}}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "payment_watch::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(PaymentWatch);
}
