//! A ZeroClaw WIT tool plugin: `spl-transfer-build`.
//!
//! Builds unsigned SPL/SOL transfer transactions (base64) with ATA handling,
//! memo attachment, and a human-readable summary the approval gate can render.
//! A human or the host signs — the plugin never sees a key.
//!
//! CUSTODY TIER: T1 (build-only, zero secrets). RPC usage is read-only:
//! getLatestBlockhash + getTokenAccountsByOwner (ATA existence).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod spl_transfer_build;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use crate::spl_transfer_build::{
        ata_address, b58decode_impl, b58encode, build_transfer, TransferSpec,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "spl-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "spl-transfer-build";
    const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    struct SplTransferBuild;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        from: String,
        to: String,
        amount: f64,
        /// SPL mint; omit or "SOL" for native.
        #[serde(default)]
        mint: Option<String>,
        /// Token decimals (required for SPL; default 9 for SOL).
        #[serde(default)]
        decimals: Option<u8>,
        #[serde(default)]
        memo: Option<String>,
        /// Create destination ATA if it doesn't exist (default true).
        #[serde(default)]
        create_ata_if_missing: Option<bool>,
        #[serde(default)]
        rpc_url: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SplTransferBuild {
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

    fn latest_blockhash(rpc: &str) -> Result<String, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash",
            "params": [{"commitment": "confirmed"}]
        });
        rpc_post(rpc, &body)?
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.get("blockhash"))
            .and_then(|b| b.as_str())
            .map(String::from)
            .ok_or_else(|| "rpc: no blockhash in response".into())
    }

    /// Does `owner`'s ATA for `mint` exist? (getAccountInfo on the derived ATA.)
    fn ata_exists(rpc: &str, owner: &str, mint: &str) -> bool {
        let (Ok(o), Ok(m)) = (b58decode_impl(owner), b58decode_impl(mint)) else {
            return true; // can't check -> assume exists, skip creation
        };
        let ata = b58encode(&ata_address(&o, &m));
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
            "params": [ata, {"encoding": "base64"}]
        });
        rpc_post(rpc, &body)
            .ok()
            .and_then(|r| r.get("result").cloned())
            .and_then(|r| r.get("value").cloned())
            .map(|v| !v.is_null())
            .unwrap_or(true)
    }

    fn fail(msg: &str) -> ToolResult {
        emit(PluginAction::Fail, PluginOutcome::Failure, msg, None);
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg.to_string()),
        }
    }

    impl Tool for SplTransferBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an UNSIGNED SPL or SOL transfer transaction (base64) with ATA handling and \
             memo, plus a human-readable summary for the approval gate. Never signs (T1): a human \
             or the host signs and broadcasts. Use for invoice settlement, payouts, transfers."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Sender address (base58) — will sign outside this plugin."},
                    "to": {"type": "string", "description": "Recipient address (base58)."},
                    "amount": {"type": "number", "description": "Amount in SOL or SPL ui units."},
                    "mint": {"type": "string", "description": "SPL mint. Omit or 'SOL' for native SOL."},
                    "decimals": {"type": "integer", "description": "SPL decimals (e.g. 6 for USDC). Default 9."},
                    "memo": {"type": "string", "description": "On-chain memo for reconciliation."},
                    "create_ata_if_missing": {"type": "boolean", "description": "Create recipient ATA if absent (default true)."}
                },
                "required": ["from", "to", "amount"]
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
            let mint = parsed.mint.filter(|m| m != "SOL" && !m.is_empty());

            let blockhash = match latest_blockhash(&rpc) {
                Ok(b) => b,
                Err(e) => return Ok(fail(&e)),
            };
            let dest_exists = mint.as_deref().map(|m| ata_exists(&rpc, &parsed.to, m));

            let spec = TransferSpec {
                from: parsed.from,
                to: parsed.to,
                amount_ui: parsed.amount,
                decimals: parsed.decimals.unwrap_or(9),
                mint,
                memo: parsed.memo,
                create_ata_if_missing: parsed.create_ata_if_missing.unwrap_or(true),
                dest_ata_exists: dest_exists,
            };
            match build_transfer(&spec, &blockhash) {
                Ok(tx) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "built unsigned tx",
                        None,
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::json!({
                            "unsigned_tx_base64": tx.base64_tx,
                            "summary": tx.summary,
                            "needs_ata_creation": tx.needs_ata_creation,
                            "recent_blockhash": tx.recent_blockhash,
                            "signing": "UNSIGNED — human or host approval gate must sign + broadcast",
                        }).to_string(),
                        error: None,
                    })
                }
                Err(e) => Ok(fail(&e)),
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, _n: Option<usize>) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "spl_transfer_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SplTransferBuild);
}
