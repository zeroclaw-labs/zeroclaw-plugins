//! ZeroClaw WIT tool plugin: `spl_transfer_build`.
//!
//! Builds an UNSIGNED Solana transfer transaction (native SOL or SPL token)
//! under operator policy: recipient allowlist, per-transfer caps and an
//! optional durable nonce account so the transaction survives a human
//! approval queue. The component holds no keys, cannot sign and cannot
//! broadcast; it returns base64 transaction bytes plus a plain-English digest
//! of exactly what will be signed.
//!
//! All logic lives in [`builder`] with no wasm dependency (host-testable with
//! plain `cargo test`); this file is the thin `#[cfg(target_family = "wasm")]`
//! component shim plus the waki-backed RPC transport.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod builder;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::builder::{run, Lookups};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SplTransferBuild;

    /// waki-backed transport: POSTs JSON-RPC bodies to the operator's rpc_url.
    struct WakiRpc {
        rpc_url: String,
    }

    impl Lookups for WakiRpc {
        fn rpc(&mut self, body: &str) -> Result<String, String> {
            let resp = waki::Client::new()
                .post(&self.rpc_url)
                .header("Content-Type", "application/json")
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("rpc transport: {e}"))?;
            let status = resp.status_code();
            let bytes = resp.body().map_err(|e| format!("rpc body: {e}"))?;
            if status != 200 {
                return Err(format!("rpc http status {status}"));
            }
            String::from_utf8(bytes).map_err(|e| format!("rpc utf8: {e}"))
        }
    }

    fn log(level: LogLevel, action: PluginAction, outcome: Option<PluginOutcome>, message: String) {
        log_record(
            level,
            &PluginEvent {
                function_name: "spl_transfer_build::tool::execute".into(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message,
            },
        );
    }

    impl PluginInfo for SplTransferBuild {
        fn plugin_name() -> String {
            env!("CARGO_PKG_NAME").to_string()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Tool for SplTransferBuild {
        fn name() -> String {
            "spl_transfer_build".to_string()
        }

        fn description() -> String {
            "Build an UNSIGNED Solana transfer transaction (SOL or an SPL token like USDC) \
             for the owner to review and sign. Enforces the operator's recipient allowlist \
             and per-transfer caps; cannot sign or send anything. Use when the user asks to \
             pay, transfer or send tokens to a known recipient. Args: sender and recipient \
             wallet addresses, decimal amount, optional mint (defaults to SOL), optional \
             memo and payment reference."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "sender": { "type": "string", "description": "Base58 wallet address that will sign and pay fees." },
                    "recipient": { "type": "string", "description": "Base58 wallet address receiving the transfer. Must be on the operator's allowlist." },
                    "amount": { "type": "string", "description": "Decimal amount in user units, e.g. \"25\" or \"0.5\". A string, never a number." },
                    "mint": { "type": "string", "description": "Base58 SPL mint address, or \"SOL\" (default) for native SOL." },
                    "memo": { "type": "string", "description": "Optional memo recorded on-chain, e.g. an invoice number. Max 256 bytes." },
                    "reference": { "type": "string", "description": "Optional base58 32-byte Solana Pay reference key for payment discovery." }
                },
                "required": ["sender", "recipient", "amount"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            log(
                LogLevel::Info,
                PluginAction::Start,
                None,
                "building unsigned transfer".into(),
            );
            // The transport needs the operator's rpc_url, which lives inside
            // __config; peel it out without trusting anything else here.
            let rpc_url = serde_json::from_str::<serde_json::Value>(&args)
                .ok()
                .and_then(|v| {
                    v.get("__config")?
                        .get("rpc_url")?
                        .as_str()
                        .map(str::to_string)
                })
                .unwrap_or_default();
            let mut transport = WakiRpc { rpc_url };
            match run(&args, &mut transport) {
                Ok(output) => {
                    log(
                        LogLevel::Info,
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "unsigned transfer built".into(),
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    log(
                        LogLevel::Warn,
                        PluginAction::Fail,
                        Some(PluginOutcome::Failure),
                        format!("refused/failed: {e}"),
                    );
                    // Refusals are a SUCCESSFUL tool outcome (the tool did its
                    // job: it said no and why), surfaced as output so the
                    // model relays the reason instead of retrying blindly.
                    Ok(ToolResult {
                        success: false,
                        output: format!("{e}"),
                        error: Some(format!("{e}")),
                    })
                }
            }
        }
    }

    export!(SplTransferBuild);
}
