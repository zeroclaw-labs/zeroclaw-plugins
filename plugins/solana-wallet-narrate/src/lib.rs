
pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use crate::core::narrate::narrate;
    use crate::core::rpc::{get_signatures, get_transaction};
    use crate::core::shape::format_narration;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct SolanaWalletNarrate;

    #[derive(serde::Deserialize)]
    struct Args {
        wallet: String,
        #[serde(default = "default_limit")]
        limit: u8,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn default_limit() -> u8 { 5 }

    impl PluginInfo for SolanaWalletNarrate {
        fn plugin_name() -> String { "solana-wallet-narrate".to_string() }
        fn plugin_version() -> String { env!("CARGO_PKG_VERSION").to_string() }
    }

    impl Tool for SolanaWalletNarrate {
        fn name() -> String { "solana_wallet_narrate".to_string() }

        fn description() -> String {
            "Narrate recent Solana wallet transactions in plain English.              Returns human-readable sentences: SOL transfers, token transfers,              and contract interactions. Args: wallet (base58 address), limit (default 5).".to_string()
        }

        fn parameters_schema() -> String {
            r#"{"type":"object","properties":{"wallet":{"type":"string","description":"Solana wallet address (base58)"},"limit":{"type":"integer","description":"Number of transactions (default 5, max 10)"}},"required":["wallet"]}"#.to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: Args = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid args: {e}")),
                    });
                }
            };

            let rpc_url = parsed.config.get("rpc_url").cloned()
                .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());

            let limit = parsed.limit.min(10);

            let sigs_raw = match get_signatures(&rpc_url, &parsed.wallet, limit) {
                Ok(r) => r,
                Err(e) => return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("RPC error: {e}")),
                }),
            };

            let sentences = narrate(&parsed.wallet, &sigs_raw, |sig| {
                get_transaction(&rpc_url, sig)
            });

            let output = format_narration(&parsed.wallet, &sentences);

            log_record(LogLevel::Info, &PluginEvent {
                function_name: "solana_wallet_narrate::execute".to_string(),
                action: PluginAction::Complete,
                outcome: Some(PluginOutcome::Success),
                duration_ms: None,
                attrs: Some(format!(r#"{{"wallet":"{}","count":{}}}"#, parsed.wallet, sentences.len())),
                message: "narration complete".to_string(),
            });

            Ok(ToolResult { success: true, output, error: None })
        }
    }

    export!(SolanaWalletNarrate);
}
