pub mod charge;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });
    
    use std::collections::HashMap;
    use crate::charge::execute_charge;
    use solana_plugin_core::Pubkey;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };
    
    struct AutopayCharge;
    
    const PLUGIN_NAME: &str = "autopay-charge";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "autopay-charge";
    
    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        merchant_wallet: String,
        token_mint: String,
        amount: u64,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }
    
    struct WasmHttpRequester;
    
    impl solana_plugin_core::HttpRequester for WasmHttpRequester {
        fn post(&self, url: &str, body: &str) -> Result<String, String> {
            let resp = waki::Client::new()
                .post(url)
                .header("Content-Type", "application/json")
                .body(body.as_bytes())
                .send()
                .map_err(|e| format!("HTTP request failed: {e:?}"))?;
                
            if resp.status_code() != 200 {
                return Err(format!("HTTP status error: {}", resp.status_code()));
            }
            
            let resp_bytes = resp.body()
                .map_err(|e| format!("Failed to read response body: {e:?}"))?;
                
            String::from_utf8(resp_bytes)
                .map_err(|e| format!("Invalid UTF-8 response: {e}"))
        }
    }
    
    impl PluginInfo for AutopayCharge {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }
    
    impl Tool for AutopayCharge {
        fn name() -> String {
            TOOL_NAME.to_string()
        }
        
        fn description() -> String {
            "Autonomously execute a direct debit charge from the user's wallet to a merchant's wallet. \
             Checks the delegated spend allowance and enforces strict daily spend limits in-plugin before signing and sending."
                .to_string()
        }
        
        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "merchant_wallet": {
                        "type": "string",
                        "description": "The base58 public key of the merchant receiving the payment."
                    },
                    "token_mint": {
                        "type": "string",
                        "description": "The base58 public key of the SPL token mint (e.g., USDC)."
                    },
                    "amount": {
                        "type": "integer",
                        "description": "The raw amount of tokens to charge (in smallest units, e.g., 1000000 for 1 USDC)."
                    }
                },
                "required": ["merchant_wallet", "token_mint", "amount"]
            })
            .to_string()
        }
        
        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, &format!("invalid arguments: {e}"));
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };
            
            // Extract and validate configuration values
            let rpc_url = parsed.config.get("rpc_url")
                .map(|s| s.as_str())
                .unwrap_or("https://api.mainnet-beta.solana.com");
                
            let user_wallet_str = match parsed.config.get("user_wallet") {
                Some(w) => w,
                None => return err_result("Missing configuration: 'user_wallet' must be configured in plugin settings"),
            };
            let user_wallet = match Pubkey::from_string(user_wallet_str) {
                Ok(p) => p,
                Err(e) => return err_result(&format!("invalid config user_wallet: {e}")),
            };
            
            let agent_pk_str = match parsed.config.get("agent_private_key") {
                Some(k) => k,
                None => return err_result("Missing configuration: 'agent_private_key' must be configured in plugin settings"),
            };
            let agent_pk_bytes = match bs58::decode(agent_pk_str).into_vec() {
                Ok(v) => v,
                Err(e) => return err_result(&format!("invalid config agent_private_key format (base58 expected): {e}")),
            };
            let mut private_key = [0u8; 32];
            if agent_pk_bytes.len() == 32 {
                private_key.copy_from_slice(&agent_pk_bytes);
            } else if agent_pk_bytes.len() == 64 {
                private_key.copy_from_slice(&agent_pk_bytes[0..32]);
            } else {
                return err_result(&format!("invalid config agent_private_key length (expected 32 or 64 bytes, got {})", agent_pk_bytes.len()));
            }
            
            let daily_cap = match parsed.config.get("daily_cap") {
                Some(c) => match c.parse::<u64>() {
                    Ok(val) => val,
                    Err(e) => return err_result(&format!("invalid config daily_cap: {e}")),
                },
                None => 50_000_000, // Default to 50 USDC daily cap if not configured
            };
            
            let merchant = match Pubkey::from_string(&parsed.merchant_wallet) {
                Ok(p) => p,
                Err(e) => return err_result(&format!("invalid merchant_wallet: {e}")),
            };
            let mint = match Pubkey::from_string(&parsed.token_mint) {
                Ok(p) => p,
                Err(e) => return err_result(&format!("invalid token_mint: {e}")),
            };
            
            let now_timestamp = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(_) => 0i64,
            };
            
            emit(PluginAction::Start, PluginOutcome::Success, "initiating autonomous charge");
            
            let requester = WasmHttpRequester;
            match execute_charge(
                &requester,
                rpc_url,
                &private_key,
                &user_wallet,
                &merchant,
                &mint,
                parsed.amount,
                daily_cap,
                now_timestamp,
            ) {
                Ok(signature) => {
                    emit(PluginAction::Complete, PluginOutcome::Success, "successfully executed charge");
                    
                    let summary = format!(
                        "Charged {amount} successfully using delegated spending power.\n\
                         Transaction ID: {signature}",
                        amount = parsed.amount
                    );
                    
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::json!({
                            "signature": signature,
                            "summary": summary
                        }).to_string(),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, &format!("charge execution failed: {e}"));
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }
    
    fn err_result(msg: &str) -> Result<ToolResult, String> {
        emit(PluginAction::Fail, PluginOutcome::Failure, msg);
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg.to_string()),
        })
    }
    
    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "autopay_charge::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }
    
    export!(AutopayCharge);
}
