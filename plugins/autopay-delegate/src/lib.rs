pub mod delegate;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });
    
    use crate::delegate::build_delegate_transaction;
    use solana_plugin_core::Pubkey;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };
    
    struct AutopayDelegate;
    
    const PLUGIN_NAME: &str = "autopay-delegate";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "autopay-delegate";
    
    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        owner_wallet: String,
        delegate_wallet: String,
        token_mint: String,
        amount: u64,
        recent_blockhash: String,
    }
    
    impl PluginInfo for AutopayDelegate {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }
    
    impl Tool for AutopayDelegate {
        fn name() -> String {
            TOOL_NAME.to_string()
        }
        
        fn description() -> String {
            "Generate an unsigned Solana transaction that delegates SPL token spending power (allowance) from the user's wallet to the agent. \
             This is the first step for direct debit/autopay setup, allowing the agent to pay autonomously up to the approved amount. \
             The output base64 transaction must be signed and submitted by the owner's wallet."
                .to_string()
        }
        
        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "owner_wallet": {
                        "type": "string",
                        "description": "The base58 public key of the owner's wallet (the delegator)."
                    },
                    "delegate_wallet": {
                        "type": "string",
                        "description": "The base58 public key of the agent's wallet (the delegate)."
                    },
                    "token_mint": {
                        "type": "string",
                        "description": "The base58 public key of the SPL token mint (e.g., USDC)."
                    },
                    "amount": {
                        "type": "integer",
                        "description": "The raw amount of tokens to delegate (in smallest units, e.g., 50000000 for 50 USDC)."
                    },
                    "recent_blockhash": {
                        "type": "string",
                        "description": "Recent blockhash for transaction construction."
                    }
                },
                "required": ["owner_wallet", "delegate_wallet", "token_mint", "amount", "recent_blockhash"]
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
            
            let owner = match Pubkey::from_string(&parsed.owner_wallet) {
                Ok(p) => p,
                Err(e) => return err_result(&format!("invalid owner_wallet: {e}")),
            };
            let delegate = match Pubkey::from_string(&parsed.delegate_wallet) {
                Ok(p) => p,
                Err(e) => return err_result(&format!("invalid delegate_wallet: {e}")),
            };
            let mint = match Pubkey::from_string(&parsed.token_mint) {
                Ok(p) => p,
                Err(e) => return err_result(&format!("invalid token_mint: {e}")),
            };
            
            let mut recent_blockhash_bytes = [0u8; 32];
            let decoded_hash = match bs58::decode(&parsed.recent_blockhash).into_vec() {
                Ok(v) => v,
                Err(e) => return err_result(&format!("invalid recent_blockhash: {e}")),
            };
            if decoded_hash.len() != 32 {
                return err_result("invalid recent_blockhash length (must be 32 bytes)");
            }
            recent_blockhash_bytes.copy_from_slice(&decoded_hash);
            
            emit(PluginAction::Start, PluginOutcome::Success, "building delegate transaction");
            
            match build_delegate_transaction(&owner, &delegate, &mint, parsed.amount, recent_blockhash_bytes) {
                Ok(tx_b64) => {
                    emit(PluginAction::Complete, PluginOutcome::Success, "successfully built delegate transaction");
                    
                    let user_readable = format!(
                        "Unsigned approve transaction generated successfully.\n\n\
                         Please sign and submit this transaction to delegate {amount_formatted} spend allowance of token mint {token_mint_formatted} to the agent's key ({agent_key_formatted}).\n\n\
                         Payload (Base64):\n{tx_b64}",
                        amount_formatted = parsed.amount,
                        token_mint_formatted = parsed.token_mint,
                        agent_key_formatted = parsed.delegate_wallet
                    );
                    
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::json!({
                            "transaction": tx_b64,
                            "summary": user_readable
                        }).to_string(),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, &format!("failed to build delegate transaction: {e}"));
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
                function_name: "autopay_delegate::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }
    
    export!(AutopayDelegate);
}
