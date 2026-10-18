//! A ZeroClaw WIT tool plugin: `unsigned_transfer`.
//!
//! Assembles an **unsigned** SOL or SPL-token transfer transaction and returns it
//! as base64 wire bytes for a human's wallet (or a Squads multisig) to sign. It
//! holds no private key and **never signs** — it only prepares a transfer the
//! owner must approve. This is the deepest "the agent handled the money" step
//! that is still zero-custody (T1): the agent constructs a real transaction; the
//! signature stays with the owner.
//!
//! The assembly core lives in [`tx`] (host-testable; uses the modular Solana
//! crates that compile to `wasm32-wasip2`), the RPC substrate in [`rpc`]. Build:
//!   rustup target add wasm32-wasip2 && cargo build --target wasm32-wasip2 --release

pub mod rpc;
pub mod tx;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::json;

    use crate::rpc;
    use crate::tx;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct UnsignedTransfer;

    const PLUGIN_NAME: &str = "unsigned-transfer";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "unsigned_transfer";

    #[derive(serde::Deserialize)]
    struct Args {
        from: String,
        to: String,
        amount: String,
        #[serde(default)]
        spl_token: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for UnsignedTransfer {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for UnsignedTransfer {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Assemble an UNSIGNED SOL or SPL-token transfer transaction for a human's wallet or a \
             Squads multisig to sign. Holds no key and never signs — it returns base64 transaction \
             wire bytes the owner must approve. Use it to prepare a transfer; the owner authorizes it."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "properties": {
                    "from": { "type": "string", "description": "Base58 sender/owner address (the fee payer and signer)." },
                    "to": { "type": "string", "description": "Base58 recipient address." },
                    "amount": { "type": "string", "description": "Amount in SOL, or in the SPL token's UI units if spl_token is set. Non-negative decimal string, e.g. \"1.5\"." },
                    "spl_token": { "type": "string", "description": "SPL token mint address. Omit for a native SOL transfer." }
                },
                "required": ["from", "to", "amount"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let a: Args = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let url = rpc::rpc_url(&a.config);

            // Recent blockhash (required for any transfer).
            let bh_resp = match rpc::call(
                &url,
                "getLatestBlockhash",
                json!([{"commitment": "confirmed"}]),
            ) {
                Ok(v) => v,
                Err(e) => return fail_rpc(e),
            };
            let blockhash = match rpc::result(&bh_resp)
                .ok()
                .and_then(|r| r.pointer("/value/blockhash").and_then(|v| v.as_str()))
            {
                Some(b) => b.to_string(),
                None => return fail_rpc("could not read a recent blockhash".into()),
            };

            let (output, action_msg) = if let Some(mint) = a.spl_token.as_deref() {
                match build_spl(&url, &a, mint, &blockhash) {
                    Ok(v) => (v, "assembled unsigned SPL transfer"),
                    Err(e) => return reject(e),
                }
            } else {
                let lamports = match tx::ui_to_base_units(a.amount.trim(), 9) {
                    Ok(n) => n,
                    Err(e) => return reject(e),
                };
                match tx::build_sol_transfer(&a.from, &a.to, lamports, &blockhash) {
                    Ok(b64) => (
                        json!({
                            "unsigned_transaction_base64": b64,
                            "kind": "sol",
                            "from": a.from, "to": a.to, "amount": a.amount,
                            "recent_blockhash": blockhash,
                            "next_step": "Give this to the owner's wallet or a Squads multisig to sign and submit. This plugin never signs."
                        }),
                        "assembled unsigned SOL transfer",
                    ),
                    Err(e) => return reject(e),
                }
            };

            emit(PluginAction::Complete, PluginOutcome::Success, action_msg);
            Ok(ToolResult {
                success: true,
                output: output.to_string(),
                error: None,
            })
        }
    }

    /// SPL path: fetch mint decimals (verifying it is a mint), derive the
    /// recipient ATA and check whether it exists (creating it if not), then
    /// assemble the unsigned `transfer_checked`.
    fn build_spl(
        url: &str,
        a: &Args,
        mint: &str,
        blockhash: &str,
    ) -> Result<serde_json::Value, String> {
        let acct = rpc::call(
            url,
            "getAccountInfo",
            json!([mint, {"encoding": "jsonParsed"}]),
        )?;
        let value = rpc::result(&acct)?
            .get("value")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if value.is_null() {
            return Err(format!("spl_token mint \"{mint}\" not found"));
        }
        if value.pointer("/data/parsed/type").and_then(|v| v.as_str()) != Some("mint") {
            return Err(format!("\"{mint}\" is not an SPL mint"));
        }
        // Only classic SPL Token is supported: a Token-2022 mint would need the
        // 2022 program id + ATA derivation (transfer hooks/fees change the tx).
        // Fail closed rather than assemble a wrong transaction.
        const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        if value.get("owner").and_then(|v| v.as_str()) != Some(SPL_TOKEN_PROGRAM) {
            return Err(format!(
                "\"{mint}\" is not a classic SPL Token mint (Token-2022 not yet supported)"
            ));
        }
        let decimals = value
            .pointer("/data/parsed/info/decimals")
            .and_then(|v| v.as_u64())
            .ok_or("mint has no decimals")? as u8;

        let amount_base = tx::ui_to_base_units(a.amount.trim(), decimals as u32)?;

        // Does the recipient already have an ATA for this mint?
        let dest_ata = tx::associated_token_account(&a.to, mint)?;
        let dest_ai = rpc::call(
            url,
            "getAccountInfo",
            json!([dest_ata, {"encoding": "base64"}]),
        )?;
        let create_ata = rpc::result(&dest_ai)?
            .get("value")
            .map(|v| v.is_null())
            .unwrap_or(true);

        let b64 = tx::build_spl_transfer(
            &a.from,
            &a.to,
            mint,
            amount_base,
            decimals,
            create_ata,
            blockhash,
        )?;
        Ok(json!({
            "unsigned_transaction_base64": b64,
            "kind": "spl",
            "from": a.from, "to": a.to, "amount": a.amount,
            "spl_token": mint, "decimals": decimals,
            "creates_recipient_ata": create_ata,
            "recent_blockhash": blockhash,
            "next_step": "Give this to the owner's wallet or a Squads multisig to sign and submit. This plugin never signs."
        }))
    }

    fn reject(msg: String) -> Result<ToolResult, String> {
        emit(PluginAction::Reject, PluginOutcome::Failure, "rejected");
        Ok(ToolResult {
            success: false,
            output: msg,
            error: None,
        })
    }

    fn fail_rpc(msg: String) -> Result<ToolResult, String> {
        emit(PluginAction::Fail, PluginOutcome::Failure, "rpc error");
        Ok(ToolResult {
            success: false,
            output: msg,
            error: None,
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "unsigned_transfer::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(UnsignedTransfer);
}
