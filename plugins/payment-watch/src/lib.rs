pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::core::{
        check_payment, derive_ata, ExpectedPayment, ObservedPayment, PaymentWatchArgs, Pubkey,
        RpcClient, WatchError, PARAMETERS_SCHEMA,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde::Deserialize;
    use std::collections::HashMap;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const DEFAULT_RPC_URL: &str = "https://api.devnet.solana.com/";
    struct PaymentWatch;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        recipient: String,
        amount: String,
        decimals: u8,
        mint: String,
        reference: String,
        #[serde(default)]
        token_2022: bool,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl ExecuteArgs {
        fn watch_args(&self) -> PaymentWatchArgs {
            PaymentWatchArgs {
                recipient: self.recipient.clone(),
                amount: self.amount.clone(),
                decimals: self.decimals,
                mint: self.mint.clone(),
                reference: self.reference.clone(),
                token_2022: self.token_2022,
            }
        }
        fn rpc_url(&self) -> String {
            self.config
                .get("rpc_url")
                .filter(|url| !url.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.into())
        }
    }

    impl PluginInfo for PaymentWatch {
        fn plugin_name() -> String {
            "payment-watch".into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }

    impl Tool for PaymentWatch {
        fn name() -> String {
            "payment_watch".into()
        }
        fn description() -> String {
            "Check Solana for an SPL-token payment matching an exact amount and reference. Returns a payment-received event for an SOP or waiting when no match exists. Read-only; never signs or sends.".into()
        }
        fn parameters_schema() -> String {
            PARAMETERS_SCHEMA.into()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            log(PluginAction::Start, None, "checking for referenced payment");
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return failure(format!("invalid arguments: {error}")),
            };
            let rpc = HostRpc::new(parsed.rpc_url());
            let result = match check_payment(&parsed.watch_args(), &rpc) {
                Ok(value) => value,
                Err(error) => return failure(error.to_string()),
            };
            let output = match serde_json::to_string(&result) {
                Ok(value) => value,
                Err(error) => return failure(format!("failed to serialize result: {error}")),
            };
            let (outcome, message) = if result.status == "paid" {
                (PluginOutcome::Success, "observed referenced payment")
            } else {
                (PluginOutcome::Success, "payment not yet observed")
            };
            log(PluginAction::Complete, Some(outcome), message);
            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn failure(message: String) -> Result<ToolResult, String> {
        log(
            PluginAction::Fail,
            Some(PluginOutcome::Failure),
            "payment watch failed",
        );
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        })
    }
    fn log(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "payment_watch::tool::execute".into(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.into(),
            },
        );
    }

    struct HostRpc {
        rpc_url: String,
    }
    impl HostRpc {
        fn new(rpc_url: String) -> Self {
            Self { rpc_url }
        }
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, WatchError> {
            let body =
                serde_json::json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params});
            let response = waki::Client::new()
                .post(&self.rpc_url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .map_err(|error| WatchError::Rpc(format!("HTTP request failed: {error}")))?;
            let value = response
                .json::<serde_json::Value>()
                .map_err(|error| WatchError::Rpc(format!("invalid JSON-RPC response: {error}")))?;
            if let Some(error) = value.get("error") {
                return Err(WatchError::Rpc(format!("RPC returned an error: {error}")));
            }
            Ok(value)
        }
    }
    impl RpcClient for HostRpc {
        fn recent_payments(
            &self,
            expected: &ExpectedPayment,
        ) -> Result<Vec<ObservedPayment>, WatchError> {
            let ata = derive_ata(expected.recipient, expected.mint, expected.token_program)?;
            let signatures = self
                .call(
                    "getSignaturesForAddress",
                    serde_json::json!([ata.to_base58(), {"limit": 20, "commitment":"confirmed"}]),
                )?
                .pointer("/result")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| WatchError::Rpc("missing signature list".into()))?
                .clone();
            let mut payments = Vec::new();
            for entry in signatures {
                if !entry.get("err").is_none_or(serde_json::Value::is_null) {
                    continue;
                }
                let Some(signature) = entry.get("signature").and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let tx = self.call("getTransaction", serde_json::json!([signature, {"encoding":"jsonParsed", "maxSupportedTransactionVersion":0, "commitment":"confirmed"}]))?;
                if let Some(payment) = parse_transaction(&tx, expected, signature) {
                    payments.push(payment);
                }
            }
            Ok(payments)
        }
    }

    fn parse_transaction(
        value: &serde_json::Value,
        expected: &ExpectedPayment,
        signature: &str,
    ) -> Option<ObservedPayment> {
        let keys = value
            .pointer("/result/transaction/message/accountKeys")?
            .as_array()?;
        let key_at = |index: u64| -> Option<&str> {
            keys.get(index as usize)?
                .get("pubkey")?
                .as_str()
                .or_else(|| keys.get(index as usize)?.as_str())
        };
        let reference_present = keys.iter().any(|key| {
            key.get("pubkey")
                .and_then(serde_json::Value::as_str)
                .or_else(|| key.as_str())
                == Some(expected.reference.to_base58().as_str())
        });
        if !reference_present {
            return None;
        }
        let pre = value.pointer("/result/meta/preTokenBalances")?.as_array()?;
        let post = value
            .pointer("/result/meta/postTokenBalances")?
            .as_array()?;
        for balance in post {
            if balance.get("mint").and_then(serde_json::Value::as_str)
                != Some(expected.mint.to_base58().as_str())
                || balance.get("owner").and_then(serde_json::Value::as_str)
                    != Some(expected.recipient.to_base58().as_str())
            {
                continue;
            }
            let index = balance.get("accountIndex")?.as_u64()?;
            let decimals = balance.pointer("/uiTokenAmount/decimals")?.as_u64()? as u8;
            let post_amount = balance
                .pointer("/uiTokenAmount/amount")?
                .as_str()?
                .parse::<u64>()
                .ok()?;
            let pre_amount = pre
                .iter()
                .find(|item| {
                    item.get("accountIndex").and_then(serde_json::Value::as_u64) == Some(index)
                })
                .and_then(|item| item.pointer("/uiTokenAmount/amount"))
                .and_then(serde_json::Value::as_str)
                .and_then(|amount| amount.parse::<u64>().ok())
                .unwrap_or(0);
            let amount_base_units = post_amount.checked_sub(pre_amount)?;
            let sender = pre
                .iter()
                .find_map(|item| {
                    if item.get("mint").and_then(serde_json::Value::as_str)
                        != Some(expected.mint.to_base58().as_str())
                    {
                        return None;
                    }
                    let account_index = item.get("accountIndex")?.as_u64()?;
                    let before = item
                        .pointer("/uiTokenAmount/amount")?
                        .as_str()?
                        .parse::<u64>()
                        .ok()?;
                    let after = post
                        .iter()
                        .find(|candidate| {
                            candidate
                                .get("accountIndex")
                                .and_then(serde_json::Value::as_u64)
                                == Some(account_index)
                        })?
                        .pointer("/uiTokenAmount/amount")?
                        .as_str()?
                        .parse::<u64>()
                        .ok()?;
                    if before > after {
                        item.get("owner")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "unknown".into());
            let recipient = Pubkey::from_base58(balance.get("owner")?.as_str()?).ok()?;
            let mint = Pubkey::from_base58(balance.get("mint")?.as_str()?).ok()?;
            let _ = key_at(index);
            return Some(ObservedPayment {
                signature: signature.into(),
                sender,
                recipient,
                mint,
                amount_base_units,
                decimals,
                reference_present,
            });
        }
        None
    }

    export!(PaymentWatch);
}
