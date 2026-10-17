//! ZeroClaw tool plugin: `jupiter_swap_build_safe`.
//!
//! The guarded workflow lives in `solsafe-core`; this is the WIT shim plus
//! wasm-only HTTP adapters for Jupiter and Solana RPC.

pub fn parameters_schema_json() -> String {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "user_public_key": {"type": "string"},
            "input_mint": {"type": "string"},
            "output_mint": {"type": "string"},
            "amount": {"type": "string"},
            "amount_type": {"type": "string", "enum": ["raw", "ui"]},
            "slippage_bps": {"type": "integer", "minimum": 0, "maximum": 10000},
            "memo": {"type": "string", "maxLength": 180},
            "only_direct_routes": {"type": "boolean"}
        },
        "required": ["user_public_key", "input_mint", "output_mint", "amount", "amount_type", "slippage_bps"]
    })
    .to_string()
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use serde_json::{json, Value};
    use solsafe_core::{
        jupiter_build_json, redact_url, JupiterClient, QuoteRequest, QuoteResponse, RpcClient,
        SolSafeError, SwapRequest, SwapResponse,
    };

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "jupiter-swap-build-safe";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "jupiter_swap_build_safe";

    struct HttpRpc {
        url: String,
    }

    impl RpcClient for HttpRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, SolSafeError> {
            if !self.url.starts_with("https://") {
                return Err(SolSafeError::Rpc("RPC URL must use HTTPS".to_string()));
            }
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
            let resp = waki::Client::new()
                .post(&self.url)
                .json(&body)
                .send()
                .map_err(|_| {
                    SolSafeError::Rpc(format!(
                        "RPC transport failed for {}",
                        redact_url(&self.url)
                    ))
                })?;
            let value = resp
                .json::<Value>()
                .map_err(|_| SolSafeError::Rpc("RPC response was malformed JSON".to_string()))?;
            if let Some(err) = value.get("error") {
                let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
                return Err(SolSafeError::Rpc(format!("JSON-RPC error code {code}")));
            }
            Ok(value.get("result").cloned().unwrap_or(value))
        }
    }

    struct HttpJupiter {
        quote_url: String,
        swap_url: String,
    }

    impl JupiterClient for HttpJupiter {
        fn get_quote(&self, request: QuoteRequest) -> Result<QuoteResponse, SolSafeError> {
            if !self.quote_url.starts_with("https://") {
                return Err(SolSafeError::Jupiter(
                    "Jupiter quote URL must use HTTPS".to_string(),
                ));
            }
            let url = format!(
                "{}?inputMint={}&outputMint={}&amount={}&slippageBps={}&onlyDirectRoutes={}",
                self.quote_url,
                request.input_mint,
                request.output_mint,
                request.amount,
                request.slippage_bps,
                request.only_direct_routes
            );
            let resp = waki::Client::new().get(&url).send().map_err(|_| {
                SolSafeError::Jupiter(format!(
                    "Jupiter quote failed for {}",
                    redact_url(&self.quote_url)
                ))
            })?;
            let raw = resp.json::<Value>().map_err(|_| {
                SolSafeError::Jupiter("Jupiter quote response was malformed JSON".to_string())
            })?;
            quote_from_value(raw)
        }

        fn build_swap(&self, request: SwapRequest) -> Result<SwapResponse, SolSafeError> {
            if !self.swap_url.starts_with("https://") {
                return Err(SolSafeError::Jupiter(
                    "Jupiter swap URL must use HTTPS".to_string(),
                ));
            }
            let body = json!({
                "userPublicKey": request.user_public_key,
                "quoteResponse": request.quote.raw,
                "wrapAndUnwrapSol": true,
                "dynamicComputeUnitLimit": true,
                "asLegacyTransaction": false
            });
            let resp = waki::Client::new()
                .post(&self.swap_url)
                .json(&body)
                .send()
                .map_err(|_| {
                    SolSafeError::Jupiter(format!(
                        "Jupiter swap failed for {}",
                        redact_url(&self.swap_url)
                    ))
                })?;
            let v = resp.json::<Value>().map_err(|_| {
                SolSafeError::Jupiter("Jupiter swap response was malformed JSON".to_string())
            })?;
            let tx = v
                .get("swapTransaction")
                .and_then(Value::as_str)
                .ok_or_else(|| SolSafeError::Jupiter("swap transaction missing".to_string()))?;
            Ok(SwapResponse {
                swap_transaction: tx.to_string(),
            })
        }
    }

    fn quote_from_value(raw: Value) -> Result<QuoteResponse, SolSafeError> {
        let route_plan = raw
            .get("routePlan")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("swapInfo"))
                    .map(|swap| solsafe_core::RouteLeg {
                        input_mint: swap
                            .get("inputMint")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        output_mint: swap
                            .get("outputMint")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        amm_key: swap
                            .get("ammKey")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        label: swap
                            .get("label")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(QuoteResponse {
            input_mint: raw
                .get("inputMint")
                .and_then(Value::as_str)
                .ok_or_else(|| SolSafeError::Jupiter("quote input mint missing".to_string()))?
                .to_string(),
            output_mint: raw
                .get("outputMint")
                .and_then(Value::as_str)
                .ok_or_else(|| SolSafeError::Jupiter("quote output mint missing".to_string()))?
                .to_string(),
            in_amount: raw
                .get("inAmount")
                .and_then(Value::as_str)
                .ok_or_else(|| SolSafeError::Jupiter("quote input amount missing".to_string()))?
                .to_string(),
            out_amount: raw
                .get("outAmount")
                .and_then(Value::as_str)
                .ok_or_else(|| SolSafeError::Jupiter("quote output amount missing".to_string()))?
                .to_string(),
            other_amount_threshold: raw
                .get("otherAmountThreshold")
                .and_then(Value::as_str)
                .ok_or_else(|| SolSafeError::Jupiter("quote threshold missing".to_string()))?
                .to_string(),
            price_impact_pct: raw
                .get("priceImpactPct")
                .and_then(Value::as_str)
                .unwrap_or("0")
                .to_string(),
            route_plan,
            raw,
        })
    }

    struct JupiterSwapBuildSafe;

    impl PluginInfo for JupiterSwapBuildSafe {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for JupiterSwapBuildSafe {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build a guarded unsigned Jupiter swap transaction for human approval. Enforces configured mint, amount, route, slippage, price-impact, simulation, and audit policy. Never signs or submits.".to_string()
        }

        fn parameters_schema() -> String {
            crate::parameters_schema_json()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            emit(PluginAction::Start, None, "request_received");
            let cfg = serde_json::from_str::<Value>(&args)
                .ok()
                .and_then(|v| v.get("__config").cloned())
                .unwrap_or_else(|| json!({}));
            let rpc = cfg
                .get("rpc_url")
                .and_then(Value::as_str)
                .map(|url| HttpRpc {
                    url: url.to_string(),
                });
            let quote_url = cfg
                .get("jupiter_quote_url")
                .and_then(Value::as_str)
                .unwrap_or("https://quote-api.jup.ag/v6/quote")
                .to_string();
            let swap_url = cfg
                .get("jupiter_swap_url")
                .and_then(Value::as_str)
                .unwrap_or("https://quote-api.jup.ag/v6/swap")
                .to_string();
            let jupiter = HttpJupiter {
                quote_url,
                swap_url,
            };
            match jupiter_build_json(&args, &jupiter, rpc.as_ref().map(|r| r as &dyn RpcClient)) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "approval_payload_created",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        Some(PluginOutcome::Failure),
                        "request_failed",
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "jupiter_swap_build_safe::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: Some("{\"plugin\":\"jupiter-swap-build-safe\"}".to_string()),
                message: message.to_string(),
            },
        );
    }

    export!(JupiterSwapBuildSafe);
}

pub use solsafe_core::*;
