//! ZeroClaw WIT tool plugin: `token_risk_check` (T0).
//!
//! Pure core in [`risk`] + [`i18n`] + [`rpc`]. Wasm shim only under `target_family = "wasm"`.

pub mod i18n;
pub mod risk;
pub mod rpc;

#[cfg(not(target_family = "wasm"))]
pub fn fetch_mint_facts_host(rpc_url: &str, mint: &str) -> Result<risk::MintFacts, String> {
    if !rpc::rpc_url_allowed(rpc_url) {
        return Err("rpc_url_not_allowlisted".into());
    }
    let body = rpc::build_get_account_info_body(mint);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .build()
        .map_err(|e| format!("rpc_client: {e}"))?;
    let resp = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|e| format!("rpc_http: {e}"))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| format!("rpc_body: {e}"))?;
    if !status.is_success() {
        return Err(format!("rpc_http_status:{status}:{text}"));
    }
    rpc::mint_facts_from_rpc_json(mint, &text)
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::i18n::{self, Locale};
    use crate::risk::{assess, detect_prompt_injection, MintFacts};
    use crate::rpc::{
        build_get_account_info_body, mint_facts_from_rpc_json, rpc_url_allowed, DEFAULT_RPC_URL,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde::Deserialize;
    use std::collections::HashMap;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";

    #[derive(Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(default = "default_locale")]
        locale: String,
        #[serde(default)]
        facts_json: Option<String>,
        #[serde(default)]
        rpc_url: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn default_locale() -> String {
        "en".into()
    }

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "T0 read-only Solana mint risk triage via public RPC (allowlisted). \
             Returns green/amber/red. Locale: en,fr,es,pt,de,ru,ja,zh. \
             Fail-closed on prompt injection. Never signs or moves funds."
                .into()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": { "type": "string", "description": "Solana mint address (base58)." },
                    "locale": { "type": "string", "default": "en" },
                    "rpc_url": { "type": "string", "description": "Optional allowlisted HTTPS RPC URL." },
                    "facts_json": { "type": "string", "description": "Optional offline MintFacts JSON (skips RPC)." }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            if detect_prompt_injection(&args) {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "prompt_injection",
                );
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(i18n::refused_inject(Locale::En).to_string()),
                });
            }

            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "bad_args");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            if detect_prompt_injection(&parsed.mint) {
                let locale = Locale::parse(&parsed.locale);
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "prompt_injection",
                );
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(i18n::refused_inject(locale).to_string()),
                });
            }

            let facts = if let Some(raw) = parsed.facts_json.as_ref() {
                match serde_json::from_str::<MintFacts>(raw) {
                    Ok(mut f) => {
                        if f.mint.is_empty() {
                            f.mint = parsed.mint.clone();
                        }
                        f
                    }
                    Err(e) => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(format!("invalid facts_json: {e}")),
                        });
                    }
                }
            } else {
                match fetch_mint_facts_wasm(&parsed) {
                    Ok(f) => f,
                    Err(e) => {
                        emit(PluginAction::Fail, PluginOutcome::Failure, "rpc_fail");
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(e),
                        });
                    }
                }
            };

            let report = assess(&facts, &parsed.locale);
            let output = serde_json::to_string(&report).unwrap_or_else(|_| report.summary.clone());
            emit(PluginAction::Complete, PluginOutcome::Success, "assessed");
            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn fetch_mint_facts_wasm(parsed: &ExecuteArgs) -> Result<MintFacts, String> {
        let rpc_url = parsed
            .rpc_url
            .clone()
            .or_else(|| parsed.config.get("rpc_url").cloned())
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        if !rpc_url_allowed(&rpc_url) {
            return Err("rpc_url_not_allowlisted".into());
        }
        let body: serde_json::Value =
            serde_json::from_str(&build_get_account_info_body(&parsed.mint))
                .map_err(|e| format!("rpc_body_json: {e}"))?;
        let resp = waki::Client::new()
            .post(&rpc_url)
            .header("Content-Type", "application/json")
            .connect_timeout(std::time::Duration::from_secs(8))
            .json(&body)
            .send()
            .map_err(|e| format!("rpc_http: {e}"))?;
        let status = resp.status_code();
        let text = resp
            .body()
            .map_err(|e| format!("rpc_read: {e}"))
            .and_then(|b| String::from_utf8(b).map_err(|e| format!("rpc_utf8: {e}")))?;
        if status >= 400 {
            return Err(format!("rpc_http_status:{status}:{text}"));
        }
        mint_facts_from_rpc_json(&parsed.mint, &text)
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
