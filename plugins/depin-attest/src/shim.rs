//! Thin wasm shim: wit-bindgen Guest + waki HttpClient + logging. No logic here.
wit_bindgen::generate!({
    path: "../../wit/v0",
    world: "tool-plugin",
    features: ["plugins-wit-v0"],
});

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{attest, CoreError, HttpClient};

use crate::core::{run, Args, Config};
use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

struct DepinAttest;

const PLUGIN_NAME: &str = "depin-attest";
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(serde::Deserialize)]
struct ExecuteArgs {
    reading: Option<f64>,
    note: Option<String>,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

struct WakiHttp;
impl HttpClient for WakiHttp {
    fn post_json(&self, url: &str, body: &str) -> Result<String, CoreError> {
        let resp = waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.as_bytes().to_vec())
            .send()
            .map_err(|e| CoreError::Http(e.to_string()))?;
        let bytes = resp.body().map_err(|e| CoreError::Http(e.to_string()))?;
        String::from_utf8(bytes).map_err(|e| CoreError::Parse(e.to_string()))
    }
}

impl PluginInfo for DepinAttest {
    fn plugin_name() -> String {
        PLUGIN_NAME.to_string()
    }
    fn plugin_version() -> String {
        PLUGIN_VERSION.to_string()
    }
}

impl Tool for DepinAttest {
    fn name() -> String {
        PLUGIN_NAME.to_string()
    }

    fn description() -> String {
        "Build an UNSIGNED Solana Memo attestation transaction from a sensor reading. \
         Returns base64 for a human to sign; never signs, never holds a key."
            .to_string()
    }

    fn parameters_schema() -> String {
        serde_json::json!({
            "type": "object",
            "properties": {
                "reading": {"type": "number", "description": "Sensor reading (e.g. temperature °C). Optional if sensor_source=mock."},
                "note": {"type": "string", "maxLength": 64, "description": "Optional short note attached to the attestation."}
            }
        })
        .to_string()
    }

    fn execute(args: String) -> Result<ToolResult, String> {
        match build(&args) {
            Ok(output) => {
                emit(
                    PluginAction::Complete,
                    PluginOutcome::Success,
                    "attestation built",
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
                    PluginOutcome::Failure,
                    "attestation rejected",
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

fn build(args: &str) -> Result<String, CoreError> {
    let parsed: ExecuteArgs =
        serde_json::from_str(args).map_err(|e| CoreError::Input(e.to_string()))?;
    let cfg = Config {
        rpc_url: cfg_get(&parsed.config, "rpc_url")?,
        device_pubkey: cfg_get(&parsed.config, "device_pubkey")?,
        sensor_source: parsed
            .config
            .get("sensor_source")
            .cloned()
            .unwrap_or_else(|| "mock".to_string()),
        nonce_account: parsed.config.get("nonce_account").cloned(),
        nonce_authority: parsed.config.get("nonce_authority").cloned(),
    };
    let call_args = Args {
        reading: parsed.reading,
        note: parsed.note,
    };
    let http = WakiHttp;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last_nonce = attest::latest_nonce(&http, &cfg.rpc_url, &cfg.device_pubkey)?;
    run(&cfg, &call_args, &http, now, last_nonce)
}

fn cfg_get(cfg: &HashMap<String, String>, key: &str) -> Result<String, CoreError> {
    cfg.get(key)
        .cloned()
        .ok_or_else(|| CoreError::Input(format!("missing config: {key}")))
}

fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
    log_record(
        LogLevel::Info,
        &PluginEvent {
            function_name: "depin_attest::tool::execute".to_string(),
            action,
            outcome: Some(outcome),
            duration_ms: None,
            attrs: None,
            message: message.to_string(),
        },
    );
}

export!(DepinAttest);
