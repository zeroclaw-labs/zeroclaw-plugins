//! ZeroClaw WIT tool plugin: `lending_health`.
//!
//! Read-only DeFi lending position health for operator-configured wallets,
//! covering Kamino (public REST API) and MarginFi (raw JSON-RPC decoding).
//! None of [`health`], [`kamino`], or [`marginfi`] depends on wasm, so the
//! whole data path builds and tests on the host under a plain `cargo test`.
//! The component below is a shim over those same functions.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod health;
pub mod kamino;
pub mod marginfi;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::Duration;

    use crate::health::{render_payload, render_total_failure, Config, Position, Protocol};
    use crate::{kamino, marginfi};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct LendingHealth;

    const TOOL_NAME: &str = "lending_health";

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        #[serde(default)]
        wallet: Option<String>,
        #[serde(default)]
        protocol: Option<String>,
        /// The host merges this plugin's validated config object into the
        /// call arguments under the reserved `__config` key, after deleting
        /// any model-supplied value of that name. It is captured as a raw
        /// `Value` so a config-shaped problem is reported as a config error
        /// rather than collapsing the whole argument parse into "invalid
        /// arguments".
        #[serde(rename = "__config", default)]
        config: serde_json::Value,
    }

    impl PluginInfo for LendingHealth {
        fn plugin_name() -> String {
            env!("CARGO_PKG_NAME").to_string()
        }

        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Tool for LendingHealth {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Read-only health report for the operator's DeFi lending positions on Kamino \
             and MarginFi: deposits, borrows, and LTV versus the liquidation threshold, \
             flagged OK, WARN, or CRITICAL. Wallets come from the plugin config allowlist; \
             arbitrary addresses are refused."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "wallet": {
                        "type": "string",
                        "description": "Optional wallet label or pubkey from the configured allowlist. Omit for all configured wallets."
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["kamino", "marginfi"],
                        "description": "Optional protocol filter. Omit for all enabled protocols."
                    }
                },
                "required": []
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return fail(format!("invalid arguments: {e}")),
            };

            let cfg = match Config::from_json(&parsed.config) {
                Ok(c) => c,
                Err(e) => return fail(format!("config error: {e}")),
            };

            let wallets = match cfg.resolve_wallet(parsed.wallet.as_deref()) {
                Ok(w) => w,
                Err(e) => return fail(e),
            };

            let protocols: Vec<Protocol> = match parsed.protocol.as_deref() {
                None => cfg.protocols.clone(),
                Some(raw) => {
                    let wanted = match raw.trim().to_ascii_lowercase().as_str() {
                        "kamino" => Protocol::Kamino,
                        "marginfi" => Protocol::Marginfi,
                        other => {
                            return fail(format!(
                                "unknown protocol `{other}`; supported: kamino, marginfi"
                            ))
                        }
                    };
                    if !cfg.protocols.contains(&wanted) {
                        return fail(format!(
                            "protocol `{raw}` is not enabled in this plugin's config"
                        ));
                    }
                    vec![wanted]
                }
            };

            let timeout = Duration::from_secs(cfg.timeout_secs);
            let mut positions: Vec<Position> = Vec::new();
            let mut issues: Vec<String> = Vec::new();
            let mut attempted = 0u32;
            let mut succeeded = 0u32;

            for wallet in &wallets {
                for proto in &protocols {
                    attempted += 1;
                    let outcome = match proto {
                        Protocol::Kamino => fetch_get(
                            &kamino::portfolio_url(&cfg.kamino_api_base, &wallet.pubkey),
                            timeout,
                        )
                        .and_then(|body| kamino::parse_portfolio(&body, &wallet.label)),
                        Protocol::Marginfi => {
                            let rpc = cfg.rpc_url.as_deref().unwrap_or_default();
                            fetch_post_json(
                                rpc,
                                &marginfi::gpa_request_body(&wallet.pubkey),
                                timeout,
                            )
                            .and_then(|body| marginfi::parse_gpa_response(&body, &wallet.label))
                        }
                    };
                    match outcome {
                        Ok(mut found) => {
                            succeeded += 1;
                            positions.append(&mut found);
                        }
                        Err(e) => issues.push(format!("{} {}: {e}", proto.as_str(), wallet.label)),
                    }
                }
            }

            if succeeded == 0 {
                return fail(render_total_failure(&issues));
            }

            // Failures ride along inside the same cap as the report itself.
            let report = render_payload(&positions, &issues, &cfg);

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                &format!(
                    "reported {} position(s) from {succeeded}/{attempted} source call(s)",
                    positions.len()
                ),
            );

            Ok(ToolResult {
                success: true,
                output: report,
                error: None,
            })
        }
    }

    /// Turns a raw wasi-http failure into something an operator can act on.
    ///
    /// Plugins reach the network through `wasmtime-wasi-http`, whose bundled
    /// request path trusts the webpki root set rather than the machine's own
    /// certificate store. Antivirus HTTPS inspection (Avast, AVG, Kaspersky,
    /// ESET) and corporate TLS-inspecting proxies present a certificate signed
    /// by a CA they install into the OS store, which that root set does not
    /// contain, so every outbound call fails. The bare code says nothing, and
    /// the same machine's browser reaches the endpoint fine, which makes the
    /// plugin look broken when the cause is entirely outside it.
    fn explain_request_error(e: impl std::fmt::Display) -> String {
        let raw = e.to_string();
        if raw.contains("TlsProtocolError") {
            return format!(
                "{raw} (TLS refused: likely antivirus HTTPS inspection or a TLS-inspecting proxy, whose CA this runtime does not trust)"
            );
        }
        raw
    }

    fn fetch_get(url: &str, timeout: Duration) -> Result<String, String> {
        let response = waki::Client::new()
            .get(url)
            .connect_timeout(timeout)
            .send()
            .map_err(|e| format!("request failed: {}", explain_request_error(e)))?;
        let status = response.status_code();
        let body = response
            .body()
            .map_err(|e| format!("response read failed: {e}"))?;
        if status != 200 {
            return Err(format!("HTTP {status}"));
        }
        String::from_utf8(body).map_err(|_| "response is not UTF-8".to_string())
    }

    fn fetch_post_json(url: &str, body: &str, timeout: Duration) -> Result<String, String> {
        let response = waki::Client::new()
            .post(url)
            .connect_timeout(timeout)
            .header("Content-Type", "application/json")
            .body(body.as_bytes().to_vec())
            .send()
            .map_err(|e| format!("request failed: {}", explain_request_error(e)))?;
        let status = response.status_code();
        let bytes = response
            .body()
            .map_err(|e| format!("response read failed: {e}"))?;
        if status != 200 {
            return Err(format!("HTTP {status}"));
        }
        String::from_utf8(bytes).map_err(|_| "response is not UTF-8".to_string())
    }

    fn fail(message: String) -> Result<ToolResult, String> {
        // The same 900-character bound the report path carries. Several failure
        // messages interpolate a value the caller supplied, so without this the
        // failure path is the wider door into the agent's context.
        let message = crate::health::cap_failure(message);
        emit(PluginAction::Fail, PluginOutcome::Failure, &message);
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "lending_health::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(LendingHealth);
}
