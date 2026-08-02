//! A ZeroClaw WIT tool plugin: `image_gen_fal`.
//!
//! Generates an image from a text prompt using fal.ai (Flux models) and returns
//! the resulting image URL.
//!
//! This replaces the tool of the same name that used to live in core
//! (`zeroclaw-tools/src/image_gen.rs`). Core already classified it as
//! `ToolKind::Plugin`; moving it out keeps a third-party paid API, and its
//! credential, off the default binary.
//!
//! The API key comes from this plugin's own jailed config section, injected by
//! the host into `execute` args as `__config` (`config_read` permission). The
//! original version read `FAL_API_KEY` through a `zc_env_read` host function;
//! raw environment access was removed from plugins in zeroclaw#8137, so the key
//! is now config-scoped per alias.
//!
//! The pure request/response logic lives in [`fal`] with no wasm dependency, so
//! it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod fal;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::fal;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct ImageGenFal;

    const PLUGIN_NAME: &str = "image-gen-fal";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "image_gen_fal";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for ImageGenFal {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    /// Build a failed `ToolResult`. Argument and credential problems are
    /// reported this way rather than as a trap so the model can correct itself.
    fn failure(message: impl Into<String>) -> ToolResult {
        let message = message.into();
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        }
    }

    /// Emit a structured record. Never logs the prompt or the API key — the
    /// prompt is user content and the key is a credential.
    ///
    /// `outcome: None` is how the WIT records "unknown"; there is no Unknown
    /// variant, so an in-flight event passes `None` rather than guessing.
    fn log(
        level: LogLevel,
        action: PluginAction,
        outcome: Option<PluginOutcome>,
        message: String,
    ) {
        log_record(
            level,
            &PluginEvent {
                function_name: "image_gen_fal::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message,
            },
        );
    }

    impl Tool for ImageGenFal {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Generate an image from a text prompt using fal.ai (Flux models). \
             Returns the image URL and metadata."
                .to_string()
        }

        fn parameters_schema() -> String {
            fal::parameters_schema().to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let value: serde_json::Value =
                serde_json::from_str(&args).map_err(|e| format!("invalid arguments JSON: {e}"))?;

            let request = match fal::parse_args(&value) {
                Ok(r) => r,
                Err(e) => return Ok(failure(e)),
            };

            let parsed: ExecuteArgs = serde_json::from_value(value.clone()).unwrap_or(ExecuteArgs {
                config: HashMap::new(),
            });
            let api_key = match fal::api_key(&parsed.config) {
                Ok(k) => k,
                Err(e) => return Ok(failure(e)),
            };

            log(
                LogLevel::Info,
                PluginAction::Start,
                None,
                format!("generating image with {}", request.model),
            );

            let response = waki::Client::new()
                .post(&request.endpoint())
                .header("Authorization", format!("Key {api_key}"))
                .header("Content-Type", "application/json")
                .body(request.body().to_string().into_bytes())
                .send()
                .map_err(|e| format!("fal.ai request failed: {e}"))?;

            let status = response.status_code();
            let body = response
                .body()
                .map_err(|e| format!("failed to read fal.ai response body: {e}"))?;
            let body = String::from_utf8_lossy(&body).into_owned();

            if status >= 400 {
                return Ok(failure(fal::truncate_error(&body, status)));
            }

            let image_url = match fal::parse_response(&body) {
                Ok(u) => u,
                Err(e) => return Ok(failure(e)),
            };

            log(
                LogLevel::Info,
                PluginAction::Complete,
                Some(PluginOutcome::Success),
                "image generated".to_string(),
            );

            Ok(ToolResult {
                success: true,
                output: fal::success_output(&request, &image_url),
                error: None,
            })
        }
    }

    export!(ImageGenFal);
}
