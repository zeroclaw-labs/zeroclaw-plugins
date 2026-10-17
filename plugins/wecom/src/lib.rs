//! A ZeroClaw WIT channel plugin for the send-only WeCom Bot Webhook API.

pub mod wecom;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;

    use crate::wecom::{build_text_body, check_api_response, webhook_url, WeComConfig, CHANNEL};
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::logging::{self, LogLevel, PluginAction, PluginEvent, PluginOutcome};
    use zeroclaw::plugin::{config, secrets};

    /// Bound each connect well inside the host's 30 s call deadline, so an
    /// unreachable address fails the request instead of the whole call.
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    thread_local! {
        static CONFIG: RefCell<WeComConfig> = RefCell::new(WeComConfig::default());
    }

    fn response_detail(resp: waki::Response) -> String {
        resp.body()
            .ok()
            .and_then(|body| String::from_utf8(body).ok())
            .unwrap_or_default()
    }

    fn send_text(cfg: &WeComConfig, content: &str) -> Result<(), String> {
        if !cfg.is_configured() {
            return Err("wecom: webhook_key is required".to_string());
        }
        let url = webhook_url(cfg.webhook_key());
        let resp = waki::Client::new()
            .post(&url)
            .connect_timeout(CONNECT_TIMEOUT)
            .header("Accept", "application/json")
            .json(&build_text_body(content))
            .send()
            .map_err(|error| format!("wecom webhook POST failed: {error}"))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!(
                "wecom webhook POST failed ({status}): {}",
                response_detail(resp)
            ));
        }
        let value = resp
            .json()
            .map_err(|error| format!("wecom response JSON failed: {error}"))?;
        check_api_response(&value)
    }

    /// Report a config or secret read the host refused or could not serve,
    /// naming the key and the error kind, never a value.
    fn report_read_failure(key: &str, kind: &str) {
        logging::log_record(
            LogLevel::Warn,
            &PluginEvent {
                function_name: "wecom::configure".to_string(),
                action: PluginAction::Fail,
                outcome: Some(PluginOutcome::Failure),
                duration_ms: None,
                attrs: None,
                message: format!("wecom: could not read {key}: {kind}"),
            },
        );
    }

    /// The fixed name of a `config.get` failure; the variants carry no payload.
    fn config_error_kind(error: config::ConfigError) -> &'static str {
        match error {
            config::ConfigError::AccessDenied => "access denied",
            config::ConfigError::Unavailable => "unavailable",
        }
    }

    /// The fixed name of a `secrets.get` failure; the variants carry no payload.
    fn secret_error_kind(error: secrets::SecretError) -> &'static str {
        match error {
            secrets::SecretError::AccessDenied => "access denied",
            secrets::SecretError::NotFound => "not found",
            secrets::SecretError::Unavailable => "unavailable",
        }
    }

    /// The instance's typed config, read when the host configures the
    /// instance. `config.get` serves the public settings; the schema's
    /// `x-secret` values reach the plugin only through `secrets.get`. A read
    /// the host refuses is logged and leaves its field at the default, so a
    /// misconfigured instance stays inert rather than half-configured.
    fn load_config() -> WeComConfig {
        let public = config::get().unwrap_or_else(|error| {
            report_read_failure("config", config_error_kind(error));
            String::new()
        });
        let mut cfg = WeComConfig::from_json(&public);
        cfg.webhook_key = secrets::get("webhook_key")
            .map_err(|error| report_read_failure("webhook_key", secret_error_kind(error)))
            .unwrap_or_default();
        cfg
    }

    struct WeComChannel;

    impl PluginInfo for WeComChannel {
        fn plugin_name() -> String {
            CHANNEL.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for WeComChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        fn configure() -> Result<(), String> {
            CONFIG.with(|state| *state.borrow_mut() = load_config());
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err(
                    "wecom: media attachments are not supported by Bot Webhook mode".into(),
                );
            }
            let cfg = CONFIG.with(|state| state.borrow().clone());
            send_text(&cfg, &message.content)
        }

        fn poll_message() -> Option<InboundMessage> {
            None
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
        }

        fn health_check() -> bool {
            CONFIG.with(|state| state.borrow().is_configured())
        }

        fn self_handle() -> Option<String> {
            None
        }
        fn self_addressed_mention() -> Option<String> {
            None
        }
        fn drop_self_message(_msg: InboundMessage) -> bool {
            false
        }
        fn start_typing(_recipient: String) -> Result<(), String> {
            Ok(())
        }
        fn stop_typing(_recipient: String) -> Result<(), String> {
            Ok(())
        }
        fn supports_draft_updates() -> bool {
            false
        }
        fn send_draft(_message: SendMessage) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn update_draft(_r: String, _m: String, _t: String) -> Result<(), String> {
            Ok(())
        }
        fn update_draft_progress(_r: String, _m: String, _t: String) -> Result<(), String> {
            Ok(())
        }
        fn finalize_draft(_r: String, _m: String, _t: String) -> Result<(), String> {
            Ok(())
        }
        fn cancel_draft(_r: String, _m: String) -> Result<(), String> {
            Ok(())
        }
        fn supports_multi_message_streaming() -> bool {
            false
        }
        fn multi_message_delay_ms() -> u64 {
            800
        }
        fn add_reaction(_c: String, _m: String, _e: String) -> Result<(), String> {
            Ok(())
        }
        fn remove_reaction(_c: String, _m: String, _e: String) -> Result<(), String> {
            Ok(())
        }
        fn pin_message(_c: String, _m: String) -> Result<(), String> {
            Ok(())
        }
        fn unpin_message(_c: String, _m: String) -> Result<(), String> {
            Ok(())
        }
        fn redact_message(_c: String, _m: String, _reason: Option<String>) -> Result<(), String> {
            Ok(())
        }
        fn request_approval(
            _recipient: String,
            _request: ApprovalRequest,
        ) -> Result<Option<ApprovalResponse>, String> {
            Ok(None)
        }
        fn request_choice(
            _question: String,
            _choices: Vec<String>,
            _timeout_secs: u64,
        ) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn supports_free_form_ask() -> bool {
            true
        }
        fn webhook_path() -> Option<String> {
            None
        }
        fn parse_webhook(_request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            Err(WebhookRejection::BadRequest(
                "wecom Bot Webhook mode is send-only".to_string(),
            ))
        }
    }

    export!(WeComChannel);
}
