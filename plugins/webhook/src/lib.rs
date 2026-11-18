//! A ZeroClaw WIT **channel** plugin: generic inbound Webhook.
//!
//! A **webhook** channel: it does not poll. The host serves `POST` on
//! `/plugin/webhook` and hands each request to [`parse_webhook`]. When a `secret`
//! is configured the plugin verifies the `X-Webhook-Signature` HMAC-SHA256 over
//! the raw body (hex, `sha256=` prefix tolerated) before decoding; a bad or
//! missing signature returns `Err(reason)` so the host replies `401`. When no
//! secret is set, all inbound is accepted. A GET is a no-op acknowledgement.
//!
//! The inbound payload is `{sender, content, thread_id?}`; replies are POSTed
//! (or PUT) to `send_url` as `{content, thread_id?, recipient?}` over the host's
//! `wasi:http` (`waki`), with the optional `auth_header` as `Authorization`.
//!
//! The pure logic (config/signature/decode/body) lives in [`webhook`] and is
//! host-`cargo test`ed; this file is the component shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod webhook;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::Duration;

    use crate::webhook::{
        build_outgoing, parse_incoming, verify_signature, Inbound, WebhookConfig, WEBHOOK_PATH,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::logging::{self, LogLevel, PluginAction, PluginEvent, PluginOutcome};
    use zeroclaw::plugin::{config, secrets};

    const PLUGIN_NAME: &str = "webhook";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Report a config or secret read the host refused or could not serve,
    /// naming the key and the error kind, never a value.
    fn report_read_failure(key: &str, kind: &str) {
        logging::log_record(
            LogLevel::Warn,
            &PluginEvent {
                function_name: "webhook::read_config".to_string(),
                action: PluginAction::Fail,
                outcome: Some(PluginOutcome::Failure),
                duration_ms: None,
                attrs: None,
                message: format!("webhook: could not read {key}: {kind}"),
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

    fn public_config() -> Result<WebhookConfig, String> {
        let public = config::get().map_err(|error| {
            report_read_failure("config", config_error_kind(error));
            "webhook: public configuration unavailable"
        })?;
        serde_json::from_str(&public)
            .map_err(|_| "webhook: invalid public configuration".to_string())
    }

    fn optional_secret(key: &str) -> Result<Option<String>, String> {
        match secrets::get(key) {
            Ok(value) => Ok(Some(value)),
            Err(secrets::SecretError::NotFound) => Ok(None),
            Err(error) => {
                report_read_failure(key, secret_error_kind(error));
                Err(format!("webhook: cannot read {key}"))
            }
        }
    }

    fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: 0,
            thread_ts: inb.thread_ts,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct WebhookChannel;

    impl PluginInfo for WebhookChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for WebhookChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure() -> Result<(), String> {
            public_config().map(|_| ())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = public_config()?;
            // No outbound URL configured → drop silently (matches the native
            // channel, which logs and returns Ok).
            let Some(url) = cfg.send_url().map(str::to_string) else {
                return Ok(());
            };
            let auth_header = optional_secret("auth_header")?;
            let body = build_outgoing(
                &message.content,
                message.thread_ts.as_deref(),
                &message.recipient,
            );

            let client = waki::Client::new();
            let mut req = match cfg.send_method().as_str() {
                "PUT" => client.put(&url),
                _ => client.post(&url),
            }
            .header("Content-Type", "application/json")
            .connect_timeout(CONNECT_TIMEOUT);
            if let Some(auth) = WebhookConfig::auth_header_value(auth_header.as_deref()) {
                req = req.header("Authorization", auth);
            }

            let resp = req
                .json(&body)
                .send()
                .map_err(|e| format!("webhook send failed: {e}"))?;
            let status = resp.status_code();
            if !(200..300).contains(&status) {
                return Err(format!("webhook send failed (HTTP {status})"));
            }
            Ok(())
        }

        /// A webhook channel never polls — inbound arrives via `parse_webhook`.
        fn poll_message() -> Option<InboundMessage> {
            None
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::WEBHOOK_INGRESS
        }

        fn health_check() -> bool {
            true
        }

        fn webhook_path() -> Option<String> {
            Some(WEBHOOK_PATH.to_string())
        }

        fn parse_webhook(request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            let headers = request.headers;
            let body = request.body;
            let method = &request.method;
            // Generic webhook has no GET verification; ack a GET with nothing.
            if method.eq_ignore_ascii_case("GET") {
                return Ok(WebhookResponse::Reply(String::new()));
            }

            let secret = optional_secret("secret").map_err(WebhookRejection::Unauthorized)?;
            let signature = header_get(&headers, "x-webhook-signature");
            if !verify_signature(
                WebhookConfig::secret_value(secret.as_deref()),
                &body,
                signature.as_deref(),
            ) {
                return Err(WebhookRejection::Unauthorized(
                    "webhook: X-Webhook-Signature verification failed".to_string(),
                ));
            }

            let inbound = parse_incoming(&body).map_err(WebhookRejection::BadRequest)?;
            Ok(WebhookResponse::Messages(vec![to_wit(inbound)]))
        }

        // ── capability-gated stubs (documented WIT defaults) ──
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
    }

    export!(WebhookChannel);
}
