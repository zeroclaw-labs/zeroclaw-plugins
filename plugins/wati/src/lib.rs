//! WATI channel. A typed GET query carries the verification challenge; the
//! guest returns it as an HTTP reply. POST events require a separately
//! authenticated ingress because this adapter does not verify provider signatures.
//! Outbound text uses the WATI conversation API.

pub mod wati;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::Duration;

    use crate::wati::{
        build_send_body, build_target, extract_challenge, parse_webhook_payload, send_url, Inbound,
        WatiConfig, WEBHOOK_PATH,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    use zeroclaw::plugin::{config, secrets};

    fn public_config() -> Result<WatiConfig, String> {
        let public = config::get().map_err(|_| "wati: public configuration unavailable")?;
        serde_json::from_str(&public).map_err(|_| "wati: invalid public configuration".to_string())
    }

    fn optional_secret(key: &str) -> Result<Option<String>, String> {
        match secrets::get(key) {
            Ok(value) => Ok(Some(value)),
            Err(secrets::SecretError::NotFound) => Ok(None),
            Err(_) => Err(format!("wati: cannot read {key}")),
        }
    }

    fn send_config() -> Result<WatiConfig, String> {
        let mut cfg = public_config()?;
        cfg.api_token = optional_secret("api_token")?;
        Ok(cfg)
    }

    const PLUGIN_NAME: &str = "wati";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: inb.timestamp,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct WatiChannel;

    impl PluginInfo for WatiChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for WatiChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure() -> Result<(), String> {
            public_config().map(|_| ())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = send_config()?;
            let token = cfg.api_token();
            if token.is_empty() {
                return Err("wati: missing api_token in config".to_string());
            }
            let target = build_target(cfg.tenant_id(), &message.recipient);
            let body = build_send_body(&target, &message.content);
            let url = send_url(&cfg.api_url());

            let resp = waki::Client::new()
                .post(&url)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .connect_timeout(CONNECT_TIMEOUT)
                .json(&body)
                .send()
                .map_err(|e| format!("wati send failed: {e}"))?;

            let status = resp.status_code();
            if status >= 400 {
                let detail = resp
                    .body()
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_default();
                return Err(format!("wati send failed (HTTP {status}): {detail}"));
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
            send_config().is_ok_and(|cfg| !cfg.api_token().is_empty())
        }

        fn webhook_path() -> Option<String> {
            Some(WEBHOOK_PATH.to_string())
        }

        fn parse_webhook(request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            let body = request.body;
            let method = &request.method;

            // ── WATI verification handshake (GET) ──
            if method.eq_ignore_ascii_case("GET") {
                let query = request.query;
                let challenge = extract_challenge(&query).map_err(WebhookRejection::BadRequest)?;
                return Ok(WebhookResponse::Reply(challenge));
            }

            // The trusted ingress authenticates the event before forwarding the body.
            let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
                WebhookRejection::BadRequest(format!("wati: invalid JSON payload: {e}"))
            })?;
            Ok(WebhookResponse::Messages(
                parse_webhook_payload(&payload)
                    .into_iter()
                    .map(to_wit)
                    .collect(),
            ))
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

    export!(WatiChannel);
}
