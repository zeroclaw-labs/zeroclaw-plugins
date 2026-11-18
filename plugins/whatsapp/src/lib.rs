//! WhatsApp Cloud channel. The plugin checks the typed GET query against the
//! verification token and returns the challenge as an HTTP reply. For POST it
//! verifies the Graph app secret against the raw body and decodes text events.
//! Replies go through the Meta Graph Cloud API.

pub mod whatsapp;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::Duration;

    use serde_json::Value;

    use crate::whatsapp::{
        build_send_body, decode_inbound, get_verification_challenge, health_url, send_url,
        verify_get_request, verify_signature, Inbound, WhatsAppConfig, WEBHOOK_PATH,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    use zeroclaw::plugin::{config, secrets};

    fn public_config() -> Result<WhatsAppConfig, String> {
        let public = config::get().map_err(|_| "whatsapp: public configuration unavailable")?;
        serde_json::from_str(&public)
            .map_err(|_| "whatsapp: invalid public configuration".to_string())
    }

    fn optional_secret(key: &str) -> Result<Option<String>, String> {
        match secrets::get(key) {
            Ok(value) => Ok(Some(value)),
            Err(secrets::SecretError::NotFound) => Ok(None),
            Err(_) => Err(format!("whatsapp: cannot read {key}")),
        }
    }

    fn send_config() -> Result<WhatsAppConfig, String> {
        let mut cfg = public_config()?;
        cfg.access_token = optional_secret("access_token")?;
        Ok(cfg)
    }

    fn inbound_config() -> Result<WhatsAppConfig, String> {
        let mut cfg = public_config()?;
        cfg.app_secret = optional_secret("app_secret")?;
        cfg.verify_token = optional_secret("verify_token")?;
        Ok(cfg)
    }

    const PLUGIN_NAME: &str = "whatsapp";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    /// Connect-phase timeout for every Graph API call. `waki` can only bound the
    /// connect (not the response body), which is enough to fail fast on a dead
    /// endpoint.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Stamp a decoded [`Inbound`] with the plugin's `channel` and the WIT
    /// inbound-message shape.
    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: inb.channel_alias,
            timestamp: inb.timestamp,
            thread_ts: inb.thread_ts,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    /// Case-insensitive header lookup over the host's (already lower-cased)
    /// header list.
    fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    struct WhatsAppChannel;

    impl PluginInfo for WhatsAppChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for WhatsAppChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure() -> Result<(), String> {
            public_config().map(|_| ())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = send_config()?;
            let token = cfg.access_token();
            if token.is_empty() {
                return Err("whatsapp: missing access_token in config".to_string());
            }
            let phone_id = cfg.phone_number_id();
            if phone_id.is_empty() {
                return Err("whatsapp: missing phone_number_id in config".to_string());
            }

            let body = build_send_body(&message.recipient, &message.content);
            let url = send_url(&cfg.api_base(), phone_id);

            let resp = waki::Client::new()
                .post(&url)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .connect_timeout(CONNECT_TIMEOUT)
                .json(&body)
                .send()
                .map_err(|e| format!("whatsapp send failed: {e}"))?;

            let status = resp.status_code();
            if status >= 400 {
                let detail = resp
                    .body()
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_default();
                return Err(format!("whatsapp send failed (HTTP {status}): {detail}"));
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
            let Ok(cfg) = send_config() else { return false };
            if !cfg.can_send() {
                return false;
            }
            let url = health_url(&cfg.api_base(), cfg.phone_number_id());
            match waki::Client::new()
                .get(&url)
                .header("Authorization", format!("Bearer {}", cfg.access_token()))
                .connect_timeout(CONNECT_TIMEOUT)
                .send()
            {
                Ok(resp) => resp.status_code() < 400,
                Err(_) => false,
            }
        }

        fn webhook_path() -> Option<String> {
            Some(WEBHOOK_PATH.to_string())
        }

        fn parse_webhook(request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            let headers = request.headers;
            let body = request.body;
            let cfg = inbound_config().map_err(WebhookRejection::Unauthorized)?;
            let method = &request.method;

            // ── Meta verification handshake (GET) ──
            if method.eq_ignore_ascii_case("GET") {
                let query = request.query;
                verify_get_request(&cfg, &query).map_err(WebhookRejection::Unauthorized)?;
                let challenge =
                    get_verification_challenge(&query).map_err(WebhookRejection::BadRequest)?;
                return Ok(WebhookResponse::Reply(challenge));
            }

            // ── Event webhook (POST) ──
            let app_secret = cfg.app_secret();
            if app_secret.is_empty() {
                return Err(WebhookRejection::Unauthorized(
                    "whatsapp: app_secret required for inbound POST".into(),
                ));
            }
            let sig = header_get(&headers, "x-hub-signature-256").unwrap_or_default();
            if !verify_signature(app_secret, &body, &sig) {
                return Err(WebhookRejection::Unauthorized(
                    "whatsapp: X-Hub-Signature-256 verification failed".into(),
                ));
            }

            let payload: Value = serde_json::from_slice(&body).map_err(|e| {
                WebhookRejection::BadRequest(format!("whatsapp: invalid JSON payload: {e}"))
            })?;
            let inbs = decode_inbound(&payload, None);
            Ok(WebhookResponse::Messages(
                inbs.into_iter().map(to_wit).collect(),
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

    export!(WhatsAppChannel);
}
