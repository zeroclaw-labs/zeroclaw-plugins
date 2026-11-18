//! Nextcloud Talk channel. The host forwards webhook requests to the guest;
//! the plugin verifies the HMAC over the random header and raw request body,
//! decodes Talk events and posts replies through the OCS chat API.

pub mod nextcloud;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::nextcloud::{
        authenticate_webhook, build_send_body, chat_url, decode_webhook, truncate_to_nc_limit,
        Inbound, NextcloudConfig,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    use zeroclaw::plugin::{config, secrets};

    fn public_config() -> Result<NextcloudConfig, String> {
        let public = config::get().map_err(|_| "nextcloud: public configuration unavailable")?;
        serde_json::from_str(&public)
            .map_err(|_| "nextcloud: invalid public configuration".to_string())
    }

    fn optional_secret(key: &str) -> Result<Option<String>, String> {
        match secrets::get(key) {
            Ok(value) => Ok(Some(value)),
            Err(secrets::SecretError::NotFound) => Ok(None),
            Err(_) => Err(format!("nextcloud: cannot read {key}")),
        }
    }

    fn send_config() -> Result<NextcloudConfig, String> {
        let mut cfg = public_config()?;
        cfg.app_token = optional_secret("app_token")?;
        Ok(cfg)
    }

    fn inbound_config() -> Result<NextcloudConfig, String> {
        let mut cfg = public_config()?;
        cfg.webhook_secret = optional_secret("webhook_secret")?;
        if cfg.webhook_secret().is_empty() {
            return Err("nextcloud: webhook_secret required for webhook ingress".into());
        }
        Ok(cfg)
    }

    const PLUGIN_NAME: &str = "nextcloud";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    /// URL path segment the host mounts under `/plugin/<segment>`.
    const WEBHOOK_SEGMENT: &str = "nextcloud";

    /// Current Unix time in milliseconds (the WIT `timestamp` unit), or `0` if the
    /// clock is unavailable.
    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Blocking OCS `POST` of a JSON body with the bot's `Bearer` token and the
    /// mandatory `OCS-APIRequest` header; any non-2xx surfaces the server's error
    /// body to `send`.
    fn post_chat(url: &str, token: &str, body: &Value) -> Result<(), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("OCS-APIRequest", "true")
            .header("Accept", "application/json")
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        if (200..300).contains(&status) {
            return Ok(());
        }
        let detail = resp
            .body()
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        Err(format!(
            "nextcloud Talk chat send failed ({status}): {detail}"
        ))
    }

    /// Stamp a decoded [`Inbound`] with the WIT inbound-message fields. `channel`
    /// is `"nextcloud"`; `timestamp` is receive-time (the webhook payload carries
    /// no reliable millisecond timestamp).
    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: now_millis(),
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct NextcloudChannel;

    impl PluginInfo for NextcloudChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for NextcloudChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure() -> Result<(), String> {
            public_config().map(|_| ())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = send_config()?;
            let token = cfg.app_token();
            if token.is_empty() {
                return Err("nextcloud: no app_token configured".to_string());
            }
            if cfg.base_url().is_empty() {
                return Err("nextcloud: no base_url configured".to_string());
            }
            let room_token = message.recipient.trim();
            if room_token.is_empty() {
                return Err("nextcloud: empty recipient (conversation token)".to_string());
            }
            let content = truncate_to_nc_limit(&message.content);
            let body = build_send_body(content);
            post_chat(&chat_url(cfg.base_url(), room_token), token, &body)
        }

        /// Webhook channel: nothing to poll — the host delivers inbound via
        /// `parse_webhook`.
        fn poll_message() -> Option<InboundMessage> {
            None
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::WEBHOOK_INGRESS
        }

        /// Config-level readiness (no network): send requires a base URL + token.
        fn health_check() -> bool {
            let Ok(cfg) = send_config() else { return false };
            !cfg.base_url().is_empty() && !cfg.app_token().is_empty()
        }

        fn webhook_path() -> Option<String> {
            Some(WEBHOOK_SEGMENT.to_string())
        }

        fn parse_webhook(request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            let headers = request.headers;
            let body = request.body;
            let cfg = inbound_config().map_err(WebhookRejection::Unauthorized)?;
            authenticate_webhook(&headers, &body, &cfg).map_err(WebhookRejection::Unauthorized)?;
            let inbound = decode_webhook(&body, &cfg).map_err(WebhookRejection::BadRequest)?;
            Ok(WebhookResponse::Messages(
                inbound.into_iter().map(to_wit).collect(),
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

    export!(NextcloudChannel);
}
