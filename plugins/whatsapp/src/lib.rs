//! A ZeroClaw WIT **channel** plugin: WhatsApp Cloud (Meta Graph webhook).
//!
//! A **webhook** channel: it does not poll. The host serves `GET` + `POST` on
//! `/plugin/whatsapp` and hands each request to [`parse_webhook`], passing the
//! request line via two reserved lower-cased headers:
//!
//!   * `x-webhook-method` — `"GET"` or `"POST"`,
//!   * `x-webhook-query`  — the raw query string.
//!
//! **GET** is Meta's verification handshake
//! (`?hub.mode=subscribe&hub.verify_token=…&hub.challenge=…`): when the token
//! matches this channel's `verify_token`, the plugin returns exactly one
//! `InboundMessage` with `channel = "__webhook_reply__"` and `content` = the
//! `hub.challenge`, which the host echoes back verbatim (enqueuing nothing).
//!
//! **POST** is a message event: the plugin verifies the `X-Hub-Signature-256`
//! HMAC-SHA256 over the raw body with its `app_secret`, then decodes
//! `entry[].changes[].value.messages[]` into inbound text messages. A bad
//! signature returns `Err(reason)` so the host replies `401`.
//!
//! Replies are sent with `POST <api_base>/<phone_number_id>/messages` (Bearer
//! `access_token`) over the host's `wasi:http` (`waki`), which performs TLS
//! host-side. The pure, I/O-free logic lives in [`whatsapp`] and is covered by a
//! host `cargo test`; this file is the thin component shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod whatsapp;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;
    use std::time::Duration;

    use serde_json::Value;

    use crate::whatsapp::{
        build_send_body, decode_inbound, get_verification_challenge, health_url, send_url,
        verify_get_request, verify_signature, Inbound, WhatsAppConfig, WEBHOOK_PATH,
        WEBHOOK_REPLY_CHANNEL,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "whatsapp";
    const PLUGIN_VERSION: &str = "0.1.0";
    /// Connect-phase timeout for every Graph API call. `waki` can only bound the
    /// connect (not the response body), which is enough to fail fast on a dead
    /// endpoint.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    thread_local! {
        static CONFIG: RefCell<WhatsAppConfig> = RefCell::new(WhatsAppConfig::default());
    }

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

    /// Build the reserved challenge-echo reply: `channel = "__webhook_reply__"`,
    /// `content` = the exact body the host should send back (the verification
    /// challenge). The host replies `200` with `content` and enqueues nothing.
    fn webhook_reply(content: String) -> InboundMessage {
        InboundMessage {
            id: "whatsapp-webhook-verify".to_string(),
            sender: String::new(),
            reply_target: String::new(),
            content,
            channel: WEBHOOK_REPLY_CHANNEL.to_string(),
            channel_alias: None,
            timestamp: 0,
            thread_ts: None,
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

        fn configure(config: String) -> Result<(), String> {
            let cfg = WhatsAppConfig::from_json(&config);
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
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
            let cfg = CONFIG.with(|c| c.borrow().clone());
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

        fn parse_webhook(
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            let method = header_get(&headers, "x-webhook-method").unwrap_or_default();

            // ── Meta verification handshake (GET) ──
            if method.eq_ignore_ascii_case("GET") {
                let query = header_get(&headers, "x-webhook-query").unwrap_or_default();
                verify_get_request(&cfg, &query).map_err(WebhookRejection::Unauthorized)?;
                let challenge =
                    get_verification_challenge(&query).map_err(WebhookRejection::BadRequest)?;
                return Ok(vec![webhook_reply(challenge)]);
            }

            // ── Event webhook (POST) ──
            // Verify X-Hub-Signature-256 when an app_secret is configured. When
            // it is absent the check is skipped (mirrors the native channel,
            // which treats app_secret as optional); configuring it is strongly
            // recommended and documented in the README.
            let app_secret = cfg.app_secret();
            if !app_secret.is_empty() {
                let sig = header_get(&headers, "x-hub-signature-256").unwrap_or_default();
                if !verify_signature(app_secret, &body, &sig) {
                    return Err(WebhookRejection::Unauthorized(
                        "whatsapp: X-Hub-Signature-256 verification failed".to_string(),
                    ));
                }
            }

            let payload: Value = serde_json::from_slice(&body).map_err(|e| {
                WebhookRejection::BadRequest(format!("whatsapp: invalid JSON payload: {e}"))
            })?;
            let inbs = decode_inbound(&payload, None);
            Ok(inbs.into_iter().map(to_wit).collect())
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
