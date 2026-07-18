//! A ZeroClaw WIT **channel** plugin: WATI (WhatsApp Business API).
//!
//! A **webhook** channel: it does not poll. The host serves `GET` + `POST` on
//! `/plugin/wati` and hands each request to [`parse_webhook`], passing the
//! request line via two reserved lower-cased headers:
//!
//!   * `x-webhook-method` — `"GET"` or `"POST"`,
//!   * `x-webhook-query`  — the raw query string.
//!
//! **GET** is WATI's verification handshake (`?hub.challenge=…`): the plugin
//! returns exactly one `InboundMessage` with `channel = "__webhook_reply__"` and
//! `content` = the `hub.challenge`, which the host echoes back verbatim. WATI
//! sends no `hub.verify_token`, so (like the native gateway) there is no token
//! check.
//!
//! **POST** is a message event. WATI does not sign its webhooks and the native
//! gateway performs no authenticity check on the body, so this plugin does not
//! either — the host gates senders via `peer_groups`. See the README.
//!
//! Replies are sent with `POST <api_base>/api/ext/v3/conversations/messages/text`
//! (Bearer `api_token`) over the host's `wasi:http` (`waki`).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod wati;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;
    use std::time::Duration;

    use crate::wati::{
        build_send_body, build_target, extract_challenge, parse_webhook_payload, send_url, Inbound,
        WatiConfig, WEBHOOK_PATH, WEBHOOK_REPLY_CHANNEL,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "wati";
    const PLUGIN_VERSION: &str = "0.1.0";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    thread_local! {
        static CONFIG: RefCell<WatiConfig> = RefCell::new(WatiConfig::default());
    }

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

    /// Build the reserved challenge-echo reply.
    fn webhook_reply(content: String) -> InboundMessage {
        InboundMessage {
            id: "wati-webhook-verify".to_string(),
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

    fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
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

        fn configure(config: String) -> Result<(), String> {
            CONFIG.with(|c| *c.borrow_mut() = WatiConfig::from_json(&config));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
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
            CONFIG.with(|c| !c.borrow().api_token().is_empty())
        }

        fn webhook_path() -> Option<String> {
            Some(WEBHOOK_PATH.to_string())
        }

        fn parse_webhook(
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            let method = header_get(&headers, "x-webhook-method").unwrap_or_default();

            // ── WATI verification handshake (GET) ──
            if method.eq_ignore_ascii_case("GET") {
                let query = header_get(&headers, "x-webhook-query").unwrap_or_default();
                let challenge = extract_challenge(&query).map_err(WebhookRejection::BadRequest)?;
                return Ok(vec![webhook_reply(challenge)]);
            }

            // ── Event webhook (POST) — no signature (WATI sends none) ──
            let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
                WebhookRejection::BadRequest(format!("wati: invalid JSON payload: {e}"))
            })?;
            Ok(parse_webhook_payload(&payload)
                .into_iter()
                .map(to_wit)
                .collect())
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
