//! A ZeroClaw WIT **channel** plugin: Linq (Partner V3 API — iMessage/RCS/SMS).
//!
//! A **webhook** channel: it does not poll. The host serves `POST` on
//! `/plugin/linq` and hands each request to [`parse_webhook`]. When a
//! `signing_secret` is configured the plugin verifies the `X-Webhook-Signature`
//! HMAC-SHA256 over `"{X-Webhook-Timestamp}.{body}"` (a 300 s replay window)
//! before decoding events; a bad signature returns `Err(reason)` so the host
//! replies `401`. Linq has no GET verification handshake, so a GET is a no-op
//! acknowledgement.
//!
//! Replies are sent to the originating chat (`POST <base>/chats/<id>/messages`);
//! on a `404` (unknown chat) the plugin creates a new chat
//! (`POST <base>/chats`) from `from_phone`. TLS is performed host-side by the
//! `wasi:http` client (`waki`).
//!
//! The pure logic (config/signature/decode/body) lives in [`linq`] and is
//! host-`cargo test`ed; this file is the component shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod linq;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::linq::{
        build_create_chat_body, build_send_body, create_chat_url, parse_webhook_payload,
        send_message_url, verify_signature, Inbound, LinqConfig, WEBHOOK_PATH,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "linq";
    const PLUGIN_VERSION: &str = "0.1.0";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    thread_local! {
        static CONFIG: RefCell<LinqConfig> = RefCell::new(LinqConfig::default());
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
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

    fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    fn post_json_bearer(url: &str, token: &str, body: &serde_json::Value) -> Result<u16, String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .connect_timeout(CONNECT_TIMEOUT)
            .json(body)
            .send()
            .map_err(|e| format!("linq send failed: {e}"))?;
        Ok(resp.status_code())
    }

    struct LinqChannel;

    impl PluginInfo for LinqChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for LinqChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            CONFIG.with(|c| *c.borrow_mut() = LinqConfig::from_json(&config));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            let token = cfg.api_token();
            if token.is_empty() {
                return Err("linq: missing api_token in config".to_string());
            }

            // Try sending to the chat named by `recipient`.
            let body = build_send_body(&message.content);
            let status = post_json_bearer(&send_message_url(&message.recipient), token, &body)?;
            if (200..300).contains(&status) {
                return Ok(());
            }

            // 404 → create a new chat with `recipient` as the destination.
            if status == 404 {
                let from = cfg.from_phone();
                let create = build_create_chat_body(from, &message.recipient, &message.content);
                let cstatus = post_json_bearer(&create_chat_url(), token, &create)?;
                if (200..300).contains(&cstatus) {
                    return Ok(());
                }
                return Err(format!("linq create-chat failed (HTTP {cstatus})"));
            }

            Err(format!("linq send failed (HTTP {status})"))
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
            // Linq has no GET verification handshake; ack a GET with nothing.
            if method.eq_ignore_ascii_case("GET") {
                return Ok(Vec::new());
            }

            let cfg = CONFIG.with(|c| c.borrow().clone());
            // Verify the signature only when a signing secret is configured
            // (mirrors the native gateway).
            if let Some(secret) = cfg.signing_secret() {
                let timestamp = header_get(&headers, "x-webhook-timestamp").unwrap_or_default();
                let signature = header_get(&headers, "x-webhook-signature").unwrap_or_default();
                if !verify_signature(secret, &body, &timestamp, &signature, now_secs()) {
                    return Err(WebhookRejection::Unauthorized(
                        "linq: X-Webhook-Signature verification failed".to_string(),
                    ));
                }
            }

            let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
                WebhookRejection::BadRequest(format!("linq: invalid JSON payload: {e}"))
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

    export!(LinqChannel);
}
