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

    use std::cell::{Cell, RefCell};
    use std::time::Duration;

    use crate::webhook::{
        build_outgoing, parse_incoming, verify_signature, Inbound, WebhookConfig, WEBHOOK_PATH,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "webhook";
    const PLUGIN_VERSION: &str = "0.1.0";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    thread_local! {
        static CONFIG: RefCell<WebhookConfig> = RefCell::new(WebhookConfig::default());
        /// Monotonic inbound counter for the message id (`webhook_<seq>`),
        /// mirroring the native channel's sequence.
        static SEQ: Cell<u64> = const { Cell::new(0) };
    }

    fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    fn to_wit(inb: Inbound) -> InboundMessage {
        let seq = SEQ.with(|c| {
            let v = c.get();
            c.set(v.wrapping_add(1));
            v
        });
        InboundMessage {
            id: format!("webhook_{seq}"),
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

        fn configure(config: String) -> Result<(), String> {
            CONFIG.with(|c| *c.borrow_mut() = WebhookConfig::from_json(&config));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            // No outbound URL configured → drop silently (matches the native
            // channel, which logs and returns Ok).
            let Some(url) = cfg.send_url().map(str::to_string) else {
                return Ok(());
            };
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
            if let Some(auth) = cfg.auth_header() {
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

        fn parse_webhook(
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            let method = header_get(&headers, "x-webhook-method").unwrap_or_default();
            // Generic webhook has no GET verification; ack a GET with nothing.
            if method.eq_ignore_ascii_case("GET") {
                return Ok(Vec::new());
            }

            let cfg = CONFIG.with(|c| c.borrow().clone());
            let signature = header_get(&headers, "x-webhook-signature");
            if !verify_signature(cfg.secret(), &body, signature.as_deref()) {
                return Err(WebhookRejection::Unauthorized(
                    "webhook: X-Webhook-Signature verification failed".to_string(),
                ));
            }

            let inbound = parse_incoming(&body).map_err(WebhookRejection::BadRequest)?;
            Ok(vec![to_wit(inbound)])
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
