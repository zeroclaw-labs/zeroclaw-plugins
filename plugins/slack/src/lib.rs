//! A ZeroClaw WIT **channel** plugin: Slack (Events API webhook).
//!
//! This is a webhook-ingress channel, not a poller. The host serves
//! `GET`+`POST` on `/plugin/slack`; each inbound request is handed to
//! [`parse_webhook`] (in the pure [`slack`] core), which:
//!   - verifies the Slack request signature (`X-Slack-Signature` HMAC-SHA256
//!     over the raw body, with the 5-minute replay window) using the app
//!     `signing_secret` from config — authentication failures return the typed
//!     unauthorized rejection and enqueue nothing;
//!   - answers the `url_verification` handshake by echoing the `challenge`
//!     back in the HTTP response body (the `__webhook_reply__` convention);
//!   - decodes `event_callback` message events into inbound messages.
//!
//! Outbound replies go through `POST {api_base}/chat.postMessage` with a static
//! `Authorization: Bearer <bot_token>`; long text is chunked. All HTTP uses the
//! host's `wasi:http` (`http_client`) with TLS performed host-side.
//!
//! The interesting logic (config, signature check, payload decode, send-body
//! build, chunking) lives in [`slack`] with no wasm/http deps and is covered by
//! a host `cargo test`; this file is the thin component shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod slack;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::slack::{
        authenticate_webhook, build_send_body, chunk_text, decode_webhook, Inbound, SlackConfig,
        WebhookOutcome, CHANNEL, MAX_TEXT_CHARS, WEBHOOK_REPLY_CHANNEL,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "slack";
    const PLUGIN_VERSION: &str = "0.1.0";

    thread_local! {
        static CONFIG: RefCell<SlackConfig> = RefCell::new(SlackConfig::default());
    }

    /// Current Unix time in seconds — the unit the signature replay-window check
    /// expects. `0` on a broken clock, which just makes every request read as
    /// stale (fail-closed).
    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Stamp a core [`Inbound`] with the WIT `inbound-message` fields.
    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp: inb.timestamp,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    /// The single-message `__webhook_reply__` envelope: the host replies 200
    /// with `content` as the body and enqueues nothing.
    fn webhook_reply(content: String) -> InboundMessage {
        InboundMessage {
            id: String::new(),
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

    /// Blocking `POST` of a `chat.postMessage` body with the bot token. Slack
    /// returns HTTP 200 even for logical failures, so both the status and the
    /// `ok` field are checked; the API `error` is surfaced to `send`.
    fn post_message(
        cfg: &SlackConfig,
        channel: &str,
        text: &str,
        thread_ts: Option<&str>,
    ) -> Result<(), String> {
        let body = build_send_body(channel, text, thread_ts);
        let resp = waki::Client::new()
            .post(&cfg.post_message_url())
            .header("Authorization", format!("Bearer {}", cfg.bot_token()))
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let value = resp.json::<Value>().map_err(|e| e.to_string())?;
        if !(200..300).contains(&status) {
            return Err(format!("slack chat.postMessage HTTP {status}"));
        }
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            let detail = value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            return Err(format!("slack chat.postMessage failed: {detail}"));
        }
        Ok(())
    }

    struct SlackChannel;

    impl PluginInfo for SlackChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for SlackChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = SlackConfig::from_json(&config);
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if cfg.bot_token().is_empty() {
                return Err("slack: no bot_token configured".to_string());
            }
            let thread = message.thread_ts.as_deref();
            let chunks = chunk_text(&message.content, MAX_TEXT_CHARS);
            for chunk in chunks {
                post_message(&cfg, &message.recipient, &chunk, thread)?;
            }
            Ok(())
        }

        /// Webhook channel: inbound arrives via `parse_webhook`, never polling.
        fn poll_message() -> Option<InboundMessage> {
            None
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::WEBHOOK_INGRESS
        }

        fn health_check() -> bool {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            !cfg.bot_token().is_empty() && !cfg.signing_secret().is_empty()
        }

        fn webhook_path() -> Option<String> {
            Some(PLUGIN_NAME.to_string())
        }

        fn parse_webhook(
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            let secret = CONFIG.with(|c| c.borrow().signing_secret().to_string());
            if !authenticate_webhook(&secret, &headers, &body, now_secs())
                .map_err(WebhookRejection::Unauthorized)?
            {
                return Ok(Vec::new());
            }
            match decode_webhook(&body).map_err(WebhookRejection::BadRequest)? {
                WebhookOutcome::Challenge(challenge) => Ok(vec![webhook_reply(challenge)]),
                WebhookOutcome::Messages(msgs) => Ok(msgs.into_iter().map(to_wit).collect()),
            }
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

    export!(SlackChannel);
}
