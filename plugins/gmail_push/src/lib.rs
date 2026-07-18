//! A ZeroClaw WIT **channel** plugin: Gmail Pub/Sub push.
//!
//! A **webhook** channel: it does not poll. The host serves `POST` on
//! `/plugin/gmail_push`, which Google Pub/Sub calls whenever the watched mailbox
//! changes. The push carries only `{emailAddress, historyId}` (base64 in the
//! envelope) — **not** the message — so on each notification the plugin:
//!
//!   1. verifies `Authorization: Bearer <webhook_secret>` (when a secret is
//!      configured), else `Err` → the host replies `401`;
//!   2. decodes the Pub/Sub envelope → notification;
//!   3. calls the Gmail **History** API since the last-seen `historyId`
//!      (`thread_local` state), then **messages.get** for each new message, over
//!      the host's `wasi:http` (`waki`) with the `oauth_token`;
//!   4. returns the extracted From/Subject/body as inbound messages.
//!
//! The first notification just seeds `historyId` and returns nothing (mirrors the
//! native channel). Replies are sent via `messages.send`.
//!
//! On `configure` the plugin makes a best-effort `users.watch` registration so
//! Pub/Sub starts delivering; see the README for the renewal limitation.
//!
//! The pure logic (auth/decode/extract/body) lives in [`gmail_push`] and is
//! host-`cargo test`ed; this file is the I/O shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod gmail_push;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::{Cell, RefCell};
    use std::time::Duration;

    use serde_json::Value;

    use crate::gmail_push::{
        build_send_body, build_send_raw, build_watch_body, history_message_ids, history_url,
        message_to_inbound, message_url, parse_envelope, parse_notification, send_url,
        verify_bearer, watch_url, GmailMessage, GmailPushConfig, HistoryResponse, InboundFields,
        WEBHOOK_PATH,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "gmail_push";
    const PLUGIN_VERSION: &str = "0.1.0";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    thread_local! {
        static CONFIG: RefCell<GmailPushConfig> = RefCell::new(GmailPushConfig::default());
        /// Last Gmail `historyId` seen. `0` means "not yet seeded"; the first
        /// notification records it and returns no messages (native behavior).
        static LAST_HISTORY_ID: Cell<u64> = const { Cell::new(0) };
    }

    fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    fn to_wit(inb: InboundFields) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: inb.timestamp,
            thread_ts: inb.thread_ts,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    fn get_bearer(url: &str, token: &str) -> Result<Value, String> {
        waki::Client::new()
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .connect_timeout(CONNECT_TIMEOUT)
            .send()
            .map_err(|e| format!("gmail_push GET failed: {e}"))?
            .json::<Value>()
            .map_err(|e| format!("gmail_push: bad JSON response: {e}"))
    }

    fn post_json_bearer(url: &str, token: &str, body: &Value) -> Result<u16, String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .connect_timeout(CONNECT_TIMEOUT)
            .json(body)
            .send()
            .map_err(|e| format!("gmail_push POST failed: {e}"))?;
        Ok(resp.status_code())
    }

    /// Fetch new message IDs from the History API since `start_id`, following
    /// pagination. Returns the IDs and the newest `historyId` observed.
    fn fetch_history(token: &str, start_id: u64) -> Result<(Vec<String>, u64), String> {
        let mut ids = Vec::new();
        let mut newest = start_id;
        let mut page_token: Option<String> = None;
        loop {
            let v = get_bearer(&history_url(start_id, page_token.as_deref()), token)?;
            let resp: HistoryResponse = serde_json::from_value(v)
                .map_err(|e| format!("gmail_push: bad history response: {e}"))?;
            ids.extend(history_message_ids(&resp));
            if resp.history_id > newest {
                newest = resp.history_id;
            }
            match resp.next_page_token {
                Some(pt) => page_token = Some(pt),
                None => break,
            }
        }
        Ok((ids, newest))
    }

    fn fetch_message(token: &str, id: &str) -> Result<GmailMessage, String> {
        let v = get_bearer(&message_url(id), token)?;
        serde_json::from_value(v).map_err(|e| format!("gmail_push: bad message response: {e}"))
    }

    struct GmailPushChannel;

    impl PluginInfo for GmailPushChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for GmailPushChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = GmailPushConfig::from_json(&config);
            // Best-effort `users.watch` registration so Pub/Sub starts
            // delivering. Errors are ignored (external watch management may be in
            // use); renewal is not performed — see the README.
            let token = cfg.oauth_token().to_string();
            if !token.is_empty() && !cfg.topic.trim().is_empty() {
                let body = build_watch_body(cfg.topic.trim(), &cfg.label_filter);
                let _ = post_json_bearer(&watch_url(), &token, &body);
            }
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            let token = cfg.oauth_token();
            if token.is_empty() {
                return Err("gmail_push: missing oauth_token in config".to_string());
            }
            let subject = message.subject.as_deref().unwrap_or("ZeroClaw Message");
            let raw = build_send_raw(&message.recipient, subject, &message.content);
            let status = post_json_bearer(&send_url(), token, &build_send_body(&raw))?;
            if !(200..300).contains(&status) {
                return Err(format!("gmail_push send failed (HTTP {status})"));
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
            CONFIG.with(|c| !c.borrow().oauth_token().is_empty())
        }

        fn webhook_path() -> Option<String> {
            Some(WEBHOOK_PATH.to_string())
        }

        fn parse_webhook(
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            let method = header_get(&headers, "x-webhook-method").unwrap_or_default();
            // Pub/Sub delivers via POST; ack a GET with nothing.
            if method.eq_ignore_ascii_case("GET") {
                return Ok(Vec::new());
            }

            let cfg = CONFIG.with(|c| c.borrow().clone());

            // ── Shared-secret auth ──
            let auth = header_get(&headers, "authorization").unwrap_or_default();
            if !verify_bearer(cfg.webhook_secret(), &auth) {
                return Err(WebhookRejection::Unauthorized(
                    "gmail_push: unauthorized (bad or missing Bearer secret)".to_string(),
                ));
            }

            // ── Decode the Pub/Sub notification ──
            let envelope = parse_envelope(&body).map_err(WebhookRejection::BadRequest)?;
            let notification =
                parse_notification(&envelope.message).map_err(WebhookRejection::BadRequest)?;

            let token = cfg.oauth_token();
            if token.is_empty() {
                return Err(WebhookRejection::BadRequest(
                    "gmail_push: missing oauth_token in config".to_string(),
                ));
            }

            // First notification seeds the cursor and yields nothing.
            let last = LAST_HISTORY_ID.with(Cell::get);
            if last == 0 {
                LAST_HISTORY_ID.with(|c| c.set(notification.history_id));
                return Ok(Vec::new());
            }

            // Fetch messages added since the last-seen historyId.
            let (message_ids, newest) =
                fetch_history(token, last).map_err(WebhookRejection::BadRequest)?;
            LAST_HISTORY_ID.with(|c| c.set(newest.max(last)));

            let mut out = Vec::new();
            for id in message_ids {
                // A single message fetch failing must not drop the whole batch
                // (mirrors the native channel, which logs and continues).
                if let Ok(msg) = fetch_message(token, &id) {
                    if let Some(inb) = message_to_inbound(&msg) {
                        out.push(to_wit(inb));
                    }
                }
            }
            Ok(out)
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

    export!(GmailPushChannel);
}
