//! A ZeroClaw WIT **channel** plugin: Mochat (self-hosted customer service).
//!
//! Polls the Mochat REST API (`GET /api/message/receive`, a short request each
//! call so it never stalls `send`) and delivers each inbound text message to the
//! agent; sends the agent's replies with `POST /api/message/send`. The API base
//! URL and token come from the plugin's config section (`config_read`); all HTTP
//! goes through the host's `wasi:http` (`http_client`), which performs TLS
//! host-side and carries the `Authorization: Bearer` credential.
//!
//! The pure REST logic lives in [`mochat`] (no wasm/http deps) and is covered by
//! a host `cargo test`; this file is the thin component shim that wires it to the
//! `channel-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod mochat;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::mochat::{
        DedupSet, Inbound, MochatConfig, build_send_body, extract_messages, health_url, is_send_ok,
        message_id, parse_message, receive_url, send_error, send_url,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "mochat";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    thread_local! {
        static CONFIG: RefCell<MochatConfig> = RefCell::new(MochatConfig::default());
        // Poll cursor: the platform id of the last delivered message, sent as
        // `?since_id=` on the next receive request.
        static CURSOR: RefCell<Option<String>> = const { RefCell::new(None) };
        static BUFFER: RefCell<VecDeque<Inbound>> = RefCell::new(VecDeque::new());
        // Belt-and-suspenders with `since_id`: never re-deliver a message id we
        // have already handed out, even if the server ignores the cursor.
        static DEDUP: RefCell<DedupSet> = RefCell::new(DedupSet::default());
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn get_json(url: &str, token: &str) -> Result<Value, String> {
        waki::Client::new()
            .get(url)
            .header("Authorization", bearer(token))
            .send()
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .map_err(|e| e.to_string())
    }

    fn post_json(url: &str, token: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .header("Authorization", bearer(token))
            .json(body)
            .send()
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .map_err(|e| e.to_string())
    }

    /// Current Unix time in milliseconds; used to stamp messages the server did
    /// not timestamp (the native channel likewise stamps `now()`).
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn to_wit(inb: Inbound) -> InboundMessage {
        let timestamp = if inb.timestamp != 0 {
            inb.timestamp
        } else {
            now_ms()
        };
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct MochatChannel;

    impl PluginInfo for MochatChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for MochatChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = MochatConfig::from_json(&config);
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.has_credentials() {
                return Err("mochat: no api_url/api_token configured".to_string());
            }
            let url = send_url(cfg.base_url());
            let body = build_send_body(&message.recipient, &message.content);
            let resp = post_json(&url, &cfg.api_token, &body)?;
            if !is_send_ok(&resp) {
                return Err(send_error(&resp));
            }
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            // Drain the buffer first; only hit the network when it is empty.
            if let Some(inb) = BUFFER.with(|b| b.borrow_mut().pop_front()) {
                return Some(to_wit(inb));
            }
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.has_credentials() {
                return None;
            }
            let since = CURSOR.with(|c| c.borrow().clone());
            let url = receive_url(cfg.base_url(), since.as_deref());
            let resp = get_json(&url, &cfg.api_token).ok()?;
            let messages = extract_messages(&resp);
            if messages.is_empty() {
                return None;
            }
            for msg in &messages {
                let mid = message_id(msg);
                // Dedup check first (matches the native ordering): mark the id
                // seen even for messages later skipped for empty content.
                if DEDUP.with(|d| d.borrow_mut().is_duplicate(&mid)) {
                    continue;
                }
                if let Some(inb) = parse_message(msg) {
                    BUFFER.with(|b| b.borrow_mut().push_back(inb));
                    // Advance the cursor only for delivered messages, as the
                    // native poller does after a successful send.
                    if !mid.is_empty() {
                        CURSOR.with(|c| *c.borrow_mut() = Some(mid));
                    }
                }
            }
            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
        }

        fn health_check() -> bool {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.has_credentials() {
                return false;
            }
            let url = health_url(cfg.base_url());
            match waki::Client::new()
                .get(&url)
                .header("Authorization", bearer(&cfg.api_token))
                .send()
            {
                Ok(r) => (200..300).contains(&r.status_code()),
                Err(_) => false,
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

        fn webhook_path() -> Option<String> {
            None
        }

        fn parse_webhook(
            _headers: Vec<(String, String)>,
            _body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            Err(WebhookRejection::BadRequest(
                "this channel does not serve webhooks".to_string(),
            ))
        }
    }

    export!(MochatChannel);
}
