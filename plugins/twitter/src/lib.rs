//! A ZeroClaw WIT **channel** plugin: X/Twitter.
//!
//! Polls the X API v2 mentions timeline (`GET /users/{id}/mentions`, a short
//! request each call so it never stalls `send`) and delivers each mention to
//! the agent; sends the agent's replies with `POST /tweets` (threading long
//! replies as a self-reply chain). The bearer token and settings come from the
//! plugin's config section (`config_read`); all HTTP goes through the host's
//! `wasi:http` (`http_client`), which performs TLS host-side and carries the
//! OAuth2 Bearer credential.
//!
//! The pure API logic lives in [`twitter`] (no wasm/http deps) and is covered
//! by a host `cargo test`; this file is the thin component shim that wires it to
//! the `channel-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod twitter;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;
    use std::collections::VecDeque;

    use serde_json::Value;

    use crate::twitter::{
        Inbound, TWEET_MAX_CHARS, TwitterConfig, advance_cursor, build_mentions_url, build_self_url,
        build_tweet_body, build_tweets_url, chunk_tweet, created_tweet_id, is_user_allowed,
        parse_mentions, parse_self_handle, parse_self_id, reply_id_from_recipient,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "twitter";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    thread_local! {
        static CONFIG: RefCell<TwitterConfig> = RefCell::new(TwitterConfig::default());
        static SINCE_ID: RefCell<Option<String>> = const { RefCell::new(None) };
        static BUFFER: RefCell<VecDeque<Inbound>> = RefCell::new(VecDeque::new());
        static SELF_ID: RefCell<Option<String>> = const { RefCell::new(None) };
        static SELF_HANDLE: RefCell<Option<String>> = const { RefCell::new(None) };
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

    /// Best-effort `GET /users/me` → `(id, @handle)`; `None` on any error so a
    /// missing or unreachable token never fails `configure`.
    fn fetch_self(cfg: &TwitterConfig) -> Option<(String, Option<String>)> {
        if cfg.bearer_token.is_empty() {
            return None;
        }
        let v = get_json(&build_self_url(&cfg.api_base_url), &cfg.bearer_token).ok()?;
        let id = parse_self_id(&v)?;
        Some((id, parse_self_handle(&v)))
    }

    /// The cached authenticated user id, fetching + caching it (and the handle)
    /// on first need. `None` when the token is missing or `users/me` is
    /// unreachable, so the poll loop simply yields nothing this tick.
    fn ensure_self_id(cfg: &TwitterConfig) -> Option<String> {
        if let Some(id) = SELF_ID.with(|s| s.borrow().clone()) {
            return Some(id);
        }
        let (id, handle) = fetch_self(cfg)?;
        SELF_ID.with(|s| *s.borrow_mut() = Some(id.clone()));
        if handle.is_some() {
            SELF_HANDLE.with(|h| *h.borrow_mut() = handle);
        }
        Some(id)
    }

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

    struct TwitterChannel;

    impl PluginInfo for TwitterChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for TwitterChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = TwitterConfig::from_json(&config);
            if let Some((id, handle)) = fetch_self(&cfg) {
                SELF_ID.with(|s| *s.borrow_mut() = Some(id));
                SELF_HANDLE.with(|h| *h.borrow_mut() = handle);
            }
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if cfg.bearer_token.is_empty() {
                return Err("twitter: no bearer_token configured".to_string());
            }
            let url = build_tweets_url(&cfg.api_base_url);
            // Reply to the target tweet; each subsequent chunk replies to the
            // tweet just created, forming a thread.
            let mut reply_to = reply_id_from_recipient(&message.recipient);
            for chunk in chunk_tweet(&message.content, TWEET_MAX_CHARS) {
                if chunk.trim().is_empty() {
                    continue;
                }
                let body = build_tweet_body(&chunk, reply_to.as_deref());
                let resp = post_json(&url, &cfg.bearer_token, &body)?;
                match created_tweet_id(&resp) {
                    Some(id) => reply_to = Some(id),
                    None => return Err(format!("twitter create tweet failed: {resp}")),
                }
            }
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(inb) = BUFFER.with(|b| b.borrow_mut().pop_front()) {
                return Some(to_wit(inb));
            }
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if cfg.bearer_token.is_empty() {
                return None;
            }
            let self_id = ensure_self_id(&cfg)?;
            let since = SINCE_ID.with(|s| s.borrow().clone());
            let url = build_mentions_url(&cfg.api_base_url, &self_id, since.as_deref());
            let resp = get_json(&url, &cfg.bearer_token).ok()?;

            // Advance the cursor even when everything is filtered out, so the
            // next poll doesn't re-fetch the same page.
            if let Some(cursor) = advance_cursor(&resp) {
                SINCE_ID.with(|s| *s.borrow_mut() = Some(cursor));
            }

            let mentions = parse_mentions(&resp);
            if mentions.is_empty() {
                return None;
            }
            let gated = !cfg.allowed_users.is_empty();
            for inb in mentions {
                // Never re-ingest the bot's own tweets (self-loop guard).
                if inb.sender == self_id {
                    continue;
                }
                let identities = [inb.sender.clone()];
                if !gated || is_user_allowed(&identities, &cfg.allowed_users) {
                    BUFFER.with(|b| b.borrow_mut().push_back(inb));
                }
            }
            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::SELF_HANDLE
        }

        fn health_check() -> bool {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            !cfg.bearer_token.is_empty() && fetch_self(&cfg).is_some()
        }

        fn self_handle() -> Option<String> {
            SELF_HANDLE.with(|h| h.borrow().clone())
        }

        // ── capability-gated stubs (documented WIT defaults) ──
        fn self_addressed_mention() -> Option<String> {
            SELF_HANDLE.with(|h| h.borrow().clone())
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

    export!(TwitterChannel);
}
