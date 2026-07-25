//! A ZeroClaw WIT **channel** plugin: Reddit (OAuth2 bot).
//!
//! Exchanges a refresh token for a short-lived access token
//! (`POST www.reddit.com/api/v1/access_token`, HTTP Basic `client_id:secret`,
//! `grant_type=refresh_token`), long-polls the inbox for unread mentions, DMs,
//! and comment replies (`GET oauth.reddit.com/message/unread`, short
//! non-blocking polls so it never stalls `send`), marks the batch read
//! (`POST /api/read_message`), and replies as a threaded comment
//! (`POST /api/comment`) or a DM (`POST /api/compose`). Credentials come from the
//! plugin's config section (`config_read`); all HTTP goes through the host's
//! `wasi:http` (`http_client`), which performs TLS host-side. Every request
//! carries the required `User-Agent`.
//!
//! The pure OAuth2/REST logic lives in [`reddit`] (no wasm/http deps) and is
//! covered by a host `cargo test`; this file is the thin component shim that
//! wires it to the `channel-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod reddit;

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

    use crate::reddit::{
        basic_auth_header, extract_children, is_thing_fullname, item_fullname, join_fullnames,
        parse_item, parse_token_response, token_form, Inbound, RedditConfig, REDDIT_API_BASE,
        REDDIT_TOKEN_URL, UNREAD_LIMIT, USER_AGENT,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "reddit";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const DEFAULT_DM_SUBJECT: &str = "Message from ZeroClaw";

    thread_local! {
        static CONFIG: RefCell<RedditConfig> = RefCell::new(RedditConfig::default());
        // Cached OAuth2 access token; cleared and refreshed on a 401.
        static TOKEN: RefCell<Option<String>> = const { RefCell::new(None) };
        static BUFFER: RefCell<VecDeque<Inbound>> = RefCell::new(VecDeque::new());
        static SELF_HANDLE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// `GET` with a `Bearer` token and the required `User-Agent` → `(status,
    /// body)`. The body is parsed even on error responses (Reddit returns JSON
    /// errors), so a caller can inspect the status for a 401 re-auth.
    fn get_json(url: &str, token: &str) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("User-Agent", USER_AGENT)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().map_err(|e| e.to_string())?;
        Ok((status, val))
    }

    /// `POST` a `application/x-www-form-urlencoded` body with a full
    /// `Authorization` header value (`Basic …` for the token endpoint, `Bearer …`
    /// for the API) and the required `User-Agent` → `(status, body)`. Write
    /// endpoints (`read_message`, `comment`, `compose`) may return an empty body;
    /// it is parsed best-effort and falls back to `Null`.
    fn post_form(url: &str, auth: &str, form: &[(&str, String)]) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", auth)
            .header("User-Agent", USER_AGENT)
            .form(form)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().unwrap_or(Value::Null);
        Ok((status, val))
    }

    /// Exchange the refresh token for a fresh access token and cache it (used at
    /// load time and to re-auth after a 401).
    fn refresh_access_token(cfg: &RedditConfig) -> Result<String, String> {
        let auth = basic_auth_header(cfg.client_id.trim(), &cfg.client_secret);
        let form = token_form(cfg.refresh_token.trim());
        let (status, val) = post_form(REDDIT_TOKEN_URL, &auth, &form)?;
        if status >= 400 {
            return Err(format!("reddit token refresh failed ({status}): {val}"));
        }
        let token = parse_token_response(&val)
            .ok_or_else(|| format!("reddit token: unexpected response: {val}"))?;
        TOKEN.with(|t| *t.borrow_mut() = Some(token.clone()));
        Ok(token)
    }

    /// Return the cached access token, authenticating on first use.
    fn ensure_token(cfg: &RedditConfig) -> Result<String, String> {
        if let Some(t) = TOKEN.with(|t| t.borrow().clone()) {
            return Ok(t);
        }
        refresh_access_token(cfg)
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

    struct RedditChannel;

    impl PluginInfo for RedditChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for RedditChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = RedditConfig::from_json(&config);
            // The bot's own handle is just the configured username (no lookup).
            let handle = {
                let u = cfg.username.trim();
                if u.is_empty() {
                    None
                } else {
                    Some(u.to_string())
                }
            };
            SELF_HANDLE.with(|h| *h.borrow_mut() = handle);
            // Warm the access token (best effort) so the first send/poll is fast;
            // missing or unreachable credentials never fail configure.
            if cfg.has_credentials() {
                let _ = refresh_access_token(&cfg);
            }
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.has_credentials() {
                return Err(
                    "reddit: no client_id/client_secret/refresh_token configured".to_string()
                );
            }
            let token = ensure_token(&cfg)?;

            // A fullname recipient (t1_/t3_/t4_) is a threaded comment reply;
            // anything else is a username to DM.
            let (url, form) = if is_thing_fullname(&message.recipient) {
                (
                    format!("{REDDIT_API_BASE}/api/comment"),
                    vec![
                        ("thing_id", message.recipient.clone()),
                        ("text", message.content.clone()),
                    ],
                )
            } else {
                let subject = message
                    .subject
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| DEFAULT_DM_SUBJECT.to_string());
                (
                    format!("{REDDIT_API_BASE}/api/compose"),
                    vec![
                        ("to", message.recipient.clone()),
                        ("subject", subject),
                        ("text", message.content.clone()),
                    ],
                )
            };

            let (status, val) = post_form(&url, &format!("Bearer {token}"), &form)?;
            if status == 401 {
                // Access token expired — re-auth once and retry.
                TOKEN.with(|t| *t.borrow_mut() = None);
                let token = refresh_access_token(&cfg)?;
                let (status, val) = post_form(&url, &format!("Bearer {token}"), &form)?;
                if status >= 400 {
                    return Err(format!("reddit send failed ({status}): {val}"));
                }
                return Ok(());
            }
            if status >= 400 {
                return Err(format!("reddit send failed ({status}): {val}"));
            }
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(inb) = BUFFER.with(|b| b.borrow_mut().pop_front()) {
                return Some(to_wit(inb));
            }
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.has_credentials() {
                return None;
            }
            let token = ensure_token(&cfg).ok()?;
            let url = format!("{REDDIT_API_BASE}/message/unread?limit={UNREAD_LIMIT}");

            // One short poll; re-auth once on a 401.
            let (token, val) = {
                let (status, val) = get_json(&url, &token).ok()?;
                if status == 401 {
                    TOKEN.with(|t| *t.borrow_mut() = None);
                    let t = refresh_access_token(&cfg).ok()?;
                    let (status, val) = get_json(&url, &t).ok()?;
                    if status >= 400 {
                        return None;
                    }
                    (t, val)
                } else if status >= 400 {
                    return None;
                } else {
                    (token, val)
                }
            };

            let children = extract_children(&val);
            if children.is_empty() {
                return None;
            }

            // Buffer the deliverable items and collect every fetched fullname to
            // mark read — Reddit's server-side read state is the poll cursor, so
            // an item is never re-delivered once acknowledged.
            let mut read_ids: Vec<String> = Vec::new();
            for item in &children {
                if let Some(name) = item_fullname(item) {
                    read_ids.push(name);
                }
                if let Some(inb) = parse_item(item, &cfg.username, &cfg.subreddits) {
                    BUFFER.with(|b| b.borrow_mut().push_back(inb));
                }
            }

            // Advance the cursor: mark the batch read (best effort).
            if !read_ids.is_empty() {
                let form = [("id", join_fullnames(&read_ids))];
                let _ = post_form(
                    &format!("{REDDIT_API_BASE}/api/read_message"),
                    &format!("Bearer {token}"),
                    &form,
                );
            }

            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::SELF_HANDLE
                | ChannelCapabilities::SELF_ADDRESSED_MENTION
        }

        fn health_check() -> bool {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            cfg.has_credentials() && ensure_token(&cfg).is_ok()
        }

        fn self_handle() -> Option<String> {
            SELF_HANDLE.with(|h| h.borrow().clone())
        }

        // ── capability-gated stubs (documented WIT defaults) ──
        fn self_addressed_mention() -> Option<String> {
            SELF_HANDLE.with(|h| h.borrow().clone().map(|u| format!("u/{u}")))
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

    export!(RedditChannel);
}
