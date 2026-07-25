//! A ZeroClaw WIT **channel** plugin: Bluesky (AT Protocol).
//!
//! Authenticates with an app password (`com.atproto.server.createSession`),
//! polls `app.bsky.notification.listNotifications` for unread mentions/replies
//! (short, non-blocking polls so it never stalls `send`), marks them seen
//! (`app.bsky.notification.updateSeen`), and replies as threaded posts
//! (`com.atproto.repo.createRecord`). Credentials come from the plugin's config
//! section (`config_read`); all HTTP goes through the host's `wasi:http`
//! (`http_client`), which performs TLS host-side.
//!
//! The pure AT-Protocol logic lives in [`bluesky`] (no wasm/http deps) and is
//! covered by a host `cargo test`; this file is the thin component shim that
//! wires it to the `channel-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod bluesky;

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

    use crate::bluesky::{
        BlueskyConfig, Inbound, Session, build_create_session, build_send_body, build_update_seen,
        extract_notifications, latest_indexed_at, millis_to_rfc3339, notification_indexed_at,
        parse_notification, parse_session, truncate_post, xrpc_url, NSID_CREATE_RECORD,
        NSID_CREATE_SESSION, NSID_LIST_NOTIFICATIONS, NSID_UPDATE_SEEN,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "bluesky";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    /// Notifications fetched per poll. Small so a poll stays cheap and never
    /// stalls `send`; the buffer is drained one message per `poll_message`.
    const NOTIFICATION_LIMIT: u32 = 40;

    thread_local! {
        static CONFIG: RefCell<BlueskyConfig> = RefCell::new(BlueskyConfig::default());
        static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
        // Poll cursor: the latest `indexedAt` delivered so far. Anything at or
        // before it is treated as already-seen (belt-and-suspenders with the
        // server-side `isRead` flag / `updateSeen`).
        static CURSOR: RefCell<String> = const { RefCell::new(String::new()) };
        static BUFFER: RefCell<VecDeque<Inbound>> = RefCell::new(VecDeque::new());
        static SELF_HANDLE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// `GET` with a `Bearer` token → `(status, body)`. The body is parsed even on
    /// error responses (AT Protocol returns JSON errors), so a caller can inspect
    /// the status for a 401 re-auth.
    fn get_json(url: &str, token: &str) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().map_err(|e| e.to_string())?;
        Ok((status, val))
    }

    /// `POST` a JSON body, optionally with a `Bearer` token → `(status, body)`.
    fn post_json(url: &str, token: Option<&str>, body: &Value) -> Result<(u16, Value), String> {
        let mut req = waki::Client::new().post(url).json(body);
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req.send().map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().map_err(|e| e.to_string())?;
        Ok((status, val))
    }

    /// Authenticate and cache a fresh [`Session`] (used at load time and to
    /// re-auth after a 401).
    fn create_session(cfg: &BlueskyConfig) -> Result<Session, String> {
        let url = xrpc_url(&cfg.base_url(), NSID_CREATE_SESSION);
        let body = build_create_session(cfg.handle.trim(), &cfg.app_password);
        let (status, val) = post_json(&url, None, &body)?;
        if status >= 400 {
            return Err(format!("bluesky createSession failed ({status}): {val}"));
        }
        let session = parse_session(&val)
            .ok_or_else(|| format!("bluesky createSession: unexpected response: {val}"))?;
        SESSION.with(|s| *s.borrow_mut() = Some(session.clone()));
        Ok(session)
    }

    /// Return the cached session, authenticating on first use.
    fn ensure_session(cfg: &BlueskyConfig) -> Result<Session, String> {
        if let Some(s) = SESSION.with(|s| s.borrow().clone()) {
            return Ok(s);
        }
        create_session(cfg)
    }

    fn now_rfc3339() -> String {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        millis_to_rfc3339(millis)
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

    struct BlueskyChannel;

    impl PluginInfo for BlueskyChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for BlueskyChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = BlueskyConfig::from_json(&config);
            // Warm the session (best effort) so the bot's own handle/DID are
            // known; a missing or unreachable credential never fails configure.
            let handle = if cfg.has_credentials() {
                create_session(&cfg).ok().map(|s| {
                    if s.handle.is_empty() {
                        cfg.handle.trim().to_string()
                    } else {
                        s.handle
                    }
                })
            } else {
                None
            };
            SELF_HANDLE.with(|h| *h.borrow_mut() = handle);
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.has_credentials() {
                return Err("bluesky: no handle/app_password configured".to_string());
            }
            let session = ensure_session(&cfg)?;
            let url = xrpc_url(&cfg.base_url(), NSID_CREATE_RECORD);
            let text = truncate_post(&message.content);
            let created_at = now_rfc3339();

            let body = build_send_body(&session.did, &text, &message.recipient, &created_at);
            let (status, val) = post_json(&url, Some(&session.access_jwt), &body)?;
            if status == 401 {
                // Access token expired — re-auth once and retry with the fresh DID.
                SESSION.with(|s| *s.borrow_mut() = None);
                let session = create_session(&cfg)?;
                let body = build_send_body(&session.did, &text, &message.recipient, &created_at);
                let (status, val) = post_json(&url, Some(&session.access_jwt), &body)?;
                if status >= 400 {
                    return Err(format!("bluesky createRecord failed ({status}): {val}"));
                }
                return Ok(());
            }
            if status >= 400 {
                return Err(format!("bluesky createRecord failed ({status}): {val}"));
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
            let session = ensure_session(&cfg).ok()?;
            let url = format!(
                "{}?limit={}",
                xrpc_url(&cfg.base_url(), NSID_LIST_NOTIFICATIONS),
                NOTIFICATION_LIMIT
            );

            // One short poll; re-auth once on a 401.
            let (session, val) = {
                let (status, val) = get_json(&url, &session.access_jwt).ok()?;
                if status == 401 {
                    SESSION.with(|s| *s.borrow_mut() = None);
                    let s = create_session(&cfg).ok()?;
                    let (status, val) = get_json(&url, &s.access_jwt).ok()?;
                    if status >= 400 {
                        return None;
                    }
                    (s, val)
                } else if status >= 400 {
                    return None;
                } else {
                    (session, val)
                }
            };

            let notifs = extract_notifications(&val);
            if notifs.is_empty() {
                return None;
            }

            let prev_cursor = CURSOR.with(|c| c.borrow().clone());
            for notif in &notifs {
                // Client-side cursor: only deliver notifications newer than the
                // last one seen (guards against `updateSeen` propagation lag).
                if !prev_cursor.is_empty() && notification_indexed_at(notif) <= prev_cursor.as_str() {
                    continue;
                }
                if let Some(inb) = parse_notification(notif, &session.did) {
                    BUFFER.with(|b| b.borrow_mut().push_back(inb));
                }
            }

            // Advance the cursor and mark the batch seen (best effort).
            if let Some(latest) = latest_indexed_at(&notifs) {
                if latest > prev_cursor {
                    CURSOR.with(|c| *c.borrow_mut() = latest.clone());
                    let seen_url = xrpc_url(&cfg.base_url(), NSID_UPDATE_SEEN);
                    let seen_body = build_update_seen(&latest);
                    let _ = post_json(&seen_url, Some(&session.access_jwt), &seen_body);
                }
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
            cfg.has_credentials() && create_session(&cfg).is_ok()
        }

        fn self_handle() -> Option<String> {
            SELF_HANDLE.with(|h| h.borrow().clone())
        }

        // ── capability-gated stubs (documented WIT defaults) ──
        fn self_addressed_mention() -> Option<String> {
            SELF_HANDLE.with(|h| h.borrow().clone().map(|hdl| format!("@{hdl}")))
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

    export!(BlueskyChannel);
}
