//! A ZeroClaw WIT **channel** plugin: Discord (Gateway over host `ws-client`).
//!
//! Discord delivers messages over a persistent WebSocket (the Gateway), which a
//! sandboxed plugin cannot open itself. This plugin drives the host's
//! `ws-client` import: the host owns the socket + TLS, and the plugin runs the
//! full Gateway protocol — IDENTIFY, heartbeats, RESUME, and MESSAGE_CREATE
//! dispatch — synchronously from `poll-message`, one non-blocking `ws-receive`
//! drain per poll. Replies go out over the REST API (`POST /channels/{id}/
//! messages`) through the host's `wasi:http` (`waki`). The bot token + settings
//! come from the plugin's config section (`config_read`).
//!
//! The protocol decisions live in [`discord::Session`] (a pure, host-tested
//! state machine driven by [`discord::Session::on_frame`]); this file is the
//! component shim that owns the socket handle, timers, and reconnect backoff,
//! and translates the machine's [`discord::FrameAction`]s into `ws-client` I/O.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod discord;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    use serde_json::Value;

    use crate::discord::{
        bot_user_id_from_token, build_heartbeat, build_send_body, chunk_text,
        close_code_from_reason, is_fatal_close_code, requires_new_session, DiscordConfig,
        FrameAction, Inbound, Session, MAX_MESSAGE_CHARS,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::ws_client::{self, WsEvent};

    const PLUGIN_NAME: &str = "discord";
    const PLUGIN_VERSION: &str = "0.1.0";

    /// Reconnect backoff bounds. A successful Hello handshake resets to the floor.
    const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);
    /// Frames drained per `poll-message` before yielding back to the host loop.
    const DRAIN_BATCH: usize = 64;

    /// Connection-scoped shim state: the pure session machine plus the socket
    /// handle, timers, and backoff the machine deliberately does not own.
    struct GatewayState {
        /// The pure protocol state machine (identity + resume coordinates).
        session: Session,
        /// Open `ws-client` handle, or `None` when disconnected.
        handle: Option<u64>,
        /// This connection intends to RESUME (vs a fresh IDENTIFY) at Hello.
        pending_resume: bool,
        last_hb: Option<Instant>,
        /// Earliest instant a reconnect may be attempted (backoff gate).
        next_connect_at: Option<Instant>,
        backoff: Duration,
        /// A fatal close (bad token/intents) was seen — stop reconnecting.
        fatal: bool,
        /// Token-derived `<@id>` mention form, available before the first READY.
        self_mention: Option<String>,
    }

    impl Default for GatewayState {
        fn default() -> Self {
            Self {
                session: Session::default(),
                handle: None,
                pending_resume: false,
                last_hb: None,
                next_connect_at: None,
                backoff: INITIAL_BACKOFF,
                fatal: false,
                self_mention: None,
            }
        }
    }

    thread_local! {
        static CONFIG: RefCell<DiscordConfig> = RefCell::new(DiscordConfig::default());
        static STATE: RefCell<GatewayState> = RefCell::new(GatewayState::default());
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
    }

    // ── HTTP (wasi:http via waki) ─────────────────────────────────────────────

    fn get_json_auth(url: &str, token: &str) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .get(url)
            .header("Authorization", format!("Bot {token}"))
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().unwrap_or(Value::Null);
        Ok((status, val))
    }

    fn post_json_auth(url: &str, token: &str, body: &Value) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("Bot {token}"))
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().unwrap_or(Value::Null);
        Ok((status, val))
    }

    /// Fetch a fresh Gateway WSS base via `GET /gateway/bot`. Returns `None` on
    /// any error or when the session-start limit is exhausted (the bot must wait
    /// — a fresh connect would just be rejected).
    fn fetch_fresh_gateway_url(cfg: &DiscordConfig) -> Option<String> {
        let (status, v) =
            get_json_auth(&format!("{}/gateway/bot", cfg.api_base), &cfg.bot_token).ok()?;
        if status != 200 {
            return None;
        }
        let remaining = v
            .get("session_start_limit")
            .and_then(|s| s.get("remaining"))
            .and_then(Value::as_u64);
        if remaining == Some(0) {
            return None;
        }
        v.get("url").and_then(Value::as_str).map(String::from)
    }

    // ── Connection lifecycle (shim side: sockets, timers, backoff) ────────────

    fn schedule_backoff(st: &mut GatewayState) {
        st.next_connect_at = Some(Instant::now() + st.backoff);
        st.backoff = (st.backoff * 2).min(MAX_BACKOFF);
    }

    /// Open (or resume) a Gateway connection when disconnected and past the
    /// backoff gate. Resumes to `resume_gateway_url` when a session is live,
    /// else fetches a fresh Gateway URL and IDENTIFYs.
    fn ensure_connected(st: &mut GatewayState, cfg: &DiscordConfig) {
        if let Some(at) = st.next_connect_at {
            if Instant::now() < at {
                return;
            }
        }
        st.next_connect_at = None;

        let can_resume = st.session.can_resume();
        // Resume URL (on a resume) wins, then a configured `gateway_url`
        // override, then live discovery via GET /gateway/bot.
        let base = if can_resume {
            st.session
                .resume_url
                .clone()
                .or_else(|| cfg.gateway_url.clone())
                .or_else(|| fetch_fresh_gateway_url(cfg))
        } else {
            cfg.gateway_url
                .clone()
                .or_else(|| fetch_fresh_gateway_url(cfg))
        };
        let Some(base) = base else {
            schedule_backoff(st);
            return;
        };

        let ws_url = format!("{base}/?v=10&encoding=json");
        match ws_client::ws_connect(&ws_url, &[]) {
            Ok(handle) => {
                st.handle = Some(handle);
                st.pending_resume = can_resume;
                st.last_hb = None;
            }
            Err(_) => schedule_backoff(st),
        }
    }

    /// Tear down for an op-7/op-9 reconnect. `keep_session` resumes vs a fresh
    /// IDENTIFY. Reconnects promptly (server-directed, no backoff).
    fn reconnect(st: &mut GatewayState, handle: u64, keep_session: bool) {
        ws_client::ws_close(handle);
        st.handle = None;
        if keep_session {
            st.session.mark_disconnected();
        } else {
            st.session.wipe();
        }
        st.next_connect_at = None;
    }

    /// Tear down after a transport error and reconnect with backoff.
    fn teardown_error(st: &mut GatewayState, handle: u64) {
        ws_client::ws_close(handle);
        st.handle = None;
        st.session.mark_disconnected();
        schedule_backoff(st);
    }

    /// Handle a `Closed` event. A fatal Discord close code (bad token/intents)
    /// stops reconnection; a new-session code wipes the session; otherwise
    /// reconnect with backoff. Absent a numeric code the close is transient.
    fn handle_close(st: &mut GatewayState, handle: u64, reason: &str) {
        ws_client::ws_close(handle);
        st.handle = None;
        st.session.mark_disconnected();
        if let Some(code) = close_code_from_reason(reason) {
            if is_fatal_close_code(code) {
                st.fatal = true;
                return;
            }
            if requires_new_session(code) {
                st.session.wipe();
            }
        }
        schedule_backoff(st);
    }

    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: 0,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct DiscordChannel;

    impl PluginInfo for DiscordChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for DiscordChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = DiscordConfig::from_json(&config);
            // Derive the bot id from the token so self-filtering + the mention
            // form work before the first READY (READY later confirms both).
            let bot_id = bot_user_id_from_token(&cfg.bot_token).unwrap_or_default();
            let mention = (!bot_id.is_empty()).then(|| format!("<@{bot_id}>"));
            STATE.with(|s| {
                let mut st = s.borrow_mut();
                *st = GatewayState::default();
                st.session.bot_user_id = bot_id;
                st.self_mention = mention;
            });
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            BUFFER.with(|b| b.borrow_mut().clear());
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if cfg.bot_token.is_empty() {
                return Err("discord: no bot_token configured".to_string());
            }
            // The recipient is a raw Discord channel ID; a thread is targeted by
            // its own channel ID, so no special reply/thread handling is needed.
            let url = format!("{}/channels/{}/messages", cfg.api_base, message.recipient);
            for chunk in chunk_text(&message.content, MAX_MESSAGE_CHARS) {
                let (status, resp) =
                    post_json_auth(&url, &cfg.bot_token, &build_send_body(&chunk))?;
                if !(200..300).contains(&status) {
                    return Err(format!("discord send failed ({status}): {resp}"));
                }
            }
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(inb) = BUFFER.with(|b| b.borrow_mut().pop_front()) {
                return Some(to_wit(inb));
            }
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if cfg.bot_token.is_empty() {
                return None;
            }

            STATE.with(|s| {
                let mut guard = s.borrow_mut();
                let st: &mut GatewayState = &mut guard;
                if st.fatal {
                    return;
                }
                let Some(handle) = st.handle else {
                    ensure_connected(st, &cfg);
                    return;
                };
                // Heartbeat once the interval has elapsed (only after Hello, i.e.
                // once the session has adopted an interval).
                if st.session.hello_seen() {
                    let interval = Duration::from_millis(st.session.hb_interval_ms);
                    let due = st.last_hb.is_none_or(|t| t.elapsed() >= interval);
                    if due {
                        if ws_client::ws_send_text(handle, &build_heartbeat(st.session.seq))
                            .is_err()
                        {
                            teardown_error(st, handle);
                            return;
                        }
                        st.last_hb = Some(Instant::now());
                    }
                }
                // Drain a bounded batch of frames, applying each machine action.
                for _ in 0..DRAIN_BATCH {
                    match ws_client::ws_receive(handle) {
                        Ok(WsEvent::Text(t)) => {
                            match st.session.on_frame(&cfg, &t, st.pending_resume) {
                                FrameAction::None => {}
                                FrameAction::Handshake(payload) => {
                                    let _ = ws_client::ws_send_text(handle, &payload);
                                    st.last_hb = Some(Instant::now());
                                    st.backoff = INITIAL_BACKOFF;
                                }
                                FrameAction::Send(payload) => {
                                    let _ = ws_client::ws_send_text(handle, &payload);
                                    st.last_hb = Some(Instant::now());
                                }
                                FrameAction::Emit(inb) => {
                                    BUFFER.with(|b| b.borrow_mut().push_back(inb));
                                }
                                FrameAction::Reconnect { keep_session } => {
                                    reconnect(st, handle, keep_session);
                                    break;
                                }
                            }
                        }
                        Ok(WsEvent::Idle) => break,
                        Ok(WsEvent::Closed(r)) => {
                            handle_close(st, handle, &r);
                            break;
                        }
                        Err(_) => {
                            teardown_error(st, handle);
                            break;
                        }
                    }
                }
            });

            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::SELF_ADDRESSED_MENTION
        }

        fn health_check() -> bool {
            // A live-connection check would need a blocking REST round-trip on
            // every call; report configured-ness instead (token present).
            !CONFIG.with(|c| c.borrow().bot_token.is_empty())
        }

        fn self_handle() -> Option<String> {
            STATE.with(|s| s.borrow().session.self_handle.clone())
        }

        fn self_addressed_mention() -> Option<String> {
            STATE.with(|s| s.borrow().self_mention.clone())
        }

        // ── capability-gated stubs (documented WIT defaults) ──
        fn drop_self_message(_msg: InboundMessage) -> bool {
            // Self messages are already filtered in `message_create_to_inbound`.
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

    export!(DiscordChannel);
}
