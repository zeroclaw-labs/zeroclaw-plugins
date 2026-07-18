//! A ZeroClaw WIT **channel** plugin: WeChat (personal iLink Bot).
//!
//! Long-polls the iLink Bot API (`getupdates`, with a short server-hold hint so
//! it never stalls `send`) and delivers each inbound text message to the agent;
//! sends the agent's replies with `sendmessage`. The channel settings and the
//! iLink session token come from the plugin's config section (`config_read`);
//! all HTTP goes through the host's `wasi:http` (`http_client`), which performs
//! TLS host-side.
//!
//! Session note: the native `wechat` channel establishes its iLink session
//! interactively (render a QR code to a TTY, long-poll for the phone scan) and
//! persists the resulting `bot_token`. That flow cannot run inside the wasm
//! sandbox, so this plugin expects the already-established token via its
//! `bot_token` config key (see README). With no token it is inert: `poll`
//! returns `none` and `send` returns a clear error.
//!
//! The pure iLink logic lives in [`wechat`] (no wasm/http deps) and is covered
//! by a host `cargo test`; this file is the thin component shim that wires it to
//! the `channel-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod wechat;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, VecDeque};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::wechat::{
        build_getconfig_body, build_getupdates_body, build_send_body, context_token_of,
        extract_msgs, is_session_expired, next_cursor, parse_message, response_error_code,
        sender_id, to_plain_text, wechat_uin, CHANNEL_VERSION, Inbound, WeChatConfig,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "wechat";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    /// Server-hold hint (ms) for `getupdates`. `0` asks the server to return
    /// immediately (a short poll), so a blocking call never stalls an
    /// interleaved `send`; if the server ignores the hint it falls back to its
    /// own long-poll window.
    const GETUPDATES_LONGPOLL_MS: u64 = 0;
    /// Connect-phase timeout for every API call. `waki` can only bound the
    /// connect (not the response body), which is enough to fail fast on a dead
    /// endpoint.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    thread_local! {
        static CONFIG: RefCell<WeChatConfig> = RefCell::new(WeChatConfig::default());
        /// The iLink session token (from `config.bot_token`); `None` == unsessioned.
        static TOKEN: RefCell<Option<String>> = const { RefCell::new(None) };
        /// Persisted `get_updates_buf` cursor.
        static CURSOR: RefCell<String> = const { RefCell::new(String::new()) };
        /// Drained one message per `poll_message`.
        static BUFFER: RefCell<VecDeque<Inbound>> = RefCell::new(VecDeque::new());
        /// Per-sender `context_token` cache, harvested on poll and read on send.
        static CONTEXT_TOKENS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
        /// Monotonic counter feeding per-request `client_id` / `X-WECHAT-UIN`.
        static SEQ: Cell<u64> = const { Cell::new(0) };
        /// WeChat has no user-facing `@handle`; kept for the stub surface.
        static SELF_HANDLE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    fn ilink_url(cfg: &WeChatConfig, endpoint: &str) -> String {
        format!("{}/ilink/bot/{}", cfg.api_base(), endpoint)
    }

    /// A wall-clock + counter seed, unique per request within a run.
    fn next_seed() -> u64 {
        let seq = SEQ.with(|s| {
            let n = s.get().wrapping_add(1);
            s.set(n);
            n
        });
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        nanos ^ seq.rotate_left(17)
    }

    fn next_client_id() -> String {
        format!("zeroclaw-{}", next_seed())
    }

    /// `POST` a JSON body to an iLink endpoint with the bot-token auth headers →
    /// `(status, parsed-body)`. The body is parsed even on error responses (iLink
    /// returns JSON `ret`/`errcode` errors) so the caller can inspect them.
    fn post_ilink(url: &str, token: &str, body: &Value) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("AuthorizationType", "ilink_bot_token")
            .header("X-WECHAT-UIN", wechat_uin(next_seed()))
            .header("Authorization", format!("Bearer {token}"))
            .connect_timeout(CONNECT_TIMEOUT)
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().map_err(|e| e.to_string())?;
        Ok((status, val))
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

    struct WeChatChannel;

    impl PluginInfo for WeChatChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for WeChatChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = WeChatConfig::from_json(&config);
            // Best-effort session bootstrap: the interactive QR login can't run
            // in-sandbox, so the "session" is the token the operator supplied.
            // A missing token never fails load — it is surfaced at `send` time
            // and makes `poll` inert.
            let token = if cfg.has_session() {
                Some(cfg.token().to_string())
            } else {
                None
            };
            SELF_HANDLE.with(|h| *h.borrow_mut() = None);
            TOKEN.with(|t| *t.borrow_mut() = token);
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let token = TOKEN.with(|t| t.borrow().clone());
            let Some(token) = token else {
                return Err(
                    "wechat: no iLink session — establish one via a one-time `zeroclaw` QR \
                     login and set `bot_token` in this channel's config (see README)"
                        .to_string(),
                );
            };
            let cfg = CONFIG.with(|c| c.borrow().clone());
            let to = &message.recipient;
            let context_token = CONTEXT_TOKENS
                .with(|m| m.borrow().get(to).cloned())
                .unwrap_or_default();
            let text = to_plain_text(&message.content);
            let client_id = next_client_id();
            let body = build_send_body(to, &text, &context_token, &client_id, CHANNEL_VERSION);
            let url = ilink_url(&cfg, "sendmessage");

            let (status, val) = post_ilink(&url, &token, &body)?;
            if status >= 400 {
                return Err(format!("wechat sendMessage failed ({status}): {val}"));
            }
            if let Some(code) = response_error_code(&val) {
                if is_session_expired(code) {
                    TOKEN.with(|t| *t.borrow_mut() = None);
                }
                return Err(format!("wechat sendMessage failed (errcode {code}): {val}"));
            }
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(inb) = BUFFER.with(|b| b.borrow_mut().pop_front()) {
                return Some(to_wit(inb));
            }
            let token = TOKEN.with(|t| t.borrow().clone())?;
            let cfg = CONFIG.with(|c| c.borrow().clone());

            let cursor = CURSOR.with(|c| c.borrow().clone());
            let body = build_getupdates_body(&cursor, GETUPDATES_LONGPOLL_MS, CHANNEL_VERSION);
            let url = ilink_url(&cfg, "getupdates");

            let (status, val) = post_ilink(&url, &token, &body).ok()?;
            if status >= 400 {
                return None;
            }
            if let Some(code) = response_error_code(&val) {
                // Session expiry means the token is dead until a new QR login;
                // drop it so we stop hammering the API (poll goes inert).
                if is_session_expired(code) {
                    TOKEN.with(|t| *t.borrow_mut() = None);
                }
                return None;
            }

            if let Some(nc) = next_cursor(&val) {
                CURSOR.with(|c| *c.borrow_mut() = nc);
            }

            let msgs = extract_msgs(&val);
            if msgs.is_empty() {
                return None;
            }
            for msg in &msgs {
                // Cache the per-sender context_token so a later `send` can thread.
                if let (Some(uid), Some(ctx)) = (sender_id(msg), context_token_of(msg)) {
                    CONTEXT_TOKENS.with(|m| m.borrow_mut().insert(uid, ctx));
                }
                if let Some(inb) = parse_message(msg, None) {
                    BUFFER.with(|b| b.borrow_mut().push_back(inb));
                }
            }
            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
        }

        fn health_check() -> bool {
            let token = TOKEN.with(|t| t.borrow().clone());
            let Some(token) = token else {
                return false;
            };
            let cfg = CONFIG.with(|c| c.borrow().clone());
            let url = ilink_url(&cfg, "getconfig");
            match post_ilink(&url, &token, &build_getconfig_body(CHANNEL_VERSION)) {
                Ok((status, val)) => {
                    status < 400
                        && response_error_code(&val).map_or(true, |code| !is_session_expired(code))
                }
                Err(_) => false,
            }
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

    export!(WeChatChannel);
}
