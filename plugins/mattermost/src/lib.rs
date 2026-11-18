//! A ZeroClaw WIT **channel** plugin: Mattermost.
//!
//! Polls a configured Mattermost channel with the v4 REST API
//! (`GET /channels/{id}/posts?since=<create_at_ms>`, a quick request so it never
//! stalls `send`) and delivers each new post to the agent; sends the agent's
//! replies with `POST /posts`. The server URL, bot token, and channel come from
//! the plugin's config section (`config_read`); all HTTP goes through the host's
//! `wasi:http` (`http_client`) with a static `Authorization: Bearer <token>`,
//! and TLS is performed host-side.
//!
//! The pure REST-API logic lives in [`mattermost`] (no wasm/http deps) and is
//! covered by a host `cargo test`; this file is the thin component shim that
//! wires it to the `channel-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod mattermost;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::mattermost::{
        build_send_body, extract_posts, me_url, parse_post, parse_self_user_id,
        parse_self_username, post_create_at, posts_poll_url, posts_url, split_recipient, url_path,
        Inbound, MattermostConfig,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::logging::{self, LogLevel, PluginAction, PluginEvent, PluginOutcome};
    use zeroclaw::plugin::{config, secrets};

    const PLUGIN_NAME: &str = "mattermost";
    /// Bound each connect well inside the host's 30 s call deadline, so an
    /// unreachable address fails the request instead of the whole call.
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    thread_local! {
        static CONFIG: RefCell<MattermostConfig> = RefCell::new(MattermostConfig::default());
        // Poll cursor: the max post `create_at` (Unix ms) delivered so far. Seeded
        // to "now" in `configure` so the channel backlog is ignored on startup.
        static CURSOR: Cell<i64> = const { Cell::new(0) };
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        // Bot user id — `self_handle` + the self-loop guard in `parse_post`.
        static SELF_USER_ID: RefCell<Option<String>> = const { RefCell::new(None) };
        // Bot `@username` — `self_addressed_mention`.
        static SELF_MENTION: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// Current Unix time in milliseconds (the cursor unit), or `0` if the clock
    /// is unavailable — a `0` seed just replays recent history once, harmlessly.
    fn now_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Blocking `GET` with the bot token; non-2xx is an error so the poll simply
    /// yields no message this tick.
    fn get_json(url: &str, token: &str) -> Result<Value, String> {
        let resp = waki::Client::new()
            .get(url)
            .connect_timeout(CONNECT_TIMEOUT)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!("GET {} returned {status}", url_path(url)));
        }
        resp.json::<Value>().map_err(|e| e.to_string())
    }

    /// Blocking `POST` of a JSON body with the bot token; returns `Err` on any
    /// non-2xx, surfacing the server's error body to `send`.
    fn post_json(url: &str, token: &str, body: &Value) -> Result<(), String> {
        let resp = waki::Client::new()
            .post(url)
            .connect_timeout(CONNECT_TIMEOUT)
            .header("Authorization", format!("Bearer {token}"))
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        if (200..300).contains(&status) {
            return Ok(());
        }
        let detail = resp
            .body()
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        Err(format!("mattermost createPost failed ({status}): {detail}"))
    }

    /// Best-effort `GET /users/me` → `(user_id, @username)`; `(None, None)` on any
    /// error so a missing or unreachable token never fails `configure`.
    fn fetch_self(cfg: &MattermostConfig) -> (Option<String>, Option<String>) {
        let token = cfg.token();
        if token.is_empty() || cfg.base_url().is_empty() {
            return (None, None);
        }
        match get_json(&me_url(cfg.base_url()), token) {
            Ok(v) => (parse_self_user_id(&v), parse_self_username(&v)),
            Err(_) => (None, None),
        }
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

    /// Report a config or secret read the host refused or could not serve,
    /// naming the key and the error kind, never a value.
    fn report_read_failure(key: &str, kind: &str) {
        logging::log_record(
            LogLevel::Warn,
            &PluginEvent {
                function_name: "mattermost::configure".to_string(),
                action: PluginAction::Fail,
                outcome: Some(PluginOutcome::Failure),
                duration_ms: None,
                attrs: None,
                message: format!("mattermost: could not read {key}: {kind}"),
            },
        );
    }

    /// The fixed name of a `config.get` failure; the variants carry no payload.
    fn config_error_kind(error: config::ConfigError) -> &'static str {
        match error {
            config::ConfigError::AccessDenied => "access denied",
            config::ConfigError::Unavailable => "unavailable",
        }
    }

    /// The fixed name of a `secrets.get` failure; the variants carry no payload.
    fn secret_error_kind(error: secrets::SecretError) -> &'static str {
        match error {
            secrets::SecretError::AccessDenied => "access denied",
            secrets::SecretError::NotFound => "not found",
            secrets::SecretError::Unavailable => "unavailable",
        }
    }

    /// The instance's typed config, read when the host configures the
    /// instance. `config.get` serves the public settings; the schema's
    /// `x-secret` values reach the plugin only through `secrets.get`. A read
    /// the host refuses is logged and leaves its field at the default, so a
    /// misconfigured instance stays inert rather than half-configured.
    fn load_config() -> MattermostConfig {
        let public = config::get().unwrap_or_else(|error| {
            report_read_failure("config", config_error_kind(error));
            String::new()
        });
        let mut cfg = MattermostConfig::from_json(&public);
        cfg.bot_token = secrets::get("bot_token")
            .map_err(|error| report_read_failure("bot_token", secret_error_kind(error)))
            .ok();
        cfg
    }

    struct MattermostChannel;

    impl PluginInfo for MattermostChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for MattermostChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure() -> Result<(), String> {
            let cfg = load_config();
            // Ignore backlog: only deliver posts created after configuration.
            CURSOR.with(|c| c.set(now_millis()));
            let (user_id, mention) = fetch_self(&cfg);
            SELF_USER_ID.with(|u| *u.borrow_mut() = user_id);
            SELF_MENTION.with(|m| *m.borrow_mut() = mention);
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            let token = cfg.token();
            if token.is_empty() {
                return Err("mattermost: no bot_token configured".to_string());
            }
            let (channel_id, root_id) = split_recipient(&message.recipient);
            let body = build_send_body(&channel_id, &message.content, root_id.as_deref());
            post_json(&posts_url(cfg.base_url()), token, &body)
        }

        fn poll_message() -> Option<InboundMessage> {
            // Drain buffered posts before making another network round-trip.
            if let Some(inb) = BUFFER.with(|b| b.borrow_mut().pop_front()) {
                return Some(to_wit(inb));
            }
            let cfg = CONFIG.with(|c| c.borrow().clone());
            let token = cfg.token();
            if token.is_empty() {
                return None;
            }
            let channel_id = cfg.channel_id()?;
            let since = CURSOR.with(Cell::get);
            let url = posts_poll_url(cfg.base_url(), &channel_id, since);
            let resp = get_json(&url, token).ok()?;
            let posts = extract_posts(&resp);
            if posts.is_empty() {
                return None;
            }
            let self_id = SELF_USER_ID
                .with(|u| u.borrow().clone())
                .unwrap_or_default();
            let thread_replies = cfg.thread_replies();
            let mut max_create = since;
            for post in &posts {
                let create_at = post_create_at(post);
                max_create = max_create.max(create_at);
                // `since` is inclusive on Mattermost and thread-context posts can
                // predate the cursor; skip anything at/before it to avoid dupes.
                if create_at <= since {
                    continue;
                }
                if let Some(inb) = parse_post(post, &self_id, thread_replies) {
                    BUFFER.with(|b| b.borrow_mut().push_back(inb));
                }
            }
            CURSOR.with(|c| c.set(max_create));
            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::SELF_HANDLE
                | ChannelCapabilities::SELF_ADDRESSED_MENTION
        }

        fn health_check() -> bool {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            !cfg.token().is_empty() && fetch_self(&cfg).0.is_some()
        }

        fn self_handle() -> Option<String> {
            SELF_USER_ID.with(|u| u.borrow().clone())
        }

        fn self_addressed_mention() -> Option<String> {
            SELF_MENTION.with(|m| m.borrow().clone())
        }

        // ── capability-gated stubs (documented WIT defaults) ──
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

        fn parse_webhook(_request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            Err(WebhookRejection::BadRequest(
                "this channel does not serve webhooks".to_string(),
            ))
        }
    }

    export!(MattermostChannel);
}
