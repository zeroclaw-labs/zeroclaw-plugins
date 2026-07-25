//! A ZeroClaw WIT **channel** plugin: Gitea / Forgejo.
//!
//! Polls the instance's unread notifications (`GET /notifications`, a quick
//! request so it never stalls `send`), follows each issue/PR thread's latest
//! comment, and delivers new comments to the agent; sends the agent's replies as
//! issue/PR comments (`POST /repos/{owner}/{repo}/issues/{n}/comments`). The API
//! base URL and personal access token come from the channel's config section
//! (`config_read`); all HTTP goes through the host's `wasi:http` (`http_client`),
//! which performs TLS host-side and carries the `token` credential.
//!
//! This mirrors the built-in `git` channel's Gitea/Forgejo provider: it declares
//! `provides = "git"`, reads `[channels.git.<alias>]`, and stays inert unless
//! `provider` is `gitea`/`forgejo`. The inbound mapping (sender = author login,
//! reply target = `owner/repo#number`, id = `ghc_<comment_id>`, content = the
//! comment body) matches the native channel so the two are interchangeable.
//!
//! The pure REST/mapping logic lives in [`gitea`] (no wasm/http deps) and is
//! covered by a host `cargo test`; this file is the thin component shim that
//! wires it to the `channel-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod gitea;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::{HashSet, VecDeque};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::gitea::{
        build_comment_body, chunk_text, comment_to_inbound, create_comment_url, notifications_url,
        parse_self_login, rfc3339_to_unix, should_admit, unix_to_rfc3339, user_url, GiteaComment,
        GiteaConfig, Inbound, IssueRef, NotificationThread, COMMENT_MAX_CHARS, GITEA_USER_AGENT,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "gitea";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    /// Bound on the delivered-comment dedup set; cleared wholesale when full
    /// (the poll cursor already excludes anything older than the last tick).
    const SEEN_CAP: usize = 5_000;

    thread_local! {
        static CONFIG: RefCell<GiteaConfig> = RefCell::new(GiteaConfig::default());
        // Poll cursor: max notification `updated_at` (Unix seconds) delivered so
        // far. Seeded to "now" in `configure` so the backlog is ignored on start.
        static CURSOR: Cell<i64> = const { Cell::new(0) };
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        // Delivered comment ids — dedup at the inclusive `since` boundary.
        static SEEN: RefCell<HashSet<u64>> = RefCell::new(HashSet::new());
        // Bot login — self-loop guard, mention gate, and `self_handle`.
        static SELF_LOGIN: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// Current Unix time in seconds, or `0` if the clock is unavailable (which
    /// only replays a little recent history once, harmlessly).
    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn mark_seen(id: u64) {
        SEEN.with(|s| {
            let mut set = s.borrow_mut();
            if set.len() >= SEEN_CAP {
                set.clear();
            }
            set.insert(id);
        });
    }

    fn already_seen(id: u64) -> bool {
        SEEN.with(|s| s.borrow().contains(&id))
    }

    /// Blocking `GET` with the `token` credential; non-2xx is an error so the
    /// poll simply yields no message this tick.
    fn get_json(url: &str, token: &str) -> Result<Value, String> {
        let resp = waki::Client::new()
            .get(url)
            .header("Authorization", format!("token {token}"))
            .header("Accept", "application/json")
            .header("User-Agent", GITEA_USER_AGENT)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!("GET {url} returned {status}"));
        }
        resp.json::<Value>().map_err(|e| e.to_string())
    }

    /// Blocking `POST` of a JSON body with the `token` credential; `Err` on any
    /// non-2xx, surfacing the server's error body to `send`.
    fn post_json(url: &str, token: &str, body: &Value) -> Result<(), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("token {token}"))
            .header("Accept", "application/json")
            .header("User-Agent", GITEA_USER_AGENT)
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
        Err(format!("gitea create comment failed ({status}): {detail}"))
    }

    /// Best-effort `GET /user` → the bot's login; `None` on any error so a
    /// missing or unreachable token never fails `configure`.
    fn fetch_self_login(cfg: &GiteaConfig) -> Option<String> {
        let base = cfg.base_url()?;
        if cfg.token().is_empty() {
            return None;
        }
        let v = get_json(&user_url(&base), cfg.token()).ok()?;
        parse_self_login(&v)
    }

    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target.clone(),
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: inb.timestamp,
            // Conversation context is issue/PR-scoped: replies on the same
            // issue/PR share a thread.
            thread_ts: Some(inb.reply_target),
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct GiteaChannel;

    impl PluginInfo for GiteaChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for GiteaChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = GiteaConfig::from_json(&config);
            // Ignore backlog: only deliver comments seen after configuration.
            CURSOR.with(|c| c.set(now_secs()));
            let login = if cfg.is_active() {
                fetch_self_login(&cfg)
            } else {
                None
            };
            SELF_LOGIN.with(|l| *l.borrow_mut() = login);
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.is_active() {
                return Err(
                    "gitea: channel not configured (need provider=gitea/forgejo, api_base_url, access_token)"
                        .to_string(),
                );
            }
            let base = cfg.base_url().unwrap_or_default();
            let target = IssueRef::parse(&message.recipient).ok_or_else(|| {
                format!(
                    "gitea: invalid recipient `{}` (expected owner/repo#number)",
                    message.recipient
                )
            })?;
            let url = create_comment_url(&base, &target.repo, target.number);
            for chunk in chunk_text(&message.content, COMMENT_MAX_CHARS) {
                post_json(&url, cfg.token(), &build_comment_body(&chunk))?;
            }
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            // Drain buffered comments before making another network round-trip.
            if let Some(inb) = BUFFER.with(|b| b.borrow_mut().pop_front()) {
                return Some(to_wit(inb));
            }
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.is_active() {
                return None;
            }
            let base = cfg.base_url()?;
            let token = cfg.token();
            let since = CURSOR.with(Cell::get);

            let url = notifications_url(&base, &unix_to_rfc3339(since));
            let resp = get_json(&url, token).ok()?;
            let threads: Vec<NotificationThread> = serde_json::from_value(resp).unwrap_or_default();
            if threads.is_empty() {
                return None;
            }

            let self_login = SELF_LOGIN.with(|l| l.borrow().clone()).unwrap_or_default();
            let mut max_updated = since;
            for thread in &threads {
                let updated = rfc3339_to_unix(&thread.updated_at).unwrap_or(0);
                max_updated = max_updated.max(updated);
                // `since` is inclusive; skip anything at/before the cursor.
                if updated <= since {
                    continue;
                }
                let Some(comment_url) = thread.comment_url() else {
                    continue;
                };
                let Some(repo) = thread.repo() else {
                    continue;
                };
                let Ok(cval) = get_json(comment_url, token) else {
                    continue;
                };
                let Ok(comment) = serde_json::from_value::<GiteaComment>(cval) else {
                    continue;
                };
                if already_seen(comment.id) {
                    continue;
                }
                if !should_admit(&comment, &self_login, cfg.mention_only, cfg.listen_to_bots) {
                    continue;
                }
                if let Some(inb) = comment_to_inbound(&comment, &repo) {
                    mark_seen(comment.id);
                    BUFFER.with(|b| b.borrow_mut().push_back(inb));
                }
            }
            CURSOR.with(|c| c.set(max_updated));
            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::SELF_HANDLE
        }

        fn health_check() -> bool {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            cfg.is_active() && fetch_self_login(&cfg).is_some()
        }

        fn self_handle() -> Option<String> {
            SELF_LOGIN.with(|l| l.borrow().clone())
        }

        // ── capability-gated stubs (documented WIT defaults) ──
        fn self_addressed_mention() -> Option<String> {
            SELF_LOGIN.with(|l| l.borrow().clone())
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

    export!(GiteaChannel);
}
