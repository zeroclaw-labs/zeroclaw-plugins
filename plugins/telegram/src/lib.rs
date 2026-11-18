//! A ZeroClaw WIT **channel** plugin: Telegram.
//!
//! Long-polls the Telegram Bot API (`getUpdates`, short `timeout=0` polls so it
//! never stalls `send`) and delivers each text message to the agent; sends the
//! agent's replies with `sendMessage`. The bot token and settings come from the
//! plugin's config section (`config_read`); all HTTP goes through the host's
//! `wasi:http` (`http_client`), which performs TLS host-side.
//!
//! The pure Bot-API logic lives in [`telegram`] (no wasm/http deps) and is
//! covered by a host `cargo test`; this file is the thin component shim that
//! wires it to the `channel-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod telegram;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use serde_json::Value;

    use crate::telegram::{
        build_send_payload, chunk_text, extract_updates, is_user_allowed, next_offset,
        parse_update, split_recipient, Inbound, TelegramConfig,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::logging::{self, LogLevel, PluginAction, PluginEvent, PluginOutcome};
    use zeroclaw::plugin::{config, secrets};

    const PLUGIN_NAME: &str = "telegram";
    /// Bound each connect well inside the host's 30 s call deadline, so an
    /// unreachable address fails the request instead of the whole call.
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const MAX_MESSAGE_CHARS: usize = 4096;

    thread_local! {
        static CONFIG: RefCell<TelegramConfig> = RefCell::new(TelegramConfig::default());
        static OFFSET: Cell<i64> = const { Cell::new(0) };
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        static SELF_HANDLE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    fn endpoint(cfg: &TelegramConfig, method: &str) -> String {
        format!(
            "{}/bot{}/{}",
            cfg.api_base_url.trim_end_matches('/'),
            cfg.bot_token,
            method
        )
    }

    fn get_json(url: &str) -> Result<Value, String> {
        waki::Client::new()
            .get(url)
            .connect_timeout(CONNECT_TIMEOUT)
            .send()
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .map_err(|e| e.to_string())
    }

    fn post_json(url: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .connect_timeout(CONNECT_TIMEOUT)
            .json(body)
            .send()
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .map_err(|e| e.to_string())
    }

    /// Best-effort `getMe` → `@username`; `None` on any error so a missing or
    /// unreachable token never fails `configure`.
    fn fetch_self_handle(cfg: &TelegramConfig) -> Option<String> {
        if cfg.bot_token.is_empty() {
            return None;
        }
        let v = get_json(&endpoint(cfg, "getMe")).ok()?;
        v.get("result")?
            .get("username")
            .and_then(Value::as_str)
            .map(|u| format!("@{u}"))
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
                function_name: "telegram::configure".to_string(),
                action: PluginAction::Fail,
                outcome: Some(PluginOutcome::Failure),
                duration_ms: None,
                attrs: None,
                message: format!("telegram: could not read {key}: {kind}"),
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
    fn load_config() -> TelegramConfig {
        let public = config::get().unwrap_or_else(|error| {
            report_read_failure("config", config_error_kind(error));
            String::new()
        });
        let mut cfg = TelegramConfig::from_json(&public);
        cfg.bot_token = secrets::get("bot_token")
            .map_err(|error| report_read_failure("bot_token", secret_error_kind(error)))
            .unwrap_or_default();
        cfg
    }

    struct TelegramChannel;

    impl PluginInfo for TelegramChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for TelegramChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure() -> Result<(), String> {
            let cfg = load_config();
            let handle = fetch_self_handle(&cfg);
            SELF_HANDLE.with(|h| *h.borrow_mut() = handle);
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if cfg.bot_token.is_empty() {
                return Err("telegram: no bot_token configured".to_string());
            }
            let (chat_id, thread) = split_recipient(&message.recipient);
            let url = endpoint(&cfg, "sendMessage");
            for chunk in chunk_text(&message.content, MAX_MESSAGE_CHARS) {
                let body = build_send_payload(
                    &chat_id,
                    &chunk,
                    thread.as_deref(),
                    cfg.parse_mode.as_deref(),
                );
                let resp = post_json(&url, &body)?;
                if resp.get("ok").and_then(Value::as_bool) != Some(true) {
                    // A rejected parse_mode (bad HTML/Markdown) is the common
                    // cause; retry once as plain text before giving up.
                    let plain = build_send_payload(&chat_id, &chunk, thread.as_deref(), None);
                    let retry = post_json(&url, &plain)?;
                    if retry.get("ok").and_then(Value::as_bool) != Some(true) {
                        return Err(format!("telegram sendMessage failed: {retry}"));
                    }
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
            let offset = OFFSET.with(Cell::get);
            let url = format!(
                "{}?offset={}&timeout=0&allowed_updates=%5B%22message%22%5D",
                endpoint(&cfg, "getUpdates"),
                offset
            );
            let resp = get_json(&url).ok()?;
            let updates = extract_updates(&resp);
            if updates.is_empty() {
                return None;
            }
            let mut max_id = offset - 1;
            let gated = !cfg.allowed_users.is_empty();
            for (uid, upd) in &updates {
                max_id = max_id.max(*uid);
                if let Some(inb) = parse_update(upd) {
                    let identities = [inb.sender.clone()];
                    if !gated || is_user_allowed(&identities, &cfg.allowed_users) {
                        BUFFER.with(|b| b.borrow_mut().push_back(inb));
                    }
                }
            }
            OFFSET.with(|o| o.set(next_offset(max_id)));
            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::SELF_HANDLE
        }

        fn health_check() -> bool {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            !cfg.bot_token.is_empty() && fetch_self_handle(&cfg).is_some()
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

        fn parse_webhook(_request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            Err(WebhookRejection::BadRequest(
                "this channel does not serve webhooks".to_string(),
            ))
        }
    }

    export!(TelegramChannel);
}
