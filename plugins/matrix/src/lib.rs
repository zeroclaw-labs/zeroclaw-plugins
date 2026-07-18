//! A ZeroClaw WIT channel plugin for Matrix.
//!
//! It uses the Matrix Client-Server API through host-provided `wasi:http`: an
//! initial `/sync` establishes a cursor without replaying backlog, subsequent
//! polls emit new unencrypted text events, and replies use `m.room.message`.

pub mod matrix;

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

    use crate::matrix::{
        build_send_body, parse_room_id, parse_sync, parse_whoami, room_alias_url, send_url,
        sync_url, whoami_url, Inbound, MatrixConfig, CHANNEL,
    };
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    fn initial_transaction_id() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(1)
    }

    thread_local! {
        static CONFIG: RefCell<MatrixConfig> = RefCell::new(MatrixConfig::default());
        static SINCE: RefCell<Option<String>> = const { RefCell::new(None) };
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        static SELF_USER_ID: RefCell<Option<String>> = const { RefCell::new(None) };
        static TRANSACTION_ID: Cell<u64> = const { Cell::new(1) };
    }

    fn error_detail(resp: waki::Response) -> String {
        resp.body()
            .ok()
            .and_then(|body| String::from_utf8(body).ok())
            .unwrap_or_default()
    }

    fn get_json(url: &str, token: &str) -> Result<Value, String> {
        let resp = waki::Client::new()
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/json")
            .send()
            .map_err(|error| format!("matrix GET failed: {error}"))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!(
                "matrix GET {url} failed ({status}): {}",
                error_detail(resp)
            ));
        }
        resp.json::<Value>()
            .map_err(|error| format!("matrix response JSON failed: {error}"))
    }

    fn put_json(url: &str, token: &str, body: &Value) -> Result<Value, String> {
        let resp = waki::Client::new()
            .put(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/json")
            .json(body)
            .send()
            .map_err(|error| format!("matrix PUT failed: {error}"))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!(
                "matrix PUT {url} failed ({status}): {}",
                error_detail(resp)
            ));
        }
        resp.json::<Value>()
            .map_err(|error| format!("matrix response JSON failed: {error}"))
    }

    fn fetch_self(cfg: &MatrixConfig) -> Option<String> {
        if !cfg.is_configured() {
            return cfg.user_id().map(str::to_string);
        }
        get_json(&whoami_url(cfg.homeserver()), cfg.access_token())
            .ok()
            .and_then(|value| parse_whoami(&value))
            .or_else(|| cfg.user_id().map(str::to_string))
    }

    fn resolve_recipient(cfg: &MatrixConfig, recipient: &str) -> Result<String, String> {
        let target = recipient.trim();
        if target.starts_with('!') {
            return Ok(target.to_string());
        }
        if !target.starts_with('#') {
            return Err(format!(
                "matrix: invalid recipient `{target}` (expected !room:id or #alias:id)"
            ));
        }
        let value = get_json(
            &room_alias_url(cfg.homeserver(), target),
            cfg.access_token(),
        )?;
        parse_room_id(&value).ok_or_else(|| format!("matrix: alias `{target}` did not resolve"))
    }

    fn to_wit(message: Inbound) -> InboundMessage {
        InboundMessage {
            id: message.id,
            sender: message.sender,
            reply_target: message.reply_target,
            content: message.content,
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp: message.timestamp,
            thread_ts: message.thread_ts,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct MatrixChannel;

    impl PluginInfo for MatrixChannel {
        fn plugin_name() -> String {
            CHANNEL.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for MatrixChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = MatrixConfig::from_json(&config);
            let self_user_id = fetch_self(&cfg);
            CONFIG.with(|state| *state.borrow_mut() = cfg);
            SELF_USER_ID.with(|state| *state.borrow_mut() = self_user_id);
            SINCE.with(|state| *state.borrow_mut() = None);
            BUFFER.with(|state| state.borrow_mut().clear());
            TRANSACTION_ID.with(|state| state.set(initial_transaction_id()));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err(
                    "matrix: media attachments are not supported by this plugin yet".into(),
                );
            }
            let cfg = CONFIG.with(|state| state.borrow().clone());
            if !cfg.is_configured() {
                return Err("matrix: homeserver and access_token are required".into());
            }
            let room_id = resolve_recipient(&cfg, &message.recipient)?;
            let transaction_id = TRANSACTION_ID.with(|state| {
                let current = state.get();
                state.set(current.wrapping_add(1));
                current
            });
            let body = build_send_body(
                &message.content,
                message.thread_ts.as_deref(),
                cfg.reply_in_thread,
            );
            put_json(
                &send_url(cfg.homeserver(), &room_id, transaction_id),
                cfg.access_token(),
                &body,
            )?;
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(message) = BUFFER.with(|state| state.borrow_mut().pop_front()) {
                return Some(to_wit(message));
            }
            let cfg = CONFIG.with(|state| state.borrow().clone());
            if !cfg.is_configured() {
                return None;
            }
            let prior_since = SINCE.with(|state| state.borrow().clone());
            let value = get_json(
                &sync_url(cfg.homeserver(), prior_since.as_deref()),
                cfg.access_token(),
            )
            .ok()?;
            let self_user_id = SELF_USER_ID
                .with(|state| state.borrow().clone())
                .unwrap_or_default();
            let batch = parse_sync(&value, &cfg, &self_user_id);
            if batch.next_batch.is_empty() {
                return None;
            }
            SINCE.with(|state| *state.borrow_mut() = Some(batch.next_batch));
            prior_since.as_ref()?;
            BUFFER.with(|state| state.borrow_mut().extend(batch.messages));
            BUFFER
                .with(|state| state.borrow_mut().pop_front())
                .map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::SELF_HANDLE
                | ChannelCapabilities::SELF_ADDRESSED_MENTION
        }

        fn health_check() -> bool {
            let cfg = CONFIG.with(|state| state.borrow().clone());
            cfg.is_configured() && fetch_self(&cfg).is_some()
        }

        fn self_handle() -> Option<String> {
            SELF_USER_ID.with(|state| state.borrow().clone())
        }

        fn self_addressed_mention() -> Option<String> {
            SELF_USER_ID.with(|state| state.borrow().clone())
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
                "matrix does not serve webhooks".to_string(),
            ))
        }
    }

    export!(MatrixChannel);
}
