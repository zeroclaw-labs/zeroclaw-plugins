//! A ZeroClaw WIT **channel** plugin: Notion (task queue).
//!
//! Notion is not a chat channel — it is a task queue. This plugin polls a Notion
//! database (`POST /v1/databases/{id}/query`) for rows whose status is
//! `pending`, delivers each row's input property to the agent as an inbound
//! message, and — when the agent answers — writes the result back and flips the
//! row to `done` (`PATCH /v1/pages/{id}`). To avoid re-dispatching a row while
//! the agent works, each claimed row is first flipped `pending` → `running`. On
//! load it optionally resets rows stranded in `running` by a prior crash. The
//! integration token, database id, and property names come from the plugin's
//! config section (`config_read`); all HTTP goes through the host's `wasi:http`
//! (`http_client`), which performs TLS host-side and carries the Bearer token.
//!
//! The pure JSON/mapping logic lives in [`notion`] (no wasm/http deps) and is
//! covered by a host `cargo test`; this file is the thin component shim that
//! wires it to the `channel-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod notion;

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

    use crate::notion::{
        build_complete_payload, build_query_body, build_recover_payload,
        build_status_update_payload, database_url, detect_status_type, page_url, parse_pending,
        query_url, Inbound, NotionConfig, NOTION_VERSION,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "notion";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    thread_local! {
        static CONFIG: RefCell<NotionConfig> = RefCell::new(NotionConfig::default());
        // Detected once from the database schema: "status" or "select". `None`
        // until probed; the filters/payloads differ between the two types.
        static STATUS_TYPE: RefCell<Option<String>> = const { RefCell::new(None) };
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// `GET` with the Notion auth + version headers → `(status, body)`. The body
    /// is parsed even on error responses (Notion returns JSON errors) so callers
    /// can inspect the status.
    fn get_json(url: &str, api_key: &str) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .get(url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Notion-Version", NOTION_VERSION)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().map_err(|e| e.to_string())?;
        Ok((status, val))
    }

    /// `POST` a JSON body with the Notion auth + version headers → `(status, body)`.
    fn post_json(url: &str, api_key: &str, body: &Value) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Notion-Version", NOTION_VERSION)
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().map_err(|e| e.to_string())?;
        Ok((status, val))
    }

    /// `PATCH` a JSON body with the Notion auth + version headers → `(status, body)`.
    fn patch_json(url: &str, api_key: &str, body: &Value) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .patch(url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Notion-Version", NOTION_VERSION)
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().map_err(|e| e.to_string())?;
        Ok((status, val))
    }

    /// Probe the database schema for the status property type. Best effort:
    /// defaults to `select` on any error so a missing/unreachable token never
    /// fails.
    fn fetch_status_type(cfg: &NotionConfig) -> String {
        let url = database_url(&cfg.api_base_url, &cfg.database_id);
        match get_json(&url, &cfg.api_key) {
            Ok((status, val)) if status < 400 => detect_status_type(&val, &cfg.status_property),
            _ => "select".to_string(),
        }
    }

    /// Return the cached status property type, probing + caching it on first use.
    fn ensure_status_type(cfg: &NotionConfig) -> String {
        if let Some(st) = STATUS_TYPE.with(|s| s.borrow().clone()) {
            return st;
        }
        let st = fetch_status_type(cfg);
        STATUS_TYPE.with(|s| *s.borrow_mut() = Some(st.clone()));
        st
    }

    /// On load, reset rows stranded in `running` (a prior crash) back to
    /// `pending` so they are re-dispatched. Best effort; failures are ignored.
    fn recover_stale(cfg: &NotionConfig, status_type: &str) {
        let url = query_url(&cfg.api_base_url, &cfg.database_id);
        let body = build_query_body(&cfg.status_property, status_type, "running");
        let Ok((status, val)) = post_json(&url, &cfg.api_key, &body) else {
            return;
        };
        if status >= 400 {
            return;
        }
        for row in parse_pending(&val, &cfg.input_property) {
            let purl = page_url(&cfg.api_base_url, &row.id);
            let payload =
                build_recover_payload(&cfg.status_property, &cfg.result_property, status_type);
            let _ = patch_json(&purl, &cfg.api_key, &payload);
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

    struct NotionChannel;

    impl PluginInfo for NotionChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for NotionChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = NotionConfig::from_json(&config)?;
            // Warm the status-property type (best effort) and run crash recovery
            // once at load; a missing/unreachable token never fails configure.
            if cfg.has_credentials() {
                let st = fetch_status_type(&cfg);
                if cfg.recover_stale {
                    recover_stale(&cfg, &st);
                }
                STATUS_TYPE.with(|s| *s.borrow_mut() = Some(st));
            }
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.has_credentials() {
                return Err("notion: no api_key/database_id configured".to_string());
            }
            let status_type = ensure_status_type(&cfg);
            // The recipient is the page id (carried through from `reply_target`).
            let url = page_url(&cfg.api_base_url, &message.recipient);
            let payload = build_complete_payload(
                &cfg.status_property,
                &cfg.result_property,
                &status_type,
                &message.content,
            );
            let (status, val) = patch_json(&url, &cfg.api_key, &payload)?;
            if status >= 400 {
                return Err(format!("notion pages.update failed ({status}): {val}"));
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
            let status_type = ensure_status_type(&cfg);
            let url = query_url(&cfg.api_base_url, &cfg.database_id);
            let body = build_query_body(&cfg.status_property, &status_type, "pending");
            let (status, val) = post_json(&url, &cfg.api_key, &body).ok()?;
            if status >= 400 {
                return None;
            }
            let pending = parse_pending(&val, &cfg.input_property);
            if pending.is_empty() {
                return None;
            }
            let now = now_millis();
            let mut claimed = 0usize;
            for mut inb in pending {
                if claimed >= cfg.max_concurrent {
                    break;
                }
                // Skip empty prompts (nothing for the agent to act on).
                if inb.content.trim().is_empty() {
                    continue;
                }
                // Claim the task server-side: flip `pending` → `running` so the
                // next poll never re-dispatches it. Completion (→ `done`) happens
                // in `send`. If the claim write fails, leave the row for a later
                // poll rather than deliver a task we cannot mark in-flight.
                let purl = page_url(&cfg.api_base_url, &inb.id);
                let claim =
                    build_status_update_payload(&cfg.status_property, &status_type, "running");
                match patch_json(&purl, &cfg.api_key, &claim) {
                    Ok((s, _)) if s < 400 => {}
                    _ => continue,
                }
                inb.timestamp = now;
                BUFFER.with(|b| b.borrow_mut().push_back(inb));
                claimed += 1;
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
            let url = database_url(&cfg.api_base_url, &cfg.database_id);
            matches!(get_json(&url, &cfg.api_key), Ok((s, _)) if s < 400)
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

    export!(NotionChannel);
}
