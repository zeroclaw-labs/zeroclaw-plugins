//! A ZeroClaw WIT channel plugin for QQ Official Bot text messaging.
//!
//! OAuth, gateway discovery, and text sends use `wasi:http`; the gateway uses
//! the host-mediated `ws-client` import.

pub mod qq;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::{HashSet, VecDeque};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::qq::{
        auth_body, build_send_body, decode_gateway_frame, gateway_url, heartbeat_frame,
        identify_frame, parse_access_token, resume_frame, send_url, DecodedFrame, GatewayEvent,
        Inbound, QQConfig, API_BASE, AUTH_URL, CHANNEL, DEFAULT_HEARTBEAT_MS,
    };
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::ws_client::{self, WsEvent};

    const PLUGIN_VERSION: &str = "0.1.0";
    const MAX_DRAIN_PER_POLL: usize = 200;
    const SEEN_CAP: usize = 10_000;

    thread_local! {
        static CONFIG: RefCell<QQConfig> = RefCell::new(QQConfig::default());
        static TOKEN: RefCell<Option<(String, u64)>> = const { RefCell::new(None) };
        static CONNECTION: Cell<u64> = const { Cell::new(0) };
        static IDENTIFIED: Cell<bool> = const { Cell::new(false) };
        static HEARTBEAT_INTERVAL_MS: Cell<u64> = const { Cell::new(DEFAULT_HEARTBEAT_MS) };
        static NEXT_HEARTBEAT_MS: Cell<u64> = const { Cell::new(0) };
        static SEQUENCE: Cell<i64> = const { Cell::new(-1) };
        static SESSION_ID: RefCell<Option<String>> = const { RefCell::new(None) };
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        static SEEN: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
        static MSG_SEQ: Cell<u32> = const { Cell::new(1) };
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    fn now_secs() -> u64 {
        now_millis() / 1_000
    }

    fn response_detail(resp: waki::Response) -> String {
        resp.body()
            .ok()
            .and_then(|body| String::from_utf8(body).ok())
            .unwrap_or_default()
    }

    fn public_post_json(url: &str, body: &Value) -> Result<Value, String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .map_err(|error| format!("qq POST failed: {error}"))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!(
                "qq POST {url} failed ({status}): {}",
                response_detail(resp)
            ));
        }
        resp.json()
            .map_err(|error| format!("qq response JSON failed: {error}"))
    }

    fn authorized_get_json(url: &str, token: &str) -> Result<Value, String> {
        let resp = waki::Client::new()
            .get(url)
            .header("Authorization", format!("QQBot {token}"))
            .header("Accept", "application/json")
            .send()
            .map_err(|error| format!("qq GET failed: {error}"))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!(
                "qq GET {url} failed ({status}): {}",
                response_detail(resp)
            ));
        }
        resp.json()
            .map_err(|error| format!("qq response JSON failed: {error}"))
    }

    fn authorized_post_json(url: &str, token: &str, body: &Value) -> Result<(), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("QQBot {token}"))
            .header("Accept", "application/json")
            .json(body)
            .send()
            .map_err(|error| format!("qq send POST failed: {error}"))?;
        let status = resp.status_code();
        if (200..300).contains(&status) {
            return Ok(());
        }
        Err(format!(
            "qq send POST failed ({status}): {}",
            response_detail(resp)
        ))
    }

    fn fetch_token(cfg: &QQConfig) -> Result<(String, u64), String> {
        if !cfg.is_configured() {
            return Err("qq: app_id and app_secret are required".to_string());
        }
        let value = public_post_json(AUTH_URL, &auth_body(cfg))?;
        let token = parse_access_token(&value)
            .ok_or_else(|| "qq auth response has no access_token".to_string())?;
        let expiry = now_secs() + token.expires_in.saturating_sub(60);
        Ok((token.value, expiry))
    }

    fn get_token(cfg: &QQConfig) -> Result<String, String> {
        let now = now_secs();
        if let Some(token) = TOKEN.with(|state| {
            state
                .borrow()
                .as_ref()
                .filter(|(_, expiry)| now < *expiry)
                .map(|(token, _)| token.clone())
        }) {
            return Ok(token);
        }
        let (token, expiry) = fetch_token(cfg)?;
        TOKEN.with(|state| *state.borrow_mut() = Some((token.clone(), expiry)));
        Ok(token)
    }

    fn open_connection(cfg: &QQConfig) -> Result<u64, String> {
        let token = get_token(cfg)?;
        let value = authorized_get_json(&format!("{API_BASE}/gateway"), &token)?;
        let url = gateway_url(&value)
            .ok_or_else(|| "qq gateway response has no WebSocket URL".to_string())?;
        let handle = ws_client::ws_connect(&url, &[])?;
        CONNECTION.with(|state| state.set(handle));
        IDENTIFIED.with(|state| state.set(false));
        NEXT_HEARTBEAT_MS.with(|state| state.set(0));
        Ok(handle)
    }

    fn drop_connection(handle: u64) {
        ws_client::ws_close(handle);
        CONNECTION.with(|state| state.set(0));
        IDENTIFIED.with(|state| state.set(false));
        NEXT_HEARTBEAT_MS.with(|state| state.set(0));
    }

    fn send_heartbeat(handle: u64) -> Result<(), String> {
        let sequence = SEQUENCE.with(Cell::get);
        ws_client::ws_send_text(
            handle,
            &heartbeat_frame((sequence >= 0).then_some(sequence)),
        )?;
        let interval = HEARTBEAT_INTERVAL_MS.with(Cell::get);
        NEXT_HEARTBEAT_MS.with(|state| state.set(now_millis().saturating_add(interval)));
        Ok(())
    }

    fn identify_or_resume(handle: u64, cfg: &QQConfig, interval: u64) -> Result<(), String> {
        let token = get_token(cfg)?;
        let sequence = SEQUENCE.with(Cell::get);
        let session = SESSION_ID.with(|state| state.borrow().clone());
        let frame = match (session, sequence >= 0) {
            (Some(session_id), true) => resume_frame(&token, &session_id, sequence),
            _ => identify_frame(&token),
        };
        ws_client::ws_send_text(handle, &frame)?;
        HEARTBEAT_INTERVAL_MS.with(|state| state.set(interval.max(1_000)));
        NEXT_HEARTBEAT_MS.with(|state| state.set(now_millis().saturating_add(interval.max(1_000))));
        IDENTIFIED.with(|state| state.set(true));
        Ok(())
    }

    fn first_sighting(id: &str) -> bool {
        SEEN.with(|state| {
            let mut seen = state.borrow_mut();
            if seen.contains(id) {
                return false;
            }
            if seen.len() >= SEEN_CAP {
                seen.clear();
            }
            seen.insert(id.to_string());
            true
        })
    }

    fn handle_frame(handle: u64, cfg: &QQConfig, decoded: DecodedFrame) -> Result<bool, String> {
        if let Some(sequence) = decoded.sequence.filter(|sequence| *sequence >= 0) {
            SEQUENCE.with(|state| state.set(sequence));
        }
        match decoded.event {
            GatewayEvent::Hello {
                heartbeat_interval_ms,
            } => identify_or_resume(handle, cfg, heartbeat_interval_ms)?,
            GatewayEvent::HeartbeatRequest => send_heartbeat(handle)?,
            GatewayEvent::HeartbeatAck | GatewayEvent::Ignore => {}
            GatewayEvent::Ready { session_id } => {
                if let Some(session_id) = session_id {
                    SESSION_ID.with(|state| *state.borrow_mut() = Some(session_id));
                }
            }
            GatewayEvent::Message(message) => {
                if first_sighting(&message.id) {
                    BUFFER.with(|state| state.borrow_mut().push_back(message));
                }
            }
            GatewayEvent::Reconnect => {
                drop_connection(handle);
                return Ok(false);
            }
            GatewayEvent::InvalidSession => {
                SESSION_ID.with(|state| *state.borrow_mut() = None);
                SEQUENCE.with(|state| state.set(-1));
                drop_connection(handle);
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn to_wit(message: Inbound) -> InboundMessage {
        InboundMessage {
            id: message.id,
            sender: message.sender,
            reply_target: message.reply_target,
            content: message.content,
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp: now_secs(),
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct QQChannel;

    impl PluginInfo for QQChannel {
        fn plugin_name() -> String {
            CHANNEL.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for QQChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = QQConfig::from_json(&config);
            let handle = CONNECTION.with(Cell::get);
            if handle != 0 {
                ws_client::ws_close(handle);
            }
            CONFIG.with(|state| *state.borrow_mut() = cfg);
            TOKEN.with(|state| *state.borrow_mut() = None);
            CONNECTION.with(|state| state.set(0));
            IDENTIFIED.with(|state| state.set(false));
            HEARTBEAT_INTERVAL_MS.with(|state| state.set(DEFAULT_HEARTBEAT_MS));
            NEXT_HEARTBEAT_MS.with(|state| state.set(0));
            SEQUENCE.with(|state| state.set(-1));
            SESSION_ID.with(|state| *state.borrow_mut() = None);
            BUFFER.with(|state| state.borrow_mut().clear());
            SEEN.with(|state| state.borrow_mut().clear());
            let seed = u32::try_from(now_millis() & u64::from(u16::MAX)).unwrap_or(1);
            MSG_SEQ.with(|state| state.set(seed));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err("qq: media attachments are not supported by this plugin yet".into());
            }
            let cfg = CONFIG.with(|state| state.borrow().clone());
            let token = get_token(&cfg)?;
            let url = send_url(&message.recipient).ok_or_else(|| {
                format!(
                    "qq: invalid recipient `{}` (expected user:<openid> or group:<openid>)",
                    message.recipient
                )
            })?;
            let msg_seq = MSG_SEQ.with(|state| {
                let value = state.get();
                state.set(value.wrapping_add(1) & 0xffff);
                value
            });
            authorized_post_json(&url, &token, &build_send_body(&message.content, msg_seq))
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(message) = BUFFER.with(|state| state.borrow_mut().pop_front()) {
                return Some(to_wit(message));
            }
            let cfg = CONFIG.with(|state| state.borrow().clone());
            if !cfg.is_configured() {
                return None;
            }
            let mut handle = CONNECTION.with(Cell::get);
            if handle == 0 {
                handle = open_connection(&cfg).ok()?;
            }
            if IDENTIFIED.with(Cell::get)
                && now_millis() >= NEXT_HEARTBEAT_MS.with(Cell::get)
                && send_heartbeat(handle).is_err()
            {
                drop_connection(handle);
                return None;
            }
            for _ in 0..MAX_DRAIN_PER_POLL {
                match ws_client::ws_receive(handle) {
                    Ok(WsEvent::Text(frame)) => {
                        match handle_frame(handle, &cfg, decode_gateway_frame(&frame)) {
                            Ok(true) => {}
                            Ok(false) => break,
                            Err(_) => {
                                drop_connection(handle);
                                break;
                            }
                        }
                    }
                    Ok(WsEvent::Idle) => break,
                    Ok(WsEvent::Closed(_)) | Err(_) => {
                        drop_connection(handle);
                        break;
                    }
                }
            }
            BUFFER
                .with(|state| state.borrow_mut().pop_front())
                .map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
        }

        fn health_check() -> bool {
            let cfg = CONFIG.with(|state| state.borrow().clone());
            get_token(&cfg).is_ok()
        }

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
                "qq does not serve webhooks".to_string(),
            ))
        }
    }

    export!(QQChannel);
}
