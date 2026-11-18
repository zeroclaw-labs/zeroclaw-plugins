//! A ZeroClaw WIT channel plugin for DingTalk Stream Mode.
//!
//! DingTalk gateway registration and session-webhook replies use `wasi:http`;
//! callback frames use the host-mediated `websocket` import.

pub mod dingtalk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, VecDeque};
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::dingtalk::{
        build_reply_body, connection_url, decode_frame, registration_body, DingTalkConfig,
        GatewayResponse, Inbound, CHANNEL, GATEWAY_OPEN_URL,
    };
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::websocket::{
        self, ConnectOptions, Connection as WsConnection, Event, Message,
    };
    use zeroclaw::plugin::{config, secrets};

    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const MAX_DRAIN_PER_POLL: usize = 200;

    thread_local! {
        static CONFIG: RefCell<DingTalkConfig> = RefCell::new(DingTalkConfig::default());
        static CONNECTION: RefCell<Option<Rc<WsConnection>>> = const { RefCell::new(None) };
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        static SESSION_WEBHOOKS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
        static NEXT_ID: Cell<u64> = const { Cell::new(1) };
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    fn next_id() -> String {
        NEXT_ID.with(|state| {
            let current = state.get();
            state.set(current.wrapping_add(1));
            format!("dingtalk-{current}")
        })
    }

    fn response_detail(resp: waki::Response) -> String {
        resp.body()
            .ok()
            .and_then(|body| String::from_utf8(body).ok())
            .unwrap_or_default()
    }

    fn post_json(url: &str, body: &Value) -> Result<Value, String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .map_err(|error| format!("dingtalk POST failed: {error}"))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!(
                "dingtalk POST {url} failed ({status}): {}",
                response_detail(resp)
            ));
        }
        resp.json::<Value>()
            .map_err(|error| format!("dingtalk response JSON failed: {error}"))
    }

    fn post_json_empty(url: &str, body: &Value) -> Result<(), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .map_err(|error| format!("dingtalk webhook POST failed: {error}"))?;
        let status = resp.status_code();
        if (200..300).contains(&status) {
            return Ok(());
        }
        Err(format!(
            "dingtalk webhook POST failed ({status}): {}",
            response_detail(resp)
        ))
    }

    fn register(cfg: &DingTalkConfig) -> Result<GatewayResponse, String> {
        if !cfg.is_configured() {
            return Err("dingtalk: client_id and client_secret are required".to_string());
        }
        let value = post_json(GATEWAY_OPEN_URL, &registration_body(cfg))?;
        serde_json::from_value(value)
            .map_err(|error| format!("dingtalk gateway response failed: {error}"))
    }

    fn connect(cfg: &DingTalkConfig) -> Result<Rc<WsConnection>, String> {
        let gateway = register(cfg)?;
        let url = connection_url(&gateway)
            .ok_or_else(|| "dingtalk gateway returned an empty endpoint or ticket".to_string())?;
        let handle = websocket::connect(&ConnectOptions {
            url,
            headers: vec![],
            subprotocols: vec![],
            tls_profile: None,
        })
        .map(Rc::new)
        .map_err(|error| format!("WebSocket connect: {error:?}"))?;
        CONNECTION.with(|state| *state.borrow_mut() = Some(handle.clone()));
        Ok(handle)
    }

    fn drop_connection() {
        CONNECTION.with(|state| *state.borrow_mut() = None);
    }

    fn remember_webhook(chat_id: String, sender_id: String, url: String) {
        SESSION_WEBHOOKS.with(|state| {
            let mut webhooks = state.borrow_mut();
            webhooks.insert(chat_id, url.clone());
            webhooks.insert(sender_id, url);
        });
    }

    fn to_wit(message: Inbound) -> InboundMessage {
        InboundMessage {
            id: message.id.unwrap_or_else(next_id),
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

    struct DingTalkChannel;

    impl PluginInfo for DingTalkChannel {
        fn plugin_name() -> String {
            CHANNEL.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for DingTalkChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        fn configure() -> Result<(), String> {
            let public = config::get().map_err(|error| format!("dingtalk: config: {error:?}"))?;
            let mut cfg: DingTalkConfig = serde_json::from_str(&public)
                .map_err(|_| "dingtalk: invalid public configuration")?;
            cfg.client_secret = secrets::get("client_secret")
                .map_err(|error| format!("dingtalk: client_secret: {error:?}"))?;
            CONNECTION.with(|state| *state.borrow_mut() = None);
            BUFFER.with(|state| state.borrow_mut().clear());
            SESSION_WEBHOOKS.with(|state| state.borrow_mut().clear());
            NEXT_ID.with(|state| state.set(1));
            CONFIG.with(|state| *state.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err("dingtalk: media attachments are not supported yet".to_string());
            }
            let webhook = SESSION_WEBHOOKS
                .with(|state| state.borrow().get(&message.recipient).cloned())
                .ok_or_else(|| {
                    format!(
                        "dingtalk: no session webhook for `{}`; the chat must message the bot first",
                        message.recipient
                    )
                })?;
            post_json_empty(
                &webhook,
                &build_reply_body(&message.content, message.subject.as_deref()),
            )
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(message) = BUFFER.with(|state| state.borrow_mut().pop_front()) {
                return Some(to_wit(message));
            }
            let cfg = CONFIG.with(|state| state.borrow().clone());
            if !cfg.is_configured() {
                return None;
            }
            let handle = match CONNECTION.with(|state| state.borrow().clone()) {
                Some(handle) => handle,
                None => connect(&cfg).ok()?,
            };
            for _ in 0..MAX_DRAIN_PER_POLL {
                match handle.receive() {
                    Ok(Some(Event::Message(Message::Text(frame)))) => {
                        let outcome = decode_frame(&frame);
                        if let Some(response) = outcome.response {
                            if handle.send(&Message::Text(response)).is_err() {
                                drop_connection();
                                break;
                            }
                        }
                        if let Some(webhook) = outcome.session_webhook {
                            remember_webhook(webhook.chat_id, webhook.sender_id, webhook.url);
                        }
                        if let Some(message) = outcome.inbound {
                            BUFFER.with(|state| state.borrow_mut().push_back(message));
                        }
                    }
                    Ok(Some(Event::Message(Message::Binary(_)))) => continue,
                    Ok(None) => break,
                    Ok(Some(Event::Closed(_) | Event::Failed(_))) | Err(_) => {
                        drop_connection();
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
            CONNECTION.with(|connection| connection.borrow().is_some())
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
        fn parse_webhook(_request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            Err(WebhookRejection::BadRequest(
                "dingtalk does not serve webhooks".to_string(),
            ))
        }
    }

    export!(DingTalkChannel);
}
