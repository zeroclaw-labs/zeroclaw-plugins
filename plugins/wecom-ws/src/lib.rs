//! ZeroClaw WeCom AI Bot WebSocket channel plugin.
//!
//! The host owns the TLS socket through the unstable `ws-client` WIT import.
//! The plugin drives the WeCom subscribe, ping, callback, response, and
//! proactive-send text protocol without blocking in `poll-message`.

pub mod wecom_ws;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, VecDeque};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use crate::wecom_ws::{
        access_decision, build_ping_frame, build_proactive_frame, build_respond_frame,
        build_subscribe_frame, decode_server_frame, markdown_chunks, split_stream_content,
        AccessDecision, InboundText, MessageIdCache, ServerFrame, StreamMode, WeComEvent,
        WeComWsConfig, CHANNEL, MESSAGE_ID_CACHE_SIZE, PLUGIN_NAME, WECOM_WS_URL,
    };
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::ws_client::{self, WsEvent};

    const PLUGIN_VERSION: &str = "0.1.0";
    const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);
    const SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(10);
    const PING_INTERVAL: Duration = Duration::from_secs(30);
    const MAX_DRAIN_PER_POLL: usize = 64;
    const MAX_INBOUND_QUEUE: usize = 1_024;
    const MAX_DRAFT_REQUESTS: usize = 4_096;

    enum Connection {
        Disconnected,
        Subscribing {
            handle: u64,
            request_id: String,
            sent_at: Instant,
        },
        Ready {
            handle: u64,
            last_ping: Instant,
        },
    }

    impl Connection {
        fn handle(&self) -> Option<u64> {
            match self {
                Self::Disconnected => None,
                Self::Subscribing { handle, .. } | Self::Ready { handle, .. } => Some(*handle),
            }
        }
    }

    struct RuntimeState {
        connection: Connection,
        retry_at: Option<Instant>,
        backoff: Duration,
        seen_messages: MessageIdCache,
        inbound: VecDeque<InboundText>,
        draft_requests: HashMap<String, String>,
    }

    impl Default for RuntimeState {
        fn default() -> Self {
            Self {
                connection: Connection::Disconnected,
                retry_at: None,
                backoff: INITIAL_BACKOFF,
                seen_messages: MessageIdCache::new(MESSAGE_ID_CACHE_SIZE),
                inbound: VecDeque::new(),
                draft_requests: HashMap::new(),
            }
        }
    }

    thread_local! {
        static CONFIG: RefCell<WeComWsConfig> = RefCell::new(WeComWsConfig::default());
        static STATE: RefCell<RuntimeState> = RefCell::new(RuntimeState::default());
        static FALLBACK_ID: Cell<u64> = const { Cell::new(0) };
    }

    fn random_id() -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut bytes = [0_u8; 8];
        if getrandom::fill(&mut bytes).is_err() {
            let fallback = FALLBACK_ID.with(|counter| {
                let next = counter.get().wrapping_add(1);
                counter.set(next);
                now_millis().rotate_left(17) ^ next
            });
            bytes = fallback.to_be_bytes();
        }

        let mut id = String::with_capacity(16);
        for byte in bytes {
            id.push(char::from(HEX[usize::from(byte >> 4)]));
            id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        id
    }

    fn stream_id() -> String {
        format!("stream-{}", random_id())
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }

    fn to_wit(message: InboundText) -> InboundMessage {
        let interruption_scope_id = message
            .reply_target
            .starts_with("group--")
            .then(|| message.reply_target.clone());
        InboundMessage {
            id: message.id,
            sender: message.sender,
            reply_target: message.reply_target,
            content: message.content,
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp: now_millis(),
            thread_ts: Some(message.request_id),
            interruption_scope_id,
            attachments: Vec::new(),
            subject: None,
        }
    }

    fn schedule_reconnect(state: &mut RuntimeState, handle: u64, immediate: bool) {
        ws_client::ws_close(handle);
        state.connection = Connection::Disconnected;
        state.draft_requests.clear();
        if immediate {
            state.retry_at = None;
            state.backoff = INITIAL_BACKOFF;
        } else {
            state.retry_at = Some(Instant::now() + state.backoff);
            state.backoff = (state.backoff * 2).min(MAX_BACKOFF);
        }
    }

    fn ensure_connected(state: &mut RuntimeState, config: &WeComWsConfig) {
        if state
            .retry_at
            .is_some_and(|retry_at| Instant::now() < retry_at)
        {
            return;
        }
        state.retry_at = None;

        let Ok(handle) = ws_client::ws_connect(WECOM_WS_URL, &[]) else {
            state.retry_at = Some(Instant::now() + state.backoff);
            state.backoff = (state.backoff * 2).min(MAX_BACKOFF);
            return;
        };
        let request_id = random_id();
        let subscribe = build_subscribe_frame(config, &request_id);
        if ws_client::ws_send_text(handle, &subscribe).is_err() {
            schedule_reconnect(state, handle, false);
            return;
        }
        state.connection = Connection::Subscribing {
            handle,
            request_id,
            sent_at: Instant::now(),
        };
    }

    fn drive_transport(state: &mut RuntimeState, config: &WeComWsConfig) {
        if matches!(state.connection, Connection::Disconnected) {
            ensure_connected(state, config);
            return;
        }

        let connection = std::mem::replace(&mut state.connection, Connection::Disconnected);
        match connection {
            Connection::Disconnected => {}
            Connection::Subscribing {
                handle,
                request_id,
                sent_at,
            } => {
                if sent_at.elapsed() >= SUBSCRIBE_TIMEOUT {
                    schedule_reconnect(state, handle, false);
                    return;
                }
                for _ in 0..MAX_DRAIN_PER_POLL {
                    match ws_client::ws_receive(handle) {
                        Ok(WsEvent::Text(text)) => {
                            let Ok(ServerFrame::CommandAck(ack)) = decode_server_frame(&text)
                            else {
                                continue;
                            };
                            if ack.request_id != request_id {
                                continue;
                            }
                            if ack.is_success() {
                                state.connection = Connection::Ready {
                                    handle,
                                    last_ping: Instant::now(),
                                };
                                state.retry_at = None;
                                state.backoff = INITIAL_BACKOFF;
                            } else {
                                schedule_reconnect(state, handle, false);
                            }
                            return;
                        }
                        Ok(WsEvent::Idle) => break,
                        Ok(WsEvent::Closed(_)) | Err(_) => {
                            schedule_reconnect(state, handle, false);
                            return;
                        }
                    }
                }
                state.connection = Connection::Subscribing {
                    handle,
                    request_id,
                    sent_at,
                };
            }
            Connection::Ready {
                handle,
                mut last_ping,
            } => {
                if last_ping.elapsed() >= PING_INTERVAL {
                    if ws_client::ws_send_text(handle, &build_ping_frame(&random_id())).is_err() {
                        schedule_reconnect(state, handle, false);
                        return;
                    }
                    last_ping = Instant::now();
                }

                for _ in 0..MAX_DRAIN_PER_POLL {
                    match ws_client::ws_receive(handle) {
                        Ok(WsEvent::Text(text)) => match decode_server_frame(&text) {
                            Ok(ServerFrame::Text(message)) => {
                                if !state.seen_messages.record_if_new(&message.id) {
                                    continue;
                                }
                                if access_decision(config, &message) == AccessDecision::Allowed
                                    && state.inbound.len() < MAX_INBOUND_QUEUE
                                {
                                    state.inbound.push_back(message);
                                }
                            }
                            Ok(ServerFrame::Event(WeComEvent::Disconnected)) => {
                                schedule_reconnect(state, handle, true);
                                return;
                            }
                            Ok(
                                ServerFrame::CommandAck(_)
                                | ServerFrame::UnsupportedMessage { .. }
                                | ServerFrame::Event(WeComEvent::Other(_))
                                | ServerFrame::Unknown,
                            )
                            | Err(_) => {}
                        },
                        Ok(WsEvent::Idle) => break,
                        Ok(WsEvent::Closed(_)) | Err(_) => {
                            schedule_reconnect(state, handle, false);
                            return;
                        }
                    }
                }
                state.connection = Connection::Ready { handle, last_ping };
            }
        }
    }

    fn transmit(frames: Vec<String>) -> Result<(), String> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let handle = match state.connection {
                Connection::Ready { handle, .. } => handle,
                _ => return Err("wecom-ws: WebSocket is not subscribed".to_string()),
            };
            for frame in frames {
                if let Err(error) = ws_client::ws_send_text(handle, &frame) {
                    schedule_reconnect(&mut state, handle, false);
                    return Err(format!("wecom-ws: WebSocket send failed: {error}"));
                }
            }
            Ok(())
        })
    }

    fn proactive_frames(reply_target: &str, content: &str) -> Result<Vec<String>, String> {
        markdown_chunks(content)
            .into_iter()
            .map(|chunk| build_proactive_frame(reply_target, &random_id(), &chunk))
            .collect()
    }

    fn final_response_frames(
        reply_target: &str,
        request_id: &str,
        stream_id: &str,
        content: &str,
    ) -> Result<Vec<String>, String> {
        let (head, overflow) = split_stream_content(content);
        let mut frames = vec![build_respond_frame(request_id, stream_id, &head, true)];
        if let Some(overflow) = overflow {
            frames.extend(proactive_frames(reply_target, &overflow)?);
        }
        Ok(frames)
    }

    struct WeComWsChannel;

    impl PluginInfo for WeComWsChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for WeComWsChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let config = WeComWsConfig::from_json(&config)?;
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                if let Some(handle) = state.connection.handle() {
                    ws_client::ws_close(handle);
                }
                *state = RuntimeState::default();
            });
            CONFIG.with(|current| *current.borrow_mut() = config);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err("wecom-ws: attachments are unsupported in the text plugin".to_string());
            }
            let frames = if let Some(request_id) = message
                .thread_ts
                .as_deref()
                .map(str::trim)
                .filter(|request_id| !request_id.is_empty())
            {
                final_response_frames(
                    &message.recipient,
                    request_id,
                    &stream_id(),
                    &message.content,
                )?
            } else {
                proactive_frames(&message.recipient, &message.content)?
            };
            transmit(frames)
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(message) = STATE.with(|state| state.borrow_mut().inbound.pop_front()) {
                return Some(to_wit(message));
            }
            let config = CONFIG.with(|config| config.borrow().clone());
            if !config.is_active() {
                return None;
            }
            STATE.with(|state| drive_transport(&mut state.borrow_mut(), &config));
            STATE
                .with(|state| state.borrow_mut().inbound.pop_front())
                .map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            let mut capabilities = ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::SELF_HANDLE
                | ChannelCapabilities::SELF_ADDRESSED_MENTION;
            if CONFIG.with(|config| config.borrow().stream_mode == StreamMode::Partial) {
                capabilities |= ChannelCapabilities::SUPPORTS_DRAFT_UPDATES
                    | ChannelCapabilities::SEND_DRAFT
                    | ChannelCapabilities::UPDATE_DRAFT
                    | ChannelCapabilities::UPDATE_DRAFT_PROGRESS
                    | ChannelCapabilities::FINALIZE_DRAFT
                    | ChannelCapabilities::CANCEL_DRAFT;
            }
            capabilities
        }

        fn health_check() -> bool {
            STATE.with(|state| matches!(state.borrow().connection, Connection::Ready { .. }))
        }

        fn self_handle() -> Option<String> {
            CONFIG.with(|config| config.borrow().bot_name.clone())
        }

        fn self_addressed_mention() -> Option<String> {
            CONFIG.with(|config| config.borrow().self_mention())
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
            CONFIG.with(|config| config.borrow().stream_mode == StreamMode::Partial)
        }

        fn send_draft(message: SendMessage) -> Result<Option<String>, String> {
            if !message.attachments.is_empty() {
                return Err("wecom-ws: draft attachments are unsupported".to_string());
            }
            if !CONFIG.with(|config| config.borrow().stream_mode == StreamMode::Partial) {
                return Ok(None);
            }
            let Some(request_id) = message
                .thread_ts
                .as_deref()
                .map(str::trim)
                .filter(|request_id| !request_id.is_empty())
            else {
                return Ok(None);
            };
            let stream_id = stream_id();
            let content = if message.content.is_empty() {
                "..."
            } else {
                &message.content
            };
            transmit(vec![build_respond_frame(
                request_id, &stream_id, content, false,
            )])?;
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                if state.draft_requests.len() >= MAX_DRAFT_REQUESTS {
                    state.draft_requests.clear();
                }
                state
                    .draft_requests
                    .insert(stream_id.clone(), request_id.to_string());
            });
            Ok(Some(stream_id))
        }

        fn update_draft(
            _recipient: String,
            message_id: String,
            text: String,
        ) -> Result<(), String> {
            let request_id =
                STATE.with(|state| state.borrow().draft_requests.get(&message_id).cloned());
            if let Some(request_id) = request_id {
                transmit(vec![build_respond_frame(
                    &request_id,
                    &message_id,
                    &text,
                    false,
                )])?;
            }
            Ok(())
        }

        fn update_draft_progress(
            recipient: String,
            message_id: String,
            text: String,
        ) -> Result<(), String> {
            Self::update_draft(recipient, message_id, text)
        }

        fn finalize_draft(
            recipient: String,
            message_id: String,
            text: String,
        ) -> Result<(), String> {
            let request_id =
                STATE.with(|state| state.borrow_mut().draft_requests.remove(&message_id));
            if let Some(request_id) = request_id {
                transmit(final_response_frames(
                    &recipient,
                    &request_id,
                    &message_id,
                    &text,
                )?)?;
            }
            Ok(())
        }

        fn cancel_draft(_recipient: String, message_id: String) -> Result<(), String> {
            let request_id =
                STATE.with(|state| state.borrow_mut().draft_requests.remove(&message_id));
            if let Some(request_id) = request_id {
                transmit(vec![build_respond_frame(
                    &request_id,
                    &message_id,
                    "",
                    true,
                )])?;
            }
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
                "wecom-ws uses WebSocket ingress and does not serve webhooks".to_string(),
            ))
        }
    }

    export!(WeComWsChannel);
}
