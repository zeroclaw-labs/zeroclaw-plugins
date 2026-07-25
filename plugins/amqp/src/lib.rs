//! ZeroClaw AMQP 0-9-1 channel plugin.
//!
//! The host owns TCP/TLS through the feature-gated `socket` WIT import. The
//! guest owns AMQP framing, authentication, topology setup, consumption,
//! acknowledgements, publishing, heartbeats, and reconnect progression.

pub mod amqp;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-sockets"],
    });

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use crate::amqp::{
        encode_ack, encode_heartbeat, map_delivery, Action, AmqpConfig, MappedDelivery, Session,
        PLUGIN_NAME, PROTOCOL_HEADER,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::socket::{self, SocketEvent};

    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);
    const DRAIN_BATCH: usize = 64;
    const MAX_BUFFERED_DELIVERIES: usize = 128;

    struct QueuedInbound {
        generation: u64,
        delivery_tag: u64,
        mapped: MappedDelivery,
    }

    /// Socket/timer state that cannot live in the pure protocol session.
    struct TransportState {
        session: Session,
        handle: Option<u64>,
        last_rx: Option<Instant>,
        last_tx: Option<Instant>,
        next_connect_at: Option<Instant>,
        backoff: Duration,
        generation: u64,
        pending_ack: Option<(u64, u64)>,
    }

    impl Default for TransportState {
        fn default() -> Self {
            Self {
                session: Session::new(),
                handle: None,
                last_rx: None,
                last_tx: None,
                next_connect_at: None,
                backoff: INITIAL_BACKOFF,
                generation: 0,
                pending_ack: None,
            }
        }
    }

    thread_local! {
        static CONFIG: RefCell<Option<AmqpConfig>> = const { RefCell::new(None) };
        static STATE: RefCell<TransportState> = RefCell::new(TransportState::default());
        static BUFFER: RefCell<VecDeque<QueuedInbound>> = const { RefCell::new(VecDeque::new()) };
    }

    fn schedule_backoff(state: &mut TransportState) {
        state.next_connect_at = Some(Instant::now() + state.backoff);
        state.backoff = (state.backoff * 2).min(MAX_BACKOFF);
    }

    fn clear_connection(state: &mut TransportState) {
        if let Some(handle) = state.handle.take() {
            socket::tcp_close(handle);
        }
        state.session = Session::new();
        state.last_rx = None;
        state.last_tx = None;
        state.pending_ack = None;
        BUFFER.with(|buffer| buffer.borrow_mut().clear());
    }

    fn teardown_with_backoff(state: &mut TransportState) {
        clear_connection(state);
        schedule_backoff(state);
    }

    fn send_bytes(state: &mut TransportState, handle: u64, bytes: &[u8]) -> Result<(), String> {
        socket::tcp_send(handle, bytes).map_err(|error| format!("amqp socket send: {error}"))?;
        state.last_tx = Some(Instant::now());
        Ok(())
    }

    fn ensure_connected(state: &mut TransportState, config: &AmqpConfig) {
        if state.handle.is_some() || !config.enabled {
            return;
        }
        if let Some(next) = state.next_connect_at {
            if Instant::now() < next {
                return;
            }
        }
        state.next_connect_at = None;

        let Ok(endpoint) = config.endpoint() else {
            schedule_backoff(state);
            return;
        };
        match socket::tcp_connect(&endpoint.host, endpoint.port, endpoint.tls) {
            Ok(handle) => {
                let now = Instant::now();
                state.handle = Some(handle);
                state.session = Session::new();
                state.last_rx = Some(now);
                state.last_tx = Some(now);
                state.generation = state.generation.wrapping_add(1);
                if send_bytes(state, handle, PROTOCOL_HEADER).is_err() {
                    teardown_with_backoff(state);
                }
            }
            Err(_) => schedule_backoff(state),
        }
    }

    fn maintain_heartbeat(state: &mut TransportState, handle: u64) -> bool {
        let heartbeat_secs = state.session.heartbeat_secs();
        if heartbeat_secs == 0 {
            return true;
        }
        let heartbeat = Duration::from_secs(u64::from(heartbeat_secs));
        if state
            .last_rx
            .is_some_and(|last_rx| last_rx.elapsed() >= heartbeat * 2)
        {
            teardown_with_backoff(state);
            return false;
        }
        let send_interval = Duration::from_secs(u64::from((heartbeat_secs / 2).max(1)));
        if state
            .last_tx
            .is_none_or(|last_tx| last_tx.elapsed() >= send_interval)
            && send_bytes(state, handle, &encode_heartbeat()).is_err()
        {
            teardown_with_backoff(state);
            return false;
        }
        true
    }

    fn queue_delivery(
        state: &mut TransportState,
        config: &AmqpConfig,
        delivery: crate::amqp::Delivery,
    ) -> Result<(), String> {
        BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            if buffer.len() >= MAX_BUFFERED_DELIVERIES {
                return Err("amqp: inbound handoff buffer is full".to_string());
            }
            let delivery_tag = delivery.delivery_tag;
            buffer.push_back(QueuedInbound {
                generation: state.generation,
                delivery_tag,
                mapped: map_delivery(config, &delivery),
            });
            Ok(())
        })
    }

    fn apply_actions(
        state: &mut TransportState,
        config: &AmqpConfig,
        handle: u64,
        actions: Vec<Action>,
    ) -> bool {
        for action in actions {
            match action {
                Action::Send(bytes) => {
                    if send_bytes(state, handle, &bytes).is_err() {
                        teardown_with_backoff(state);
                        return false;
                    }
                }
                Action::Delivery(delivery) => {
                    if queue_delivery(state, config, delivery).is_err() {
                        teardown_with_backoff(state);
                        return false;
                    }
                }
                Action::Ready => {
                    state.backoff = INITIAL_BACKOFF;
                    state.next_connect_at = None;
                }
                Action::Reconnect { reply, reason: _ } => {
                    if let Some(reply) = reply {
                        let _ = send_bytes(state, handle, &reply);
                    }
                    teardown_with_backoff(state);
                    return false;
                }
            }
        }
        true
    }

    /// Advance timers and drain a bounded number of immediately available raw
    /// chunks. `tcp_receive` itself is nonblocking and returns `idle`.
    fn drive(config: &AmqpConfig) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            ensure_connected(&mut state, config);
            let Some(handle) = state.handle else {
                return;
            };
            if !maintain_heartbeat(&mut state, handle) {
                return;
            }
            if BUFFER.with(|buffer| !buffer.borrow().is_empty()) {
                return;
            }

            for _ in 0..DRAIN_BATCH {
                match socket::tcp_receive(handle) {
                    Ok(SocketEvent::Data(bytes)) => {
                        state.last_rx = Some(Instant::now());
                        let actions = match state.session.receive(config, &bytes) {
                            Ok(actions) => actions,
                            Err(_) => {
                                teardown_with_backoff(&mut state);
                                break;
                            }
                        };
                        if !apply_actions(&mut state, config, handle, actions) {
                            break;
                        }
                        if BUFFER.with(|buffer| !buffer.borrow().is_empty()) {
                            break;
                        }
                    }
                    Ok(SocketEvent::Idle) => break,
                    Ok(SocketEvent::Closed(_)) | Err(_) => {
                        teardown_with_backoff(&mut state);
                        break;
                    }
                }
            }
        });
    }

    fn timestamp_ms() -> u64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        u64::try_from(millis).unwrap_or(u64::MAX)
    }

    fn pop_inbound(config: &AmqpConfig) -> Option<InboundMessage> {
        let queued = BUFFER.with(|buffer| buffer.borrow_mut().pop_front())?;
        if config.durable_ack {
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.pending_ack = Some((queued.generation, queued.delivery_tag));
            });
        }

        Some(InboundMessage {
            id: format!("amqp_{}_{}", queued.generation, queued.delivery_tag),
            sender: queued.mapped.sender,
            reply_target: queued.mapped.reply_target,
            content: queued.mapped.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: timestamp_ms(),
            thread_ts: queued.mapped.thread_ts,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        })
    }

    fn acknowledge_previous_handoff() {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let Some((generation, delivery_tag)) = state.pending_ack.take() else {
                return;
            };
            if state.generation != generation || !state.session.is_ready() {
                return;
            }
            let Some(handle) = state.handle else {
                return;
            };
            if send_bytes(&mut state, handle, &encode_ack(delivery_tag)).is_err() {
                teardown_with_backoff(&mut state);
            }
        });
    }

    struct AmqpChannel;

    impl PluginInfo for AmqpChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for AmqpChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let config = AmqpConfig::from_json(&config)?;
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                clear_connection(&mut state);
                *state = TransportState::default();
            });
            CONFIG.with(|stored| *stored.borrow_mut() = Some(config));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err("amqp: binary attachments are unsupported".to_string());
            }
            let config = CONFIG
                .with(|stored| stored.borrow().clone())
                .ok_or_else(|| "amqp: channel is not configured".to_string())?;
            if !config.enabled {
                return Err("amqp: channel is disabled".to_string());
            }
            if message.recipient.is_empty() {
                return Err("amqp: recipient must be an AMQP routing key".to_string());
            }

            drive(&config);
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                let handle = state
                    .handle
                    .ok_or_else(|| "amqp: broker connection is not ready".to_string())?;
                let correlation_id = message
                    .in_reply_to
                    .as_deref()
                    .or(message.thread_ts.as_deref());
                let payload = state.session.encode_publish(
                    &config.exchange,
                    &message.recipient,
                    message.content.as_bytes(),
                    message.subject.as_deref(),
                    correlation_id,
                )?;
                if let Err(error) = send_bytes(&mut state, handle, &payload) {
                    teardown_with_backoff(&mut state);
                    return Err(error);
                }
                Ok(())
            })
        }

        fn poll_message() -> Option<InboundMessage> {
            let config = CONFIG.with(|stored| stored.borrow().clone())?;
            if !config.enabled {
                return None;
            }
            // The host calls poll again only after it has handled the previous
            // return value, so this is the first safe point to acknowledge it.
            acknowledge_previous_handoff();
            drive(&config);
            pop_inbound(&config)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
        }

        fn health_check() -> bool {
            let Some(config) = CONFIG.with(|stored| stored.borrow().clone()) else {
                return false;
            };
            if !config.enabled {
                return false;
            }
            drive(&config);
            STATE.with(|state| {
                let state = state.borrow();
                state.handle.is_some() && state.session.is_ready()
            })
        }

        fn self_handle() -> Option<String> {
            // `sender_label` identifies the external AMQP source. Advertising
            // it as this plugin's own handle would make the host self-loop guard
            // drop every inbound delivery because both strings are identical.
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

        fn update_draft(
            _recipient: String,
            _message_id: String,
            _text: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn update_draft_progress(
            _recipient: String,
            _message_id: String,
            _text: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn finalize_draft(
            _recipient: String,
            _message_id: String,
            _text: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn cancel_draft(_recipient: String, _message_id: String) -> Result<(), String> {
            Ok(())
        }

        fn supports_multi_message_streaming() -> bool {
            false
        }

        fn multi_message_delay_ms() -> u64 {
            800
        }

        fn add_reaction(
            _channel_id: String,
            _message_id: String,
            _emoji: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn remove_reaction(
            _channel_id: String,
            _message_id: String,
            _emoji: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn pin_message(_channel_id: String, _message_id: String) -> Result<(), String> {
            Ok(())
        }

        fn unpin_message(_channel_id: String, _message_id: String) -> Result<(), String> {
            Ok(())
        }

        fn redact_message(
            _channel_id: String,
            _message_id: String,
            _reason: Option<String>,
        ) -> Result<(), String> {
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
            false
        }

        fn webhook_path() -> Option<String> {
            None
        }

        fn parse_webhook(
            _headers: Vec<(String, String)>,
            _body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            Err(WebhookRejection::BadRequest(
                "amqp: webhook ingress is unsupported; use the socket consumer".to_string(),
            ))
        }
    }

    export!(AmqpChannel);
}
