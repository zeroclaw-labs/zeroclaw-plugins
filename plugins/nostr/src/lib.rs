//! ZeroClaw Nostr channel plugin.
//!
//! The component implements NIP-04 and NIP-17 private messages over the
//! host-mediated WebSocket capability. Cryptography and relay framing live in
//! [`nostr`]; this module is the thin stateful WIT transport adapter.

pub mod nostr;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::nostr::{
        build_auth_frame, build_direct_message, build_event_frame, build_relay_auth_event,
        decode_direct_message, decode_relay_message, DecodedDm, DmProtocol, NostrConfig,
        RelayMessage, SUBSCRIPTION_ID,
    };
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::ws_client::{self, WsEvent};

    const PLUGIN_NAME: &str = "nostr";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const MAX_DRAIN_PER_POLL: usize = 200;
    const MAX_DRAIN_PER_RELAY: usize = 32;
    const SEEN_CAP: usize = 4096;
    const PROTOCOL_CAP: usize = 4096;
    const PENDING_CAP: usize = 128;

    #[derive(Debug, Clone, Default)]
    struct RelayConnection {
        handle: Option<u64>,
        subscribed: bool,
        auth_event_id: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct PendingPublish {
        id: String,
        frame: String,
        awaiting_relays: HashSet<usize>,
    }

    #[derive(Debug, Default)]
    struct RuntimeState {
        connections: Vec<RelayConnection>,
        buffer: VecDeque<DecodedDm>,
        seen: HashSet<String>,
        protocols: HashMap<String, DmProtocol>,
        pending: VecDeque<PendingPublish>,
        listen_started_at_secs: u64,
        next_relay: usize,
    }

    thread_local! {
        static CONFIG: RefCell<Option<NostrConfig>> = const { RefCell::new(None) };
        static STATE: RefCell<RuntimeState> = RefCell::new(RuntimeState::default());
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }

    fn to_wit(message: DecodedDm) -> InboundMessage {
        InboundMessage {
            id: message.id,
            sender: message.sender.clone(),
            reply_target: message.sender,
            content: message.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: message.timestamp_ms,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    fn configured() -> Result<NostrConfig, String> {
        CONFIG
            .with(|config| config.borrow().clone())
            .ok_or_else(|| "nostr channel is not configured".to_string())
    }

    fn close_and_reset() {
        let handles = STATE.with(|state| {
            let mut state = state.borrow_mut();
            let handles = state
                .connections
                .iter_mut()
                .filter_map(|connection| connection.handle.take())
                .collect::<Vec<_>>();
            *state = RuntimeState::default();
            handles
        });
        for handle in handles {
            ws_client::ws_close(handle);
        }
    }

    fn drop_connection(relay_index: usize, handle: u64) {
        ws_client::ws_close(handle);
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(connection) = state.connections.get_mut(relay_index) {
                if connection.handle == Some(handle) {
                    *connection = RelayConnection::default();
                }
            }
        });
    }

    fn ensure_connection(config: &NostrConfig, relay_index: usize) -> Result<(u64, bool), String> {
        if let Some(handle) = STATE.with(|state| {
            state
                .borrow()
                .connections
                .get(relay_index)
                .and_then(|connection| connection.handle)
        }) {
            return Ok((handle, false));
        }
        let relay_url = config
            .relays
            .get(relay_index)
            .ok_or_else(|| "Nostr relay index is out of range".to_string())?;
        let handle = ws_client::ws_connect(relay_url, &[])
            .map_err(|error| format!("failed to connect to Nostr relay {relay_url}: {error}"))?;
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(connection) = state.connections.get_mut(relay_index) {
                *connection = RelayConnection {
                    handle: Some(handle),
                    ..RelayConnection::default()
                };
            }
        });
        Ok((handle, true))
    }

    fn ensure_subscription(
        config: &NostrConfig,
        relay_index: usize,
    ) -> Result<(u64, bool), String> {
        let (handle, newly_connected) = ensure_connection(config, relay_index)?;
        let subscribed = STATE.with(|state| {
            state
                .borrow()
                .connections
                .get(relay_index)
                .is_some_and(|connection| connection.subscribed)
        });
        if !subscribed {
            let frame = config.subscription_frame()?;
            if let Err(error) = ws_client::ws_send_text(handle, &frame) {
                drop_connection(relay_index, handle);
                return Err(format!("failed to subscribe to Nostr relay: {error}"));
            }
            STATE.with(|state| {
                if let Some(connection) = state.borrow_mut().connections.get_mut(relay_index) {
                    connection.subscribed = true;
                }
            });
        }
        Ok((handle, newly_connected))
    }

    fn pending_frames(relay_index: usize) -> Vec<String> {
        STATE.with(|state| {
            state
                .borrow()
                .pending
                .iter()
                .filter(|pending| pending.awaiting_relays.contains(&relay_index))
                .map(|pending| pending.frame.clone())
                .collect()
        })
    }

    fn resend_pending(relay_index: usize, handle: u64) {
        for frame in pending_frames(relay_index) {
            if ws_client::ws_send_text(handle, &frame).is_err() {
                drop_connection(relay_index, handle);
                break;
            }
        }
    }

    fn publish(config: &NostrConfig, event_id: String, frame: String) -> Result<(), String> {
        let mut awaiting_relays = HashSet::new();
        for relay_index in 0..config.relays.len() {
            let Ok((handle, _)) = ensure_connection(config, relay_index) else {
                continue;
            };
            if ws_client::ws_send_text(handle, &frame).is_ok() {
                awaiting_relays.insert(relay_index);
            } else {
                drop_connection(relay_index, handle);
            }
        }
        if awaiting_relays.is_empty() {
            return Err("failed to publish Nostr message to every configured relay".to_string());
        }
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.pending.len() >= PENDING_CAP {
                state.pending.pop_front();
            }
            state.pending.push_back(PendingPublish {
                id: event_id,
                frame,
                awaiting_relays,
            });
        });
        Ok(())
    }

    fn first_sighting(event_id: &str) -> bool {
        if event_id.is_empty() {
            return false;
        }
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.seen.contains(event_id) {
                return false;
            }
            if state.seen.len() >= SEEN_CAP {
                state.seen.clear();
            }
            state.seen.insert(event_id.to_string())
        })
    }

    fn remember_protocol(sender: &str, protocol: DmProtocol) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.protocols.len() >= PROTOCOL_CAP && !state.protocols.contains_key(sender) {
                state.protocols.clear();
            }
            state.protocols.insert(sender.to_string(), protocol);
        });
    }

    fn protocol_for(recipient: &str) -> DmProtocol {
        STATE.with(|state| {
            state
                .borrow()
                .protocols
                .get(recipient)
                .copied()
                .unwrap_or(DmProtocol::Nip17)
        })
    }

    fn handle_publish_ack(
        config: &NostrConfig,
        relay_index: usize,
        event_id: &str,
        accepted: bool,
        message: &str,
    ) {
        let auth_succeeded = STATE.with(|state| {
            let mut state = state.borrow_mut();
            let Some(connection) = state.connections.get_mut(relay_index) else {
                return false;
            };
            if connection.auth_event_id.as_deref() == Some(event_id) {
                connection.auth_event_id = None;
                connection.subscribed = false;
                return accepted;
            }
            let keep_for_auth = !accepted && message.starts_with("auth-required:");
            for pending in &mut state.pending {
                if pending.id == event_id && !keep_for_auth {
                    pending.awaiting_relays.remove(&relay_index);
                }
            }
            state
                .pending
                .retain(|pending| !pending.awaiting_relays.is_empty());
            false
        });

        if auth_succeeded {
            if let Ok((handle, _)) = ensure_subscription(config, relay_index) {
                resend_pending(relay_index, handle);
            }
        }
    }

    fn handle_auth_challenge(
        config: &NostrConfig,
        relay_index: usize,
        challenge: &str,
    ) -> Result<(), String> {
        let relay_url = config
            .relays
            .get(relay_index)
            .ok_or_else(|| "Nostr relay index is out of range".to_string())?;
        let event = build_relay_auth_event(&config.keys, relay_url, challenge, now_secs())?;
        let event_id = event
            .id
            .clone()
            .ok_or_else(|| "NIP-42 auth event is missing id".to_string())?;
        let frame = build_auth_frame(&event)?;
        let (handle, _) = ensure_connection(config, relay_index)?;
        if let Err(error) = ws_client::ws_send_text(handle, &frame) {
            drop_connection(relay_index, handle);
            return Err(format!("failed to send NIP-42 auth event: {error}"));
        }
        STATE.with(|state| {
            if let Some(connection) = state.borrow_mut().connections.get_mut(relay_index) {
                connection.auth_event_id = Some(event_id);
            }
        });
        Ok(())
    }

    fn process_relay_text(config: &NostrConfig, relay_index: usize, frame: &str) {
        let Ok(message) = decode_relay_message(frame) else {
            return;
        };
        match message {
            RelayMessage::Event {
                subscription_id,
                event,
            } if subscription_id == SUBSCRIPTION_ID => {
                let listen_started_at = STATE.with(|state| state.borrow().listen_started_at_secs);
                let Ok(Some(message)) =
                    decode_direct_message(&config.keys, &event, listen_started_at)
                else {
                    return;
                };
                if first_sighting(&message.id) {
                    remember_protocol(&message.sender, message.protocol);
                    STATE.with(|state| state.borrow_mut().buffer.push_back(message));
                }
            }
            RelayMessage::Ok {
                event_id,
                accepted,
                message,
            } => handle_publish_ack(config, relay_index, &event_id, accepted, &message),
            RelayMessage::Auth { challenge } => {
                let _ = handle_auth_challenge(config, relay_index, &challenge);
            }
            RelayMessage::Closed {
                subscription_id, ..
            } if subscription_id == SUBSCRIPTION_ID => {
                STATE.with(|state| {
                    if let Some(connection) = state.borrow_mut().connections.get_mut(relay_index) {
                        connection.subscribed = false;
                    }
                });
            }
            _ => {}
        }
    }

    fn drain_relays(config: &NostrConfig) {
        let relay_count = config.relays.len();
        if relay_count == 0 {
            return;
        }
        let start = STATE.with(|state| state.borrow().next_relay % relay_count);
        let mut drained = 0_usize;

        for offset in 0..relay_count {
            if drained >= MAX_DRAIN_PER_POLL {
                break;
            }
            let relay_index = (start + offset) % relay_count;
            let Ok((handle, newly_connected)) = ensure_subscription(config, relay_index) else {
                continue;
            };
            if newly_connected {
                resend_pending(relay_index, handle);
            }
            for _ in 0..MAX_DRAIN_PER_RELAY {
                if drained >= MAX_DRAIN_PER_POLL {
                    break;
                }
                match ws_client::ws_receive(handle) {
                    Ok(WsEvent::Text(frame)) => {
                        drained += 1;
                        process_relay_text(config, relay_index, &frame);
                    }
                    Ok(WsEvent::Idle) => break,
                    Ok(WsEvent::Closed(_)) | Err(_) => {
                        drop_connection(relay_index, handle);
                        break;
                    }
                }
            }
        }

        STATE.with(|state| state.borrow_mut().next_relay = (start + 1) % relay_count);
    }

    struct NostrChannel;

    impl PluginInfo for NostrChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for NostrChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let config = NostrConfig::from_json(&config)?;
            close_and_reset();
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.connections = vec![RelayConnection::default(); config.relays.len()];
                state.listen_started_at_secs = now_secs();
            });
            CONFIG.with(|stored| *stored.borrow_mut() = Some(config));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err("nostr plugin supports text messages only".to_string());
            }
            let config = configured()?;
            let recipient = crate::nostr::normalize_public_key(&message.recipient)?;
            let protocol = protocol_for(&recipient);
            let event = build_direct_message(
                &config.keys,
                &recipient,
                &message.content,
                protocol,
                now_secs(),
            )?;
            let event_id = event
                .id
                .clone()
                .ok_or_else(|| "outbound Nostr event is missing id".to_string())?;
            let frame = build_event_frame(&event)?;
            publish(&config, event_id, frame)
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(message) = STATE.with(|state| state.borrow_mut().buffer.pop_front()) {
                return Some(to_wit(message));
            }
            let config = CONFIG.with(|stored| stored.borrow().clone())?;
            drain_relays(&config);
            STATE
                .with(|state| state.borrow_mut().buffer.pop_front())
                .map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::SELF_HANDLE
        }

        fn health_check() -> bool {
            STATE.with(|state| {
                state
                    .borrow()
                    .connections
                    .iter()
                    .any(|connection| connection.handle.is_some())
            })
        }

        fn self_handle() -> Option<String> {
            CONFIG.with(|stored| {
                stored
                    .borrow()
                    .as_ref()
                    .map(|config| config.keys.public_key())
            })
        }

        fn self_addressed_mention() -> Option<String> {
            None
        }

        fn drop_self_message(_message: InboundMessage) -> bool {
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

    export!(NostrChannel);
}
