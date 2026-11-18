//! Private-message relay sessions from the NIP-04 / NIP-17 channel.
use super::zeroclaw::plugin::secrets;
use super::zeroclaw::plugin::websocket::{self, ConnectOptions, Connection, Event, Message};
use super::{InboundMessage, SendMessage, PLUGIN_NAME};
use crate::direct::{
    build_auth_frame, build_direct_message, build_event_frame, build_relay_auth_event,
    decode_direct_message, decode_relay_message, DecodedDm, DmProtocol, NostrConfig, RelayMessage,
    SUBSCRIPTION_ID,
};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
pub(super) fn active() -> bool {
    CONFIG.with(|c| c.borrow().is_some())
}
const MAX_DRAIN_PER_POLL: usize = 200;
const MAX_DRAIN_PER_RELAY: usize = 32;
const SEEN_CAP: usize = 4096;
const PROTOCOL_CAP: usize = 4096;
const PENDING_CAP: usize = 128;

#[derive(Debug, Clone, Default)]
struct RelayConnection {
    handle: Option<Rc<Connection>>,
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
    static CONFIG: RefCell<Option<Rc<NostrConfig>>> = const { RefCell::new(None) };
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

fn configured() -> Result<Rc<NostrConfig>, String> {
    CONFIG
        .with(|config| config.borrow().clone())
        .ok_or_else(|| "nostr channel is not configured".to_string())
}

pub(super) fn reset() {
    STATE.with(|state| *state.borrow_mut() = RuntimeState::default());
    CONFIG.with(|config| *config.borrow_mut() = None);
}

fn drop_connection(relay_index: usize) {
    STATE.with(|state| {
        if let Some(connection) = state.borrow_mut().connections.get_mut(relay_index) {
            *connection = RelayConnection::default();
        }
    });
}

fn ensure_connection(
    config: &NostrConfig,
    relay_index: usize,
) -> Result<(Rc<Connection>, bool), String> {
    if let Some(handle) = STATE.with(|state| {
        state
            .borrow()
            .connections
            .get(relay_index)
            .and_then(|connection| connection.handle.clone())
    }) {
        return Ok((handle, false));
    }
    let relay_url = config
        .relays
        .get(relay_index)
        .ok_or_else(|| "Nostr relay index is out of range".to_string())?;
    let handle = websocket::connect(&ConnectOptions {
        url: relay_url.clone(),
        headers: vec![],
        subprotocols: vec![],
        tls_profile: config.tls_profile.clone(),
    })
    .map(Rc::new)
    .map_err(|error| format!("failed to connect to Nostr relay: {error:?}"))?;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(connection) = state.connections.get_mut(relay_index) {
            *connection = RelayConnection {
                handle: Some(handle.clone()),
                ..RelayConnection::default()
            };
        }
    });
    Ok((handle, true))
}

fn ensure_subscription(
    config: &NostrConfig,
    relay_index: usize,
) -> Result<(Rc<Connection>, bool), String> {
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
        if let Err(error) = handle.send(&Message::Text(frame)) {
            drop_connection(relay_index);
            return Err(format!("failed to subscribe to Nostr relay: {error:?}"));
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

fn resend_pending(relay_index: usize, handle: &Connection) {
    for frame in pending_frames(relay_index) {
        if handle.send(&Message::Text(frame)).is_err() {
            drop_connection(relay_index);
            break;
        }
    }
}

fn publish(config: &NostrConfig, event_id: String, frame: String) -> Result<(), String> {
    let message = Message::Text(frame.clone());
    let mut awaiting_relays = HashSet::new();
    for relay_index in 0..config.relays.len() {
        let Ok((handle, _)) = ensure_connection(config, relay_index) else {
            continue;
        };
        if handle.send(&message).is_ok() {
            awaiting_relays.insert(relay_index);
        } else {
            drop_connection(relay_index);
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
            resend_pending(relay_index, &handle);
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
    if let Err(error) = handle.send(&Message::Text(frame)) {
        drop_connection(relay_index);
        return Err(format!("failed to send NIP-42 auth event: {error:?}"));
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
            let Ok(Some(message)) = decode_direct_message(&config.keys, &event, listen_started_at)
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
            resend_pending(relay_index, &handle);
        }
        for _ in 0..MAX_DRAIN_PER_RELAY {
            if drained >= MAX_DRAIN_PER_POLL {
                break;
            }
            match handle.receive() {
                Ok(Some(Event::Message(Message::Text(frame)))) => {
                    drained += 1;
                    process_relay_text(config, relay_index, &frame);
                }
                Ok(Some(Event::Message(Message::Binary(_)))) => {
                    drained += 1;
                }
                Ok(None) => break,
                Ok(Some(Event::Failed(_) | Event::Closed(_))) | Err(_) => {
                    drop_connection(relay_index);
                    break;
                }
            }
        }
    }

    STATE.with(|state| state.borrow_mut().next_relay = (start + 1) % relay_count);
}

pub(super) fn configure(public: &str) -> Result<(), String> {
    let mut value: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(public).map_err(|_| "nostr: invalid private-message configuration")?;
    let key = secrets::get("private_key")
        .map_err(|error| format!("nostr: direct_messages requires private_key: {error:?}"))?;
    value.insert("private_key".into(), key.into());
    let config = NostrConfig::from_json(&serde_json::Value::Object(value).to_string())?;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.connections = vec![RelayConnection::default(); config.relays.len()];
        state.listen_started_at_secs = now_secs();
    });
    CONFIG.with(|stored| *stored.borrow_mut() = Some(Rc::new(config)));
    Ok(())
}

pub(super) fn send(message: SendMessage) -> Result<(), String> {
    if !message.attachments.is_empty() {
        return Err("nostr plugin supports text messages only".to_string());
    }
    let config = configured()?;
    let recipient = crate::direct::normalize_public_key(&message.recipient)?;
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

pub(super) fn poll_message() -> Option<InboundMessage> {
    if let Some(message) = STATE.with(|state| state.borrow_mut().buffer.pop_front()) {
        return Some(to_wit(message));
    }
    let config = CONFIG.with(|stored| stored.borrow().clone())?;
    drain_relays(&config);
    STATE
        .with(|state| state.borrow_mut().buffer.pop_front())
        .map(to_wit)
}

pub(super) fn health_check() -> bool {
    STATE.with(|state| {
        state
            .borrow()
            .connections
            .iter()
            .any(|connection| connection.handle.is_some())
    })
}

pub(super) fn self_handle() -> Option<String> {
    CONFIG.with(|stored| {
        stored
            .borrow()
            .as_ref()
            .map(|config| config.keys.public_key())
    })
}
