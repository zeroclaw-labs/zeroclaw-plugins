//! A ZeroClaw WIT **channel** plugin: Nostr (WebSocket relay).
//!
//! Nostr has no HTTP polling surface: a client keeps a persistent WebSocket to a
//! relay, sends a `["REQ", ...]` subscription, and drains `["EVENT", ...]`
//! frames. A plugin can't open a socket inside the WASI sandbox, so the host
//! owns it: this shim drives the relay protocol over the host's `websocket`
//! resource (`wit/next`, gated by the `websocket_client` permission and the
//! instance's egress grant) exactly as the sibling HTTP plugins drive
//! `wasi:http`. Config arrives through `config.get`; the private key is an
//! `x-secret` read through `secrets.get`.
//!
//! Scope (v0.1.0): **receive-only, plaintext notes** — it proves the WebSocket
//! round-trip by subscribing (kind 1) and surfacing each received note as an
//! inbound message. Encrypted DMs (NIP-04 kind 4 / NIP-17) are not decrypted and
//! outbound `send` is not implemented, because both need secp256k1 (schnorr) +
//! AES that are too heavy for the pure core; see the README for the follow-up.
//!
//! The pure relay-protocol logic lives in [`nostr`] (no wasm/socket deps) and is
//! covered by a host `cargo test`; this file is the thin component shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod nostr;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/next",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::{HashSet, VecDeque};

    use crate::nostr::{
        decode_cursor, decode_relay_message, encode_cursor, event_to_inbound, should_emit,
        since_after, Inbound, NostrConfig, RelayMessage, CURSOR_KEY,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::config;
    use zeroclaw::plugin::secrets::{self, SecretError};
    use zeroclaw::plugin::state::{self, StateError};
    use zeroclaw::plugin::websocket::{self, ConnectOptions, Connection, Event, Message};

    const PLUGIN_NAME: &str = "nostr";
    const PLUGIN_VERSION: &str = "0.1.0";

    /// Max frames drained per `poll_message` so a busy relay never starves the
    /// caller's back-off loop.
    const MAX_DRAIN_PER_POLL: usize = 200;

    /// Cap on the de-dup set; cleared wholesale when exceeded (a rare, harmless
    /// re-emit after a clear is acceptable for a receive-only feed).
    const SEEN_CAP: usize = 4096;

    thread_local! {
        static CONFIG: RefCell<NostrConfig> = RefCell::new(NostrConfig::default());
        // The live relay connection; dropping it closes the socket.
        static CONN: RefCell<Option<Connection>> = const { RefCell::new(None) };
        // Whether the REQ has been sent on the current connection.
        static SUBSCRIBED: Cell<bool> = const { Cell::new(false) };
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        // Event ids already surfaced, to suppress relay/reconnect duplicates.
        static SEEN: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
        // Durable delivery cursor: the newest delivered note's `created_at`
        // and the state revision it was stored at. `None` until loaded.
        static CURSOR: RefCell<Option<(u64, Option<u64>)>> = const { RefCell::new(None) };
    }

    /// Load the durable delivery cursor. State that is unavailable or not
    /// granted leaves the channel working without persistence.
    fn load_cursor() -> (u64, Option<u64>) {
        let loaded = match state::get(CURSOR_KEY) {
            Ok(Some(entry)) => (
                decode_cursor(&entry.value).unwrap_or(0),
                Some(entry.revision),
            ),
            Ok(None) | Err(_) => (0, None),
        };
        CURSOR.with(|c| *c.borrow_mut() = Some(loaded));
        loaded
    }

    /// Advance the durable cursor to `created_at` if it is newer. A conflict
    /// means another store of this instance wrote first: re-read, keep the
    /// newer of the two, and try once more.
    fn advance_cursor(created_at: u64) {
        for _ in 0..2 {
            let (current, revision) = CURSOR.with(|c| *c.borrow()).unwrap_or((0, None));
            if created_at <= current {
                return;
            }
            match state::put(CURSOR_KEY, &encode_cursor(created_at), revision) {
                Ok(next) => {
                    CURSOR.with(|c| *c.borrow_mut() = Some((created_at, Some(next))));
                    return;
                }
                Err(StateError::Conflict) => {
                    load_cursor();
                }
                Err(_) => return,
            }
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
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    /// Record `id` as seen; returns `true` the first time (i.e. it should be
    /// emitted), `false` on a duplicate.
    fn first_sighting(id: &str) -> bool {
        if id.is_empty() {
            return false;
        }
        SEEN.with(|s| {
            let mut set = s.borrow_mut();
            if set.contains(id) {
                return false;
            }
            if set.len() >= SEEN_CAP {
                set.clear();
            }
            set.insert(id.to_string());
            true
        })
    }

    /// Close and forget the current connection so the next poll redials.
    /// Dropping the resource closes the socket and releases the host's slot.
    fn drop_connection() {
        CONN.with(|c| *c.borrow_mut() = None);
        SUBSCRIBED.with(|s| s.set(false));
    }

    /// Typed public config from `config.get`, plus the `x-secret` private key.
    fn load_config() -> Result<NostrConfig, String> {
        let public = config::get().map_err(|error| format!("nostr: config: {error:?}"))?;
        let mut value: serde_json::Value =
            serde_json::from_str(&public).map_err(|error| format!("nostr: config: {error}"))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| "nostr: config is not an object".to_string())?;
        match secrets::get("private_key") {
            Ok(key) => {
                object.insert("private_key".to_string(), serde_json::Value::String(key));
            }
            Err(SecretError::NotFound) => {}
            Err(error) => return Err(format!("nostr: secret private_key: {error:?}")),
        }
        Ok(NostrConfig::from_json(&value.to_string()))
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

        fn configure() -> Result<(), String> {
            let cfg = load_config()?;
            // A fresh config invalidates any live connection; redial lazily.
            drop_connection();
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        /// Receive-only in v0.1.0. Publishing a note requires schnorr-signing the
        /// event with secp256k1, which is deferred (see the README); we fail
        /// loudly rather than silently dropping the agent's reply.
        fn send(_message: SendMessage) -> Result<(), String> {
            Err(
                "nostr plugin v0.1.0 is receive-only; outbound publish (schnorr/secp256k1 \
                 event signing) is a planned follow-up"
                    .to_string(),
            )
        }

        fn poll_message() -> Option<InboundMessage> {
            // 1) Anything already decoded?
            if let Some(inb) = BUFFER.with(|b| b.borrow_mut().pop_front()) {
                return Some(to_wit(inb));
            }

            let cfg = CONFIG.with(|c| c.borrow().clone());
            let relay = cfg.first_relay()?.to_string();

            // 2) Ensure a live connection (redial on the next poll if it fails).
            if CONN.with(|c| c.borrow().is_none()) {
                let connection = websocket::connect(&ConnectOptions {
                    url: relay,
                    headers: Vec::new(),
                    subprotocols: Vec::new(),
                    tls_profile: cfg.tls_profile.clone(),
                })
                .ok()?;
                CONN.with(|c| *c.borrow_mut() = Some(connection));
                SUBSCRIBED.with(|s| s.set(false));
            }

            // 3) Subscribe once per connection, resuming after the newest
            //    note a previous run of this instance delivered.
            if !SUBSCRIBED.with(Cell::get) {
                let (cursor, _) = load_cursor();
                let since = since_after((cursor > 0).then_some(cursor));
                let frame = cfg.build_req_frame_since(since);
                let sent = CONN.with(|c| {
                    c.borrow()
                        .as_ref()
                        .map(|conn| conn.send(&Message::Text(frame.clone())))
                });
                match sent {
                    Some(Ok(())) => SUBSCRIBED.with(|s| s.set(true)),
                    _ => {
                        drop_connection();
                        return None;
                    }
                }
            }

            // 4) Drain a bounded batch of frames into the buffer.
            for _ in 0..MAX_DRAIN_PER_POLL {
                let received = CONN.with(|c| c.borrow().as_ref().map(Connection::receive));
                match received? {
                    Ok(Some(Event::Message(Message::Text(frame)))) => {
                        if let RelayMessage::Event { event, .. } = decode_relay_message(&frame) {
                            let (cursor, _) = CURSOR.with(|c| *c.borrow()).unwrap_or((0, None));
                            let already_delivered = cursor > 0 && event.created_at <= cursor;
                            if should_emit(&cfg, &event)
                                && !already_delivered
                                && first_sighting(&event.id)
                            {
                                let inb = event_to_inbound(&event, None);
                                BUFFER.with(|b| b.borrow_mut().push_back(inb));
                                advance_cursor(event.created_at);
                            }
                        }
                    }
                    // Binary frames carry no Nostr protocol messages.
                    Ok(Some(Event::Message(Message::Binary(_)))) => {}
                    // No frame ready — stop draining and let the host back off.
                    Ok(None) => break,
                    // Connection ended (or errored); redial on the next poll.
                    Ok(Some(Event::Closed(_) | Event::Failed(_))) | Err(_) => {
                        drop_connection();
                        break;
                    }
                }
            }

            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::SELF_HANDLE
        }

        fn health_check() -> bool {
            // Healthy when we have somewhere to connect; the socket itself is
            // host-owned and reconnected lazily by `poll_message`.
            CONFIG.with(|c| !c.borrow().relays.is_empty())
        }

        /// Our own hex pubkey, when configured — lets the runtime's self-loop
        /// guard drop notes we authored ourselves.
        fn self_handle() -> Option<String> {
            CONFIG.with(|c| c.borrow().pubkey.clone())
        }

        // ── capability-gated stubs (documented WIT defaults) ──
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
                "this channel does not serve webhooks".to_string(),
            ))
        }
    }

    export!(NostrChannel);
}
