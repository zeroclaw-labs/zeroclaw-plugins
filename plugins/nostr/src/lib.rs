//! Receive signed public Nostr notes over a host-owned WebSocket.
//! The guest verifies NIP-01 authorship before emitting a channel message.
pub mod nostr;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::{HashSet, VecDeque};

    use crate::nostr::{
        decode_cursor, decode_relay_message, encode_cursor, event_to_inbound, should_emit, Inbound,
        NostrConfig, RelayMessage, CURSOR_KEY,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::config;
    use zeroclaw::plugin::state::{self, StateError};
    use zeroclaw::plugin::websocket::{self, ConnectOptions, Connection, Event, Message};

    const PLUGIN_NAME: &str = "nostr";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    fn load_config() -> Result<NostrConfig, String> {
        let public = config::get().map_err(|error| format!("nostr: config: {error:?}"))?;
        Ok(NostrConfig::from_json(&public))
    }

    fn next_inbound() -> Option<InboundMessage> {
        let message = BUFFER.with(|queue| queue.borrow_mut().pop_front())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok();
        if let Some(now) = now {
            advance_cursor((message.timestamp / 1000).min(now.as_secs()));
        }
        Some(to_wit(message))
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
            drop_connection();
            BUFFER.with(|queue| queue.borrow_mut().clear());
            SEEN.with(|seen| seen.borrow_mut().clear());
            CURSOR.with(|cursor| *cursor.borrow_mut() = None);
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(_message: SendMessage) -> Result<(), String> {
            Err("nostr: public-note subscriptions are receive-only".into())
        }

        fn poll_message() -> Option<InboundMessage> {
            // 1) Anything already decoded?
            if let Some(message) = next_inbound() {
                return Some(message);
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
                let since = (cursor > 0).then_some(cursor);
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
                        if let RelayMessage::Event {
                            event,
                            subscription_id,
                        } = decode_relay_message(&frame)
                        {
                            if subscription_id != cfg.subscription_id {
                                continue;
                            }
                            if should_emit(&cfg, &event) && first_sighting(&event.id) {
                                let inb = event_to_inbound(&event, None);
                                BUFFER.with(|b| b.borrow_mut().push_back(inb));
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

            next_inbound()
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::SELF_HANDLE
        }

        fn health_check() -> bool {
            CONN.with(|connection| connection.borrow().is_some())
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
