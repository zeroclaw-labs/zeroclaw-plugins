//! A ZeroClaw WIT **channel** plugin: Nostr (WebSocket relay).
//!
//! Nostr has no HTTP polling surface: a client keeps a persistent WebSocket to a
//! relay, sends a `["REQ", ...]` subscription, and drains `["EVENT", ...]`
//! frames. A plugin can't open a socket inside the WASI sandbox, so the host
//! owns it: this shim drives the relay protocol over the host-mediated
//! `ws-client` import (gated by the `websocket_client` permission) exactly as
//! the sibling HTTP plugins drive `wasi:http`.
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
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::{HashSet, VecDeque};

    use crate::nostr::{
        decode_relay_message, event_to_inbound, should_emit, Inbound, NostrConfig, RelayMessage,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::ws_client::{self, WsEvent};

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
        // Current ws-client handle; 0 = not connected.
        static CONN: Cell<u64> = const { Cell::new(0) };
        // Whether the REQ has been sent on the current connection.
        static SUBSCRIBED: Cell<bool> = const { Cell::new(false) };
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        // Event ids already surfaced, to suppress relay/reconnect duplicates.
        static SEEN: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
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
    fn drop_connection(handle: u64) {
        ws_client::ws_close(handle);
        CONN.with(|c| c.set(0));
        SUBSCRIBED.with(|s| s.set(false));
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
            let cfg = NostrConfig::from_json(&config);
            // A fresh config invalidates any live connection; redial lazily.
            let handle = CONN.with(Cell::get);
            if handle != 0 {
                ws_client::ws_close(handle);
            }
            CONN.with(|c| c.set(0));
            SUBSCRIBED.with(|s| s.set(false));
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
            let mut handle = CONN.with(Cell::get);
            if handle == 0 {
                match ws_client::ws_connect(&relay, &[]) {
                    Ok(h) => {
                        CONN.with(|c| c.set(h));
                        SUBSCRIBED.with(|s| s.set(false));
                        handle = h;
                    }
                    Err(_e) => return None,
                }
            }

            // 3) Subscribe once per connection.
            if !SUBSCRIBED.with(Cell::get) {
                match ws_client::ws_send_text(handle, &cfg.build_req_frame()) {
                    Ok(()) => SUBSCRIBED.with(|s| s.set(true)),
                    Err(_e) => {
                        drop_connection(handle);
                        return None;
                    }
                }
            }

            // 4) Drain a bounded batch of frames into the buffer.
            for _ in 0..MAX_DRAIN_PER_POLL {
                match ws_client::ws_receive(handle) {
                    Ok(WsEvent::Text(frame)) => {
                        if let RelayMessage::Event { event, .. } = decode_relay_message(&frame) {
                            if should_emit(&cfg, &event) && first_sighting(&event.id) {
                                let inb = event_to_inbound(&event, None);
                                BUFFER.with(|b| b.borrow_mut().push_back(inb));
                            }
                        }
                    }
                    // No frame ready — stop draining and let the host back off.
                    Ok(WsEvent::Idle) => break,
                    // Connection ended (or errored); redial on the next poll.
                    Ok(WsEvent::Closed(_reason)) => {
                        drop_connection(handle);
                        break;
                    }
                    Err(_e) => {
                        drop_connection(handle);
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
