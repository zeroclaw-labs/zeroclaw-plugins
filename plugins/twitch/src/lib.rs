//! A ZeroClaw WIT channel plugin for Twitch chat over IRC/TLS.
//!
//! The pure protocol implementation lives in [`twitch`]. The WASM-only shim
//! drives it through the host-mediated `socket` import, keeping every receive
//! call bounded and nonblocking.

pub mod twitch;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-sockets"],
    });

    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::twitch::{
        encode_privmsg, registration_frame, Inbound, ProtocolAction, ProtocolSession, TwitchConfig,
        CHANNEL, IRC_HOST, IRC_PORT, IRC_TLS,
    };
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };
    use zeroclaw::plugin::socket::{self, SocketEvent};

    const PLUGIN_VERSION: &str = "0.1.0";
    const MAX_DRAIN_PER_POLL: usize = 128;
    const MAX_INBOUND_QUEUE: usize = 512;
    const INITIAL_RECONNECT_DELAY_MS: u64 = 1_000;
    const MAX_RECONNECT_DELAY_MS: u64 = 60_000;

    thread_local! {
        static CONFIG: RefCell<TwitchConfig> = RefCell::new(TwitchConfig::default());
        static CONNECTION: Cell<Option<u64>> = const { Cell::new(None) };
        static SESSION: RefCell<ProtocolSession> = RefCell::new(ProtocolSession::default());
        static INBOUND: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        static RECONNECT_AT_MS: Cell<u64> = const { Cell::new(0) };
        static RECONNECT_DELAY_MS: Cell<u64> = const { Cell::new(INITIAL_RECONNECT_DELAY_MS) };
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .unwrap_or(0)
    }

    fn emit(level: LogLevel, action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            level,
            &PluginEvent {
                function_name: "twitch::channel".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    fn reset_backoff() {
        RECONNECT_AT_MS.with(|state| state.set(0));
        RECONNECT_DELAY_MS.with(|state| state.set(INITIAL_RECONNECT_DELAY_MS));
    }

    fn schedule_reconnect() {
        let delay = RECONNECT_DELAY_MS.with(Cell::get);
        RECONNECT_AT_MS.with(|state| state.set(now_ms().saturating_add(delay)));
        RECONNECT_DELAY_MS.with(|state| {
            state.set(delay.saturating_mul(2).min(MAX_RECONNECT_DELAY_MS));
        });
    }

    fn reset_session() {
        SESSION.with(|state| *state.borrow_mut() = ProtocolSession::default());
    }

    fn reset_transport() {
        if let Some(handle) = CONNECTION.with(Cell::get) {
            socket::tcp_close(handle);
        }
        CONNECTION.with(|state| state.set(None));
        reset_session();
        INBOUND.with(|state| state.borrow_mut().clear());
        reset_backoff();
    }

    fn disconnect(handle: u64, reason: &str) {
        socket::tcp_close(handle);
        if CONNECTION.with(Cell::get) == Some(handle) {
            CONNECTION.with(|state| state.set(None));
        }
        reset_session();
        schedule_reconnect();
        emit(
            LogLevel::Warn,
            PluginAction::Disconnect,
            PluginOutcome::Failure,
            reason,
        );
    }

    fn connect() -> Option<u64> {
        if now_ms() < RECONNECT_AT_MS.with(Cell::get) {
            return None;
        }
        let registration = CONFIG.with(|state| registration_frame(&state.borrow()));
        let registration = match registration {
            Ok(frame) => frame,
            Err(error) => {
                schedule_reconnect();
                emit(
                    LogLevel::Error,
                    PluginAction::Connect,
                    PluginOutcome::Failure,
                    &error,
                );
                return None;
            }
        };
        let handle = match socket::tcp_connect(IRC_HOST, IRC_PORT, IRC_TLS) {
            Ok(handle) => handle,
            Err(error) => {
                schedule_reconnect();
                emit(
                    LogLevel::Warn,
                    PluginAction::Connect,
                    PluginOutcome::Failure,
                    &format!("twitch: TLS connection failed: {error}"),
                );
                return None;
            }
        };
        reset_session();
        if let Err(error) = socket::tcp_send(handle, &registration) {
            socket::tcp_close(handle);
            schedule_reconnect();
            emit(
                LogLevel::Warn,
                PluginAction::Register,
                PluginOutcome::Failure,
                &format!("twitch: IRC registration send failed: {error}"),
            );
            return None;
        }
        CONNECTION.with(|state| state.set(Some(handle)));
        emit(
            LogLevel::Info,
            PluginAction::Connect,
            PluginOutcome::Success,
            "twitch: connected to IRC over TLS",
        );
        Some(handle)
    }

    fn queue_inbound(message: Inbound) {
        let queued = INBOUND.with(|state| {
            let mut queue = state.borrow_mut();
            if queue.len() < MAX_INBOUND_QUEUE {
                queue.push_back(message);
                true
            } else {
                false
            }
        });
        if !queued {
            emit(
                LogLevel::Warn,
                PluginAction::Skip,
                PluginOutcome::Failure,
                "twitch: inbound queue is full; dropping message",
            );
        }
    }

    fn process_actions(handle: u64, actions: Vec<ProtocolAction>) -> bool {
        for action in actions {
            match action {
                ProtocolAction::Send(frame) => {
                    if let Err(error) = socket::tcp_send(handle, &frame) {
                        disconnect(
                            handle,
                            &format!("twitch: IRC protocol send failed: {error}"),
                        );
                        return false;
                    }
                }
                ProtocolAction::Inbound(message) => queue_inbound(message),
                ProtocolAction::Ready => {
                    reset_backoff();
                    emit(
                        LogLevel::Info,
                        PluginAction::Register,
                        PluginOutcome::Success,
                        "twitch: authenticated and joined configured channels",
                    );
                }
                ProtocolAction::Disconnect(reason) => {
                    disconnect(handle, &reason);
                    return false;
                }
            }
        }
        true
    }

    fn pop_inbound() -> Option<InboundMessage> {
        INBOUND
            .with(|state| state.borrow_mut().pop_front())
            .map(to_wit)
    }

    fn to_wit(message: Inbound) -> InboundMessage {
        InboundMessage {
            id: message.id,
            sender: message.sender,
            reply_target: message.reply_target,
            content: message.content,
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp: message.timestamp_ms.unwrap_or_else(now_ms),
            thread_ts: message.thread_id,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct TwitchChannel;

    impl PluginInfo for TwitchChannel {
        fn plugin_name() -> String {
            CHANNEL.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for TwitchChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let next = TwitchConfig::from_json(&config)?;
            next.validate()?;
            reset_transport();
            CONFIG.with(|state| *state.borrow_mut() = next);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err("twitch: media attachments are not supported".to_string());
            }
            let handle = CONNECTION
                .with(Cell::get)
                .ok_or_else(|| "twitch: IRC is not connected".to_string())?;
            if !SESSION.with(|state| state.borrow().is_ready()) {
                return Err("twitch: IRC registration is not ready".to_string());
            }
            let frames = encode_privmsg(
                &message.recipient,
                &message.content,
                message.thread_ts.as_deref(),
            )?;
            for frame in frames {
                if let Err(error) = socket::tcp_send(handle, &frame) {
                    let reason = format!("twitch: PRIVMSG send failed: {error}");
                    disconnect(handle, &reason);
                    return Err(reason);
                }
            }
            emit(
                LogLevel::Info,
                PluginAction::Send,
                PluginOutcome::Success,
                "twitch: sent PRIVMSG",
            );
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(message) = pop_inbound() {
                return Some(message);
            }
            if !CONFIG.with(|state| state.borrow().enabled) {
                return None;
            }
            let handle = CONNECTION.with(Cell::get).or_else(connect)?;

            for _ in 0..MAX_DRAIN_PER_POLL {
                match socket::tcp_receive(handle) {
                    Ok(SocketEvent::Data(chunk)) => {
                        let actions = CONFIG.with(|config| {
                            SESSION.with(|session| {
                                session.borrow_mut().receive(&chunk, &config.borrow())
                            })
                        });
                        if !process_actions(handle, actions) {
                            break;
                        }
                    }
                    Ok(SocketEvent::Idle) => break,
                    Ok(SocketEvent::Closed(reason)) => {
                        disconnect(handle, &format!("twitch: IRC connection closed: {reason}"));
                        break;
                    }
                    Err(error) => {
                        disconnect(handle, &format!("twitch: IRC receive failed: {error}"));
                        break;
                    }
                }
            }
            pop_inbound()
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::SELF_HANDLE
                | ChannelCapabilities::SELF_ADDRESSED_MENTION
                | ChannelCapabilities::DROP_SELF_MESSAGE
        }

        fn health_check() -> bool {
            CONNECTION.with(Cell::get).is_some() && SESSION.with(|state| state.borrow().is_ready())
        }

        fn self_handle() -> Option<String> {
            CONFIG.with(|state| state.borrow().normalized_username().ok())
        }

        fn self_addressed_mention() -> Option<String> {
            Self::self_handle()
        }

        fn drop_self_message(msg: InboundMessage) -> bool {
            Self::self_handle().is_some_and(|username| msg.sender.eq_ignore_ascii_case(&username))
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
                "twitch: this channel does not serve webhooks".to_string(),
            ))
        }
    }

    export!(TwitchChannel);
}
