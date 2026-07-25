//! A ZeroClaw WIT channel plugin for IRC over host-mediated TLS sockets.

pub mod irc;

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

    use crate::irc::{
        drain_lines, format_privmsg, Inbound, IrcConfig, IrcSession, SessionAction, CHANNEL,
    };
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::socket::{self, SocketEvent};

    const PLUGIN_VERSION: &str = "0.1.0";
    const MAX_DRAIN_PER_POLL: usize = 200;
    const BUFFER_CAPACITY: usize = 1_000;

    thread_local! {
        static CONFIG: RefCell<Option<IrcConfig>> = const { RefCell::new(None) };
        static CONNECTION: Cell<u64> = const { Cell::new(0) };
        static SESSION: RefCell<Option<IrcSession>> = const { RefCell::new(None) };
        static RECEIVE_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static INBOUND: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
        static NEXT_ID: Cell<u64> = const { Cell::new(1) };
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

    fn send_raw(handle: u64, line: &str) -> Result<(), String> {
        if line.contains(['\r', '\n']) {
            return Err("irc: refusing to send an injected protocol line".into());
        }
        let mut bytes = Vec::with_capacity(line.len().saturating_add(2));
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        socket::tcp_send(handle, &bytes)
    }

    fn connect(config: &IrcConfig) -> Result<u64, String> {
        let handle = socket::tcp_connect(&config.server, config.port, true)?;
        let session = IrcSession::new(config);
        for command in session.registration_commands(config) {
            if let Err(error) = send_raw(handle, &command) {
                socket::tcp_close(handle);
                return Err(error);
            }
        }
        SESSION.with(|state| *state.borrow_mut() = Some(session));
        RECEIVE_BUFFER.with(|state| state.borrow_mut().clear());
        CONNECTION.with(|state| state.set(handle));
        Ok(handle)
    }

    fn drop_connection(handle: u64) {
        socket::tcp_close(handle);
        CONNECTION.with(|state| state.set(0));
        SESSION.with(|state| *state.borrow_mut() = None);
        RECEIVE_BUFFER.with(|state| state.borrow_mut().clear());
    }

    fn queue_inbound(message: Inbound) {
        INBOUND.with(|state| {
            let mut queue = state.borrow_mut();
            if queue.len() >= BUFFER_CAPACITY {
                queue.pop_front();
            }
            queue.push_back(message);
        });
    }

    fn process_actions(handle: u64, actions: Vec<SessionAction>) -> Result<(), String> {
        for action in actions {
            match action {
                SessionAction::Send(line) => send_raw(handle, &line)?,
                SessionAction::Message(message) => queue_inbound(message),
            }
        }
        Ok(())
    }

    fn handle_line(handle: u64, config: &IrcConfig, line: &str) -> Result<(), String> {
        let actions = SESSION.with(|state| {
            state
                .borrow_mut()
                .as_mut()
                .ok_or_else(|| "irc: missing session state".to_string())?
                .handle_line(config, line)
        })?;
        process_actions(handle, actions)
    }

    fn to_wit(message: Inbound) -> InboundMessage {
        let sequence = NEXT_ID.with(|state| {
            let sequence = state.get();
            state.set(sequence.wrapping_add(1));
            sequence
        });
        InboundMessage {
            id: format!("irc-{}-{sequence}", now_millis()),
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

    struct IrcChannel;

    impl PluginInfo for IrcChannel {
        fn plugin_name() -> String {
            CHANNEL.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for IrcChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let config = IrcConfig::from_json(&config)?;
            let handle = CONNECTION.with(Cell::get);
            if handle != 0 {
                socket::tcp_close(handle);
            }
            CONFIG.with(|state| *state.borrow_mut() = Some(config));
            CONNECTION.with(|state| state.set(0));
            SESSION.with(|state| *state.borrow_mut() = None);
            RECEIVE_BUFFER.with(|state| state.borrow_mut().clear());
            INBOUND.with(|state| state.borrow_mut().clear());
            NEXT_ID.with(|state| state.set(1));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err("irc: media attachments are not supported".into());
            }
            let handle = CONNECTION.with(Cell::get);
            let registered = SESSION.with(|state| {
                state
                    .borrow()
                    .as_ref()
                    .is_some_and(IrcSession::is_registered)
            });
            if handle == 0 || !registered {
                return Err("irc: not connected and registered".into());
            }
            for line in format_privmsg(&message.recipient, &message.content)? {
                if let Err(error) = send_raw(handle, &line) {
                    drop_connection(handle);
                    return Err(error);
                }
            }
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(message) = INBOUND.with(|state| state.borrow_mut().pop_front()) {
                return Some(to_wit(message));
            }
            let config = CONFIG.with(|state| state.borrow().clone())?;
            let mut handle = CONNECTION.with(Cell::get);
            if handle == 0 {
                handle = connect(&config).ok()?;
            }
            for _ in 0..MAX_DRAIN_PER_POLL {
                match socket::tcp_receive(handle) {
                    Ok(SocketEvent::Data(bytes)) => {
                        let lines = RECEIVE_BUFFER
                            .with(|state| drain_lines(&mut state.borrow_mut(), &bytes));
                        let Ok(lines) = lines else {
                            drop_connection(handle);
                            break;
                        };
                        let mut failed = false;
                        for line in lines {
                            if handle_line(handle, &config, &line).is_err() {
                                failed = true;
                                break;
                            }
                        }
                        if failed {
                            drop_connection(handle);
                            break;
                        }
                    }
                    Ok(SocketEvent::Idle) => break,
                    Ok(SocketEvent::Closed(_)) | Err(_) => {
                        drop_connection(handle);
                        break;
                    }
                }
            }
            INBOUND
                .with(|state| state.borrow_mut().pop_front())
                .map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::SELF_HANDLE
                | ChannelCapabilities::SELF_ADDRESSED_MENTION
        }

        fn health_check() -> bool {
            CONNECTION.with(Cell::get) != 0
                && SESSION.with(|state| {
                    state
                        .borrow()
                        .as_ref()
                        .is_some_and(IrcSession::is_registered)
                })
        }

        fn self_handle() -> Option<String> {
            SESSION
                .with(|state| {
                    state
                        .borrow()
                        .as_ref()
                        .map(|session| session.current_nick().to_string())
                })
                .or_else(|| {
                    CONFIG.with(|state| {
                        state
                            .borrow()
                            .as_ref()
                            .map(|config| config.nickname.clone())
                    })
                })
        }

        fn self_addressed_mention() -> Option<String> {
            Self::self_handle()
        }

        fn drop_self_message(message: InboundMessage) -> bool {
            Self::self_handle().is_some_and(|handle| handle.eq_ignore_ascii_case(&message.sender))
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
                "irc: webhook ingress is unsupported".into(),
            ))
        }
    }

    export!(IrcChannel);
}
