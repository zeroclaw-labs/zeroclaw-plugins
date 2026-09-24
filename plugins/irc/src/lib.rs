//! A ZeroClaw WIT channel plugin for IRC over host-mediated TLS sockets.
//!
//! Binds `wit/next`: the host's socket resource, typed config through
//! `config.get`, and passwords through `secrets.get`.

pub mod irc;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/next",
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
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::config;
    use zeroclaw::plugin::secrets::{self, SecretError};
    use zeroclaw::plugin::sockets::{self, ConnectMode, ConnectRequest, Connection, ReceiveEvent};

    const PLUGIN_VERSION: &str = "0.1.0";
    const MAX_DRAIN_PER_POLL: usize = 200;
    const BUFFER_CAPACITY: usize = 1_000;

    thread_local! {
        static CONFIG: RefCell<Option<IrcConfig>> = const { RefCell::new(None) };
        static CONNECTION: RefCell<Option<Connection>> = const { RefCell::new(None) };
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

    fn send_raw(connection: &Connection, line: &str) -> Result<(), String> {
        if line.contains(['\r', '\n']) {
            return Err("irc: refusing to send an injected protocol line".into());
        }
        let mut bytes = Vec::with_capacity(line.len().saturating_add(2));
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        connection
            .send(&bytes)
            .map_err(|error| format!("irc: send failed: {error:?}"))
    }

    fn with_connection<T>(use_it: impl FnOnce(&Connection) -> T) -> Option<T> {
        CONNECTION.with(|state| state.borrow().as_ref().map(use_it))
    }

    fn connect(config: &IrcConfig) -> Result<(), String> {
        let connection = sockets::connect(&ConnectRequest {
            host: config.server.clone(),
            port: config.port,
            mode: ConnectMode::DirectTls,
            tls_profile: config.tls_profile.clone(),
        })
        .map_err(|error| format!("irc: connect failed: {error:?}"))?;
        let session = IrcSession::new(config);
        for command in session.registration_commands(config) {
            send_raw(&connection, &command)?;
        }
        SESSION.with(|state| *state.borrow_mut() = Some(session));
        RECEIVE_BUFFER.with(|state| state.borrow_mut().clear());
        CONNECTION.with(|state| *state.borrow_mut() = Some(connection));
        Ok(())
    }

    /// Drop the connection resource, which closes the socket and releases the
    /// host's connection slot.
    fn drop_connection() {
        CONNECTION.with(|state| *state.borrow_mut() = None);
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

    fn process_actions(actions: Vec<SessionAction>) -> Result<(), String> {
        for action in actions {
            match action {
                SessionAction::Send(line) => {
                    with_connection(|connection| send_raw(connection, &line))
                        .unwrap_or_else(|| Err("irc: not connected".into()))?
                }
                SessionAction::Message(message) => queue_inbound(message),
            }
        }
        Ok(())
    }

    fn handle_line(config: &IrcConfig, line: &str) -> Result<(), String> {
        let actions = SESSION.with(|state| {
            state
                .borrow_mut()
                .as_mut()
                .ok_or_else(|| "irc: missing session state".to_string())?
                .handle_line(config, line)
        })?;
        process_actions(actions)
    }

    /// One optional password from the instance's secret config.
    fn optional_secret(name: &str) -> Result<Option<String>, String> {
        match secrets::get(name) {
            Ok(value) => Ok(Some(value)),
            Err(SecretError::NotFound) => Ok(None),
            Err(error) => Err(format!("irc: secret {name}: {error:?}")),
        }
    }

    /// Typed public config from `config.get`, plus the passwords the schema
    /// marks `x-secret`, which the host withholds from public config.
    fn load_config() -> Result<IrcConfig, String> {
        let public = config::get().map_err(|error| format!("irc: config: {error:?}"))?;
        let mut value: serde_json::Value =
            serde_json::from_str(&public).map_err(|error| format!("irc: config: {error}"))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| "irc: config is not an object".to_string())?;
        for name in ["server_password", "nickserv_password", "sasl_password"] {
            if let Some(secret) = optional_secret(name)? {
                object.insert(name.to_string(), serde_json::Value::String(secret));
            }
        }
        IrcConfig::from_json(&value.to_string())
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

        fn configure() -> Result<(), String> {
            let config = load_config()?;
            CONFIG.with(|state| *state.borrow_mut() = Some(config));
            CONNECTION.with(|state| *state.borrow_mut() = None);
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
            let connected = with_connection(|_| ()).is_some();
            let registered = SESSION.with(|state| {
                state
                    .borrow()
                    .as_ref()
                    .is_some_and(IrcSession::is_registered)
            });
            if !connected || !registered {
                return Err("irc: not connected and registered".into());
            }
            for line in format_privmsg(&message.recipient, &message.content)? {
                let sent = with_connection(|connection| send_raw(connection, &line))
                    .unwrap_or_else(|| Err("irc: not connected".into()));
                if let Err(error) = sent {
                    drop_connection();
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
            if with_connection(|_| ()).is_none() {
                connect(&config).ok()?;
            }
            for _ in 0..MAX_DRAIN_PER_POLL {
                match with_connection(Connection::receive)? {
                    Ok(ReceiveEvent::Data(bytes)) => {
                        let lines = RECEIVE_BUFFER
                            .with(|state| drain_lines(&mut state.borrow_mut(), &bytes));
                        let Ok(lines) = lines else {
                            drop_connection();
                            break;
                        };
                        let mut failed = false;
                        for line in lines {
                            if handle_line(&config, &line).is_err() {
                                failed = true;
                                break;
                            }
                        }
                        if failed {
                            drop_connection();
                            break;
                        }
                    }
                    Ok(ReceiveEvent::Idle) => break,
                    Ok(ReceiveEvent::Closed(_)) | Err(_) => {
                        drop_connection();
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
            with_connection(|_| ()).is_some()
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
        fn parse_webhook(_request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            Err(WebhookRejection::BadRequest(
                "irc: webhook ingress is unsupported".into(),
            ))
        }
    }

    export!(IrcChannel);
}
