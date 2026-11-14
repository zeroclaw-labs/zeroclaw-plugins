//! A ZeroClaw channel plugin for IRC over a host-mediated TLS socket.
//!
//! A sandboxed component cannot open a socket, so the host owns the
//! connection: it checks the server against the instance's egress grant,
//! resolves and dials it, completes TLS (with the instance's TLS profile when
//! one is configured), and buffers bytes both ways. This shim speaks IRC over
//! that connection from `poll-message`, one bounded step per call.
//!
//! The protocol decisions live in [`irc`], a pure module covered by host
//! tests; this file performs the I/O they ask for. Only protocol state
//! survives between calls. The public config is read with `config.get` and
//! each password with `secrets.get` at the moment it is sent, and neither is
//! kept, so an edited setting or a rotated password applies on the next use.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

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
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use serde_json::{json, Value};

    use crate::irc::{
        encode_lines, format_privmsg, Action, Backoff, Disconnect, Inbound, IrcConfig, LineBuffer,
        Outbox, Retry, SaslMechanism, Secrets, Session, CHANNEL, SASL_PASSWORD,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::config;
    use zeroclaw::plugin::logging::{self, LogLevel, PluginAction, PluginEvent, PluginOutcome};
    use zeroclaw::plugin::secrets::{self, SecretError};
    use zeroclaw::plugin::sockets::{
        self, CloseReason, ConnectMode, ConnectRequest, Connection, ReceiveEvent, SocketError,
    };

    /// Socket reads per `poll-message`. Each is one host call, out of the
    /// host's 1,000 per call; the rest is left for writes and logging.
    const MAX_READS_PER_POLL: usize = 200;
    /// Messages held for the host. Reading pauses at this many, which leaves
    /// later bytes buffered in the host and the socket.
    const MAX_QUEUED_MESSAGES: usize = 64;
    /// The host accepts at most 16 KiB per socket send.
    const MAX_WRITE_BYTES: usize = 16 * 1024;

    /// Everything one instance keeps between calls.
    struct Instance {
        /// The configured nickname. The host reads the self handle in calls
        /// where config is unavailable, so this one public, config-derived
        /// value is kept from `configure`.
        nickname: String,
        connection: Option<Connection>,
        session: Option<Session>,
        lines: LineBuffer,
        inbox: VecDeque<Inbound>,
        outbox: Outbox,
        backoff: Backoff,
        /// `config.get` failed on the last poll; the connection is paused.
        config_unavailable: bool,
    }

    thread_local! {
        // The component model does not re-enter a guest during a host call, so
        // holding this borrow across one cannot be observed.
        static INSTANCE: RefCell<Option<Instance>> = const { RefCell::new(None) };
        static CLOCK: Instant = Instant::now();
        static SEQUENCE: Cell<u64> = const { Cell::new(0) };
    }

    fn with_instance<R>(f: impl FnOnce(&mut Instance) -> R) -> Option<R> {
        INSTANCE.with(|cell| cell.borrow_mut().as_mut().map(f))
    }

    /// Monotonic milliseconds, for timers.
    fn now_ms() -> u64 {
        CLOCK.with(|origin| u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    /// Wall-clock milliseconds, for message timestamps.
    fn unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(0)
    }

    fn jitter() -> u64 {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(now_ms());
        hasher.finish()
    }

    // ── host services, read at the point of use ──────────────────────────────

    fn public_config() -> Result<IrcConfig, String> {
        let json =
            config::get().map_err(|error| format!("irc: config unavailable ({})", error.name()))?;
        IrcConfig::from_public_json(&json)
    }

    struct HostSecrets;

    impl Secrets for HostSecrets {
        fn get(&mut self, name: &str) -> Result<Option<String>, String> {
            match secrets::get(name) {
                Ok(value) => Ok(Some(value)),
                Err(SecretError::NotFound) => Ok(None),
                Err(error) => Err(error.name().to_string()),
            }
        }
    }

    fn log(
        level: LogLevel,
        action: PluginAction,
        outcome: Option<PluginOutcome>,
        message: &str,
        attrs: Value,
    ) {
        logging::log_record(
            level,
            &PluginEvent {
                function_name: "irc::channel".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: Some(attrs.to_string()),
                message: message.to_string(),
            },
        );
    }

    // ── connection I/O ───────────────────────────────────────────────────────

    /// How one socket write went.
    enum Wrote {
        Done,
        /// The host queue is full or this call's host calls are spent.
        Later,
        Failed(SocketError),
    }

    fn connect_failure(error: SocketError) -> Disconnect {
        let reason = format!("connect failed ({})", error.name());
        match error {
            // The operator has not granted the server, or the TLS profile is
            // missing or broken: retrying soon cannot help.
            SocketError::AccessDenied
            | SocketError::InvalidRequest
            | SocketError::TlsConfigurationFailed => Disconnect {
                retry: Retry::Refused,
                reason,
            },
            _ => Disconnect::transient(reason),
        }
    }

    impl Instance {
        fn new(nickname: String) -> Self {
            Self {
                nickname,
                connection: None,
                session: None,
                lines: LineBuffer::default(),
                inbox: VecDeque::new(),
                outbox: Outbox::default(),
                backoff: Backoff::default(),
                config_unavailable: false,
            }
        }

        fn is_registered(&self) -> bool {
            self.connection.is_some() && self.session.as_ref().is_some_and(Session::is_registered)
        }

        /// One bounded step: connect when due, read, check liveness, and send
        /// whatever chat the pace allows.
        fn step(&mut self, cfg: &IrcConfig) {
            if self.connection.is_none() {
                if !self.backoff.ready(now_ms()) {
                    return;
                }
                self.connect(cfg);
            }
            self.pump(cfg);
            let tick = self
                .session
                .as_mut()
                .and_then(|session| session.tick(now_ms()));
            if let Some(action) = tick {
                self.apply(vec![action]);
            }
            self.flush();
        }

        fn connect(&mut self, cfg: &IrcConfig) {
            let session = Session::new(cfg, now_ms());
            let opening = match session.registration(cfg, &mut HostSecrets) {
                Ok(lines) => lines,
                Err(disconnect) => return self.lost(disconnect),
            };
            let request = ConnectRequest {
                host: cfg.server.trim().to_string(),
                port: cfg.port,
                mode: ConnectMode::DirectTls,
                tls_profile: cfg.tls_profile().map(str::to_string),
            };
            match sockets::connect(&request) {
                Ok(connection) => {
                    self.connection = Some(connection);
                    self.session = Some(session);
                    self.lines = LineBuffer::default();
                    log(
                        LogLevel::Info,
                        PluginAction::Connect,
                        Some(PluginOutcome::Success),
                        "irc: connected",
                        json!({ "server": cfg.server, "port": cfg.port }),
                    );
                    self.write_protocol(&opening);
                }
                // This call's host calls are spent; try on the next poll.
                Err(SocketError::HostUnavailable) => {}
                Err(error) => self.lost(connect_failure(error)),
            }
        }

        /// Read buffered bytes and run each complete line through the session.
        fn pump(&mut self, cfg: &IrcConfig) {
            for _ in 0..MAX_READS_PER_POLL {
                if self.inbox.len() >= MAX_QUEUED_MESSAGES {
                    return;
                }
                let Some(connection) = self.connection.as_ref() else {
                    return;
                };
                match connection.receive() {
                    Ok(ReceiveEvent::Data(bytes)) => {
                        let lines = match self.lines.push(&bytes) {
                            Ok(lines) => lines,
                            Err(reason) => return self.lost(Disconnect::transient(reason)),
                        };
                        for line in lines {
                            let Some(session) = self.session.as_mut() else {
                                return;
                            };
                            let actions =
                                session.handle_line(cfg, &mut HostSecrets, &line, now_ms());
                            self.apply(actions);
                            if self.connection.is_none() {
                                return;
                            }
                        }
                    }
                    Ok(ReceiveEvent::Idle) => return,
                    Ok(ReceiveEvent::Closed(reason)) => {
                        let reason = match reason {
                            CloseReason::PeerClosed => "the server closed the connection",
                            CloseReason::IoError => "the connection failed",
                            CloseReason::HostClosed => "the host closed the connection",
                            CloseReason::TlsUpgradeFailed => "the TLS upgrade failed",
                        };
                        return self.lost(Disconnect::transient(reason));
                    }
                    // This call's host calls are spent; the connection is fine.
                    Err(SocketError::HostUnavailable) => return,
                    Err(error) => {
                        return self.lost(Disconnect::transient(format!(
                            "receive failed ({})",
                            error.name()
                        )))
                    }
                }
            }
        }

        fn apply(&mut self, actions: Vec<Action>) {
            for action in actions {
                match action {
                    Action::Send(line) => self.write_protocol(&[line]),
                    Action::Inbound(message) => self.inbox.push_back(message),
                    Action::Registered => {
                        self.backoff.succeeded();
                        log(
                            LogLevel::Info,
                            PluginAction::Register,
                            Some(PluginOutcome::Success),
                            "irc: registered",
                            json!({ "nick": self.session.as_ref().map(Session::nick) }),
                        );
                    }
                    Action::Disconnect(disconnect) => self.lost(disconnect),
                }
                if self.connection.is_none() {
                    return;
                }
            }
        }

        /// Protocol lines go out at once, ahead of paced chat.
        fn write_protocol(&mut self, lines: &[String]) {
            let bytes = match encode_lines(lines) {
                Ok(bytes) => bytes,
                Err(reason) => return self.lost(Disconnect::fatal(reason)),
            };
            match self.write(&bytes) {
                Wrote::Done => {}
                // Protocol replies cannot wait for a later call: a lost PONG
                // or registration line stalls the session, so start over.
                Wrote::Later => self.lost(Disconnect::transient("the host send queue is full")),
                Wrote::Failed(error) => self.lost(Disconnect::transient(format!(
                    "send failed ({})",
                    error.name()
                ))),
            }
        }

        /// Send the chat lines the pace allows now.
        fn flush(&mut self) {
            if !self.is_registered() || self.outbox.is_empty() {
                return;
            }
            let due = self.outbox.take_due(now_ms());
            if due.is_empty() {
                return;
            }
            let bytes = match encode_lines(&due) {
                Ok(bytes) => bytes,
                Err(reason) => {
                    log(
                        LogLevel::Error,
                        PluginAction::Send,
                        Some(PluginOutcome::Failure),
                        "irc: dropped unsendable chat lines",
                        json!({ "reason": reason, "lines": due.len() }),
                    );
                    return;
                }
            };
            match self.write(&bytes) {
                Wrote::Done => {}
                Wrote::Later => self.outbox.requeue(due),
                Wrote::Failed(error) => {
                    self.outbox.requeue(due);
                    self.lost(Disconnect::transient(format!(
                        "send failed ({})",
                        error.name()
                    )));
                }
            }
        }

        fn write(&self, bytes: &[u8]) -> Wrote {
            let Some(connection) = self.connection.as_ref() else {
                return Wrote::Failed(SocketError::Closed);
            };
            for chunk in bytes.chunks(MAX_WRITE_BYTES) {
                match connection.send(chunk) {
                    Ok(()) => {}
                    Err(SocketError::Backpressure | SocketError::HostUnavailable) => {
                        return Wrote::Later
                    }
                    Err(error) => return Wrote::Failed(error),
                }
            }
            Wrote::Done
        }

        /// Drop the connection and schedule the next attempt.
        fn lost(&mut self, disconnect: Disconnect) {
            let was_connected = self.connection.is_some();
            // Dropping the resource closes the socket and releases the
            // host's egress lease.
            self.connection = None;
            self.session = None;
            self.lines = LineBuffer::default();
            let dropped = self.outbox.clear();
            let delay_ms = self.backoff.failed(now_ms(), disconnect.retry, jitter());
            let (level, message) = match disconnect.retry {
                Retry::Backoff => (LogLevel::Warn, "irc: disconnected; reconnecting"),
                Retry::Refused => (
                    LogLevel::Error,
                    "irc: the host refused the connection; grant the server in this \
                     instance's egress_hosts and check tls_profile",
                ),
                Retry::Park => (
                    LogLevel::Error,
                    "irc: the server rejected the configuration or credentials",
                ),
            };
            log(
                level,
                if was_connected {
                    PluginAction::Disconnect
                } else {
                    PluginAction::Connect
                },
                Some(PluginOutcome::Failure),
                message,
                json!({
                    "reason": disconnect.reason,
                    "retry_in_secs": delay_ms / 1_000,
                    "dropped_lines": dropped,
                }),
            );
        }
    }

    fn to_wit(message: Inbound) -> InboundMessage {
        let sequence = SEQUENCE.with(|cell| {
            let next = cell.get().wrapping_add(1);
            cell.set(next);
            next
        });
        let timestamp = unix_ms();
        InboundMessage {
            id: format!("irc-{timestamp}-{sequence}"),
            sender: message.sender,
            reply_target: message.reply_target,
            content: message.content,
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp,
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
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Channel for IrcChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        /// Validate the config and start over without a connection. No
        /// network here: the first `poll-message` dials.
        fn configure() -> Result<(), String> {
            let cfg = public_config()?;
            if cfg.sasl_mechanism == Some(SaslMechanism::Plain) {
                match secrets::get(SASL_PASSWORD) {
                    Ok(password) if !password.is_empty() => {}
                    Ok(_) | Err(SecretError::NotFound) => {
                        return Err(
                            "irc: sasl_mechanism = \"plain\" needs the sasl_password secret".into(),
                        )
                    }
                    Err(error) => {
                        return Err(format!("irc: cannot read sasl_password ({})", error.name()))
                    }
                }
            }
            let instance = Instance::new(cfg.nickname().to_string());
            INSTANCE.with(|cell| *cell.borrow_mut() = Some(instance));
            log(
                LogLevel::Info,
                PluginAction::Start,
                Some(PluginOutcome::Success),
                "irc: configured",
                json!({
                    "server": cfg.server,
                    "port": cfg.port,
                    "channels": cfg.channels.len(),
                    "sasl": cfg.sasl_mechanism.is_some(),
                    "tls_profile": cfg.tls_profile.is_some(),
                }),
            );
            Ok(())
        }

        /// Queue a reply for paced delivery. Lines leave on this call and the
        /// polls that follow, at most one every two seconds after a burst.
        fn send(message: SendMessage) -> Result<(), String> {
            public_config()?;
            with_instance(|instance| {
                let nick = match instance.session.as_ref() {
                    Some(session) if instance.connection.is_some() && session.is_registered() => {
                        session.nick().to_string()
                    }
                    _ => return Err("irc: not connected and registered".to_string()),
                };
                if !message.attachments.is_empty() {
                    if message.content.trim().is_empty() {
                        return Err("irc: media attachments are not supported".to_string());
                    }
                    log(
                        LogLevel::Warn,
                        PluginAction::Skip,
                        None,
                        "irc: attachments dropped; IRC carries text only",
                        json!({ "attachments": message.attachments.len() }),
                    );
                }
                let lines = format_privmsg(&nick, &message.recipient, &message.content)?;
                instance.outbox.enqueue(lines)?;
                instance.flush();
                Ok(())
            })
            .unwrap_or_else(|| Err("irc: not configured".to_string()))
        }

        fn poll_message() -> Option<InboundMessage> {
            with_instance(|instance| {
                if let Some(message) = instance.inbox.pop_front() {
                    instance.flush();
                    return Some(to_wit(message));
                }
                match public_config() {
                    Ok(cfg) => {
                        if std::mem::take(&mut instance.config_unavailable) {
                            log(
                                LogLevel::Info,
                                PluginAction::Resolve,
                                Some(PluginOutcome::Success),
                                "irc: config readable again",
                                json!({}),
                            );
                        }
                        instance.step(&cfg);
                    }
                    // Without the config there is nothing to filter messages
                    // by: pause, and resume where the session is when the
                    // config is readable again.
                    Err(reason) => {
                        if !instance.config_unavailable {
                            instance.config_unavailable = true;
                            log(
                                LogLevel::Error,
                                PluginAction::Resolve,
                                Some(PluginOutcome::Failure),
                                "irc: cannot read config; paused until it is readable",
                                json!({ "reason": reason }),
                            );
                        }
                    }
                }
                instance.inbox.pop_front().map(to_wit)
            })
            .flatten()
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::SELF_HANDLE
                | ChannelCapabilities::SELF_ADDRESSED_MENTION
        }

        /// True while registered on the server and able to read config.
        fn health_check() -> bool {
            with_instance(|instance| instance.is_registered() && !instance.config_unavailable)
                .unwrap_or(false)
        }

        fn self_handle() -> Option<String> {
            with_instance(|instance| instance.nickname.clone())
        }

        /// IRC users address a nick bare (`nick: hello`); there is no sigil.
        fn self_addressed_mention() -> Option<String> {
            Self::self_handle()
        }

        // ── capability-gated stubs (documented WIT defaults) ──
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
                "irc: webhook ingress is unsupported".to_string(),
            ))
        }
    }

    export!(IrcChannel);
}
