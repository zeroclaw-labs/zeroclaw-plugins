//! A ZeroClaw channel plugin for Twitch chat over IRC/TLS.
//!
//! The pure protocol implementation lives in [`twitch`]. This shim drives it
//! over the host's `sockets` resource: the host checks `irc.chat.twitch.tv`
//! against the instance's egress grant, dials it over TLS, and buffers bytes
//! both ways, while every receive here is bounded and nonblocking.
//!
//! Only protocol state survives between calls. The public config is read with
//! `config.get` on each call that needs it and the OAuth token with
//! `secrets.get` at registration, and neither is kept, so a rotated token
//! applies on the next connection.

pub mod twitch;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-sockets"],
    });

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use crate::twitch::{
        encode_privmsg, registration_frame, Inbound, ProtocolAction, ProtocolSession, TwitchConfig,
        CHANNEL, IRC_HOST, IRC_PORT, OAUTH_TOKEN,
    };
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::config;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };
    use zeroclaw::plugin::secrets;
    use zeroclaw::plugin::sockets::{
        self, ConnectMode, ConnectRequest, Connection, ReceiveEvent, SocketError,
    };

    /// Socket reads per `poll-message`, out of the host's 1,000 host calls.
    const MAX_READS_PER_POLL: usize = 128;
    const MAX_INBOUND_QUEUE: usize = 512;
    /// The host accepts at most 16 KiB per socket send.
    const MAX_WRITE_BYTES: usize = 16 * 1024;
    const INITIAL_RECONNECT_DELAY_MS: u64 = 1_000;
    const MAX_RECONNECT_DELAY_MS: u64 = 60_000;
    /// After the host refuses the destination: an operator must grant it.
    const REFUSED_DELAY_MS: u64 = 60_000;
    /// After Twitch rejects the token: retrying soon risks a login-flood ban.
    const REJECTED_DELAY_MS: u64 = 900_000;
    /// Twitch sends PING about every five minutes. Silence well beyond that
    /// means the link is dead.
    const SILENCE_LIMIT_MS: u64 = 360_000;

    /// Everything one instance keeps between calls.
    struct Instance {
        /// The normalized bot login. The host reads the self handle in calls
        /// where config is unavailable, so this one public, config-derived
        /// value is kept from `configure`.
        login: String,
        connection: Option<Connection>,
        session: ProtocolSession,
        inbox: VecDeque<Inbound>,
        reconnect_at_ms: u64,
        reconnect_delay_ms: u64,
        last_rx_ms: u64,
        config_unavailable: bool,
    }

    thread_local! {
        static INSTANCE: RefCell<Option<Instance>> = const { RefCell::new(None) };
        static CLOCK: Instant = Instant::now();
    }

    fn with_instance<R>(f: impl FnOnce(&mut Instance) -> R) -> Option<R> {
        INSTANCE.with(|cell| cell.borrow_mut().as_mut().map(f))
    }

    /// Monotonic milliseconds, for timers.
    fn now_ms() -> u64 {
        CLOCK.with(|origin| u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    /// Wall-clock milliseconds, for messages without a server timestamp.
    fn unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(0)
    }

    fn public_config() -> Result<TwitchConfig, String> {
        let json = config::get()
            .map_err(|error| format!("twitch: config unavailable ({})", error.name()))?;
        TwitchConfig::from_public_json(&json)
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

    /// How soon to try again after a lost connection.
    enum Retry {
        Backoff,
        Refused,
        Rejected,
    }

    impl Instance {
        fn new(login: String) -> Self {
            Self {
                login,
                connection: None,
                session: ProtocolSession::default(),
                inbox: VecDeque::new(),
                reconnect_at_ms: 0,
                reconnect_delay_ms: INITIAL_RECONNECT_DELAY_MS,
                last_rx_ms: 0,
                config_unavailable: false,
            }
        }

        fn is_ready(&self) -> bool {
            self.connection.is_some() && self.session.is_ready()
        }

        fn disconnect(&mut self, retry: Retry, reason: &str) {
            // Dropping the resource closes the socket and releases the host's
            // egress lease.
            self.connection = None;
            self.session = ProtocolSession::default();
            let delay = match retry {
                Retry::Backoff => {
                    let delay = self.reconnect_delay_ms;
                    self.reconnect_delay_ms = delay.saturating_mul(2).min(MAX_RECONNECT_DELAY_MS);
                    delay
                }
                Retry::Refused => REFUSED_DELAY_MS,
                Retry::Rejected => REJECTED_DELAY_MS,
            };
            self.reconnect_at_ms = now_ms().saturating_add(delay);
            let level = match retry {
                Retry::Backoff => LogLevel::Warn,
                Retry::Refused | Retry::Rejected => LogLevel::Error,
            };
            emit(
                level,
                PluginAction::Disconnect,
                PluginOutcome::Failure,
                &format!("{reason}; retrying in {}s", delay / 1_000),
            );
        }

        fn connect(&mut self, cfg: &TwitchConfig) {
            let token = match secrets::get(OAUTH_TOKEN) {
                Ok(token) => token,
                Err(error) => {
                    return self.disconnect(
                        Retry::Backoff,
                        &format!("twitch: cannot read oauth_token ({})", error.name()),
                    )
                }
            };
            let registration = registration_frame(cfg, &token);
            drop(token);
            let registration = match registration {
                Ok(frame) => frame,
                Err(error) => return self.disconnect(Retry::Rejected, &error),
            };
            let request = ConnectRequest {
                host: IRC_HOST.to_string(),
                port: IRC_PORT,
                mode: ConnectMode::DirectTls,
                tls_profile: None,
            };
            let connection = match sockets::connect(&request) {
                Ok(connection) => connection,
                // This call's host calls are spent; try on the next poll.
                Err(SocketError::HostUnavailable) => return,
                Err(error @ (SocketError::AccessDenied | SocketError::InvalidRequest)) => {
                    return self.disconnect(
                        Retry::Refused,
                        &format!(
                            "twitch: the host refused {IRC_HOST} ({}); grant it in this \
                             instance's egress_hosts",
                            error.name()
                        ),
                    )
                }
                Err(error) => {
                    return self.disconnect(
                        Retry::Backoff,
                        &format!("twitch: TLS connection failed ({})", error.name()),
                    )
                }
            };
            self.session = ProtocolSession::default();
            self.connection = Some(connection);
            self.last_rx_ms = now_ms();
            if let Err(error) = self.write(&registration) {
                return self.disconnect(
                    Retry::Backoff,
                    &format!("twitch: IRC registration send failed ({})", error.name()),
                );
            }
            emit(
                LogLevel::Info,
                PluginAction::Connect,
                PluginOutcome::Success,
                "twitch: connected to IRC over TLS",
            );
        }

        fn write(&self, bytes: &[u8]) -> Result<(), SocketError> {
            let connection = self.connection.as_ref().ok_or(SocketError::Closed)?;
            for chunk in bytes.chunks(MAX_WRITE_BYTES) {
                connection.send(chunk)?;
            }
            Ok(())
        }

        fn queue_inbound(&mut self, message: Inbound) {
            if self.inbox.len() < MAX_INBOUND_QUEUE {
                self.inbox.push_back(message);
            } else {
                emit(
                    LogLevel::Warn,
                    PluginAction::Skip,
                    PluginOutcome::Failure,
                    "twitch: inbound queue is full; dropping message",
                );
            }
        }

        /// Apply the session's actions; false once the connection is gone.
        fn process(&mut self, actions: Vec<ProtocolAction>) -> bool {
            for action in actions {
                match action {
                    ProtocolAction::Send(frame) => {
                        if let Err(error) = self.write(&frame) {
                            self.disconnect(
                                Retry::Backoff,
                                &format!("twitch: IRC protocol send failed ({})", error.name()),
                            );
                            return false;
                        }
                    }
                    ProtocolAction::Inbound(message) => self.queue_inbound(message),
                    ProtocolAction::Ready => {
                        self.reconnect_delay_ms = INITIAL_RECONNECT_DELAY_MS;
                        emit(
                            LogLevel::Info,
                            PluginAction::Register,
                            PluginOutcome::Success,
                            "twitch: authenticated and joined configured channels",
                        );
                    }
                    ProtocolAction::Disconnect(reason) => {
                        self.disconnect(Retry::Backoff, &reason);
                        return false;
                    }
                    ProtocolAction::Rejected(reason) => {
                        self.disconnect(Retry::Rejected, &reason);
                        return false;
                    }
                }
            }
            true
        }

        fn step(&mut self, cfg: &TwitchConfig) {
            if self.connection.is_none() {
                if now_ms() < self.reconnect_at_ms {
                    return;
                }
                self.connect(cfg);
            }
            for _ in 0..MAX_READS_PER_POLL {
                let Some(connection) = self.connection.as_ref() else {
                    return;
                };
                match connection.receive() {
                    Ok(ReceiveEvent::Data(chunk)) => {
                        self.last_rx_ms = now_ms();
                        let actions = self.session.receive(&chunk, cfg);
                        if !self.process(actions) {
                            return;
                        }
                    }
                    Ok(ReceiveEvent::Idle) => break,
                    Ok(ReceiveEvent::Closed(_)) => {
                        return self.disconnect(Retry::Backoff, "twitch: IRC connection closed")
                    }
                    // This call's host calls are spent; the connection is fine.
                    Err(SocketError::HostUnavailable) => return,
                    Err(error) => {
                        return self.disconnect(
                            Retry::Backoff,
                            &format!("twitch: IRC receive failed ({})", error.name()),
                        )
                    }
                }
            }
            if now_ms().saturating_sub(self.last_rx_ms) > SILENCE_LIMIT_MS {
                self.disconnect(
                    Retry::Backoff,
                    "twitch: no traffic from Twitch for six minutes",
                );
            }
        }
    }

    fn to_wit(message: Inbound) -> InboundMessage {
        InboundMessage {
            id: message.id,
            sender: message.sender,
            reply_target: message.reply_target,
            content: message.content,
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp: message.timestamp_ms.unwrap_or_else(unix_ms),
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
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Channel for TwitchChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        /// Validate the config and token, and start over without a
        /// connection. No network here: the first `poll-message` dials.
        fn configure() -> Result<(), String> {
            let cfg = public_config()?;
            let token = secrets::get(OAUTH_TOKEN)
                .map_err(|error| format!("twitch: cannot read oauth_token ({})", error.name()))?;
            crate::twitch::oauth_pass(&token)?;
            drop(token);
            let login = cfg.normalized_username()?;
            INSTANCE.with(|cell| *cell.borrow_mut() = Some(Instance::new(login)));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() && message.content.trim().is_empty() {
                return Err("twitch: media attachments are not supported".to_string());
            }
            with_instance(|instance| {
                if !instance.is_ready() {
                    return Err("twitch: IRC is not connected and ready".to_string());
                }
                let frames = encode_privmsg(
                    &message.recipient,
                    &message.content,
                    message.thread_ts.as_deref(),
                )?;
                for frame in frames {
                    if let Err(error) = instance.write(&frame) {
                        let reason = format!("twitch: PRIVMSG send failed ({})", error.name());
                        instance.disconnect(Retry::Backoff, &reason);
                        return Err(reason);
                    }
                }
                Ok(())
            })
            .unwrap_or_else(|| Err("twitch: not configured".to_string()))
        }

        fn poll_message() -> Option<InboundMessage> {
            with_instance(|instance| {
                if let Some(message) = instance.inbox.pop_front() {
                    return Some(to_wit(message));
                }
                match public_config() {
                    Ok(cfg) => {
                        if std::mem::take(&mut instance.config_unavailable) {
                            emit(
                                LogLevel::Info,
                                PluginAction::Resolve,
                                PluginOutcome::Success,
                                "twitch: config readable again",
                            );
                        }
                        instance.step(&cfg);
                    }
                    Err(reason) => {
                        if !instance.config_unavailable {
                            instance.config_unavailable = true;
                            emit(
                                LogLevel::Error,
                                PluginAction::Resolve,
                                PluginOutcome::Failure,
                                &format!("{reason}; paused until it is readable"),
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

        fn health_check() -> bool {
            with_instance(|instance| instance.is_ready() && !instance.config_unavailable)
                .unwrap_or(false)
        }

        fn self_handle() -> Option<String> {
            with_instance(|instance| instance.login.clone())
        }

        fn self_addressed_mention() -> Option<String> {
            with_instance(|instance| format!("@{}", instance.login))
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
                "twitch: this channel does not serve webhooks".to_string(),
            ))
        }
    }

    export!(TwitchChannel);
}
