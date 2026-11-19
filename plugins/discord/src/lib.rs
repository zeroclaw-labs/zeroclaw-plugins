//! A ZeroClaw channel plugin for Discord: the Gateway over the host's
//! `websocket` resource, replies over REST through `wasi:http`.
//!
//! A sandboxed component cannot open a socket, so the host owns the Gateway
//! connection: it checks the destination against the instance's egress grant,
//! resolves and dials it, completes the upgrade, and queues frames both ways.
//! This shim speaks the Discord protocol over that connection from
//! `poll-message`, one bounded step per call, and posts replies with
//! `POST /channels/{id}/messages`.
//!
//! The protocol and delivery decisions live in [`discord`], a pure module
//! covered by host tests; this file performs the I/O they ask for. Only
//! protocol state survives between calls. The public config is read with
//! `config.get`, and the bot token with `secrets.get`, inside each call that
//! needs them, and neither is kept: the host serves both only during a call,
//! so an edited setting or a rotated token applies on the next call.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod discord;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    use serde_json::{json, Value};

    use crate::discord::{
        bot_user_id_from_token, chunk_text, classify_channel, deliver, effective_recipient,
        gateway_ws_url, parse_gateway_bot, url_host, Beat, ChannelAccess, ChannelChecks,
        CheckReport, ConnectFailure, Disconnect, DiscordConfig, Discovery, FrameAction, Gateway,
        Handshake, Health, Inbound, Phase, ReplyTransport, Step, MAX_MESSAGE_CHARS,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::config;
    use zeroclaw::plugin::logging::{self, LogLevel, PluginAction, PluginEvent, PluginOutcome};
    use zeroclaw::plugin::secrets::{self, SecretError};
    use zeroclaw::plugin::websocket::{
        self, CloseCode, ConnectOptions, Connection, Event, Message, WebsocketError,
    };

    const PLUGIN_NAME: &str = "discord";
    const TOKEN_PROPERTY: &str = "bot_token";

    /// Events read per `poll-message` call. Each read is one host call, out of
    /// the host's 1,000 per call; the rest is left for logging and sends.
    const MAX_EVENTS_PER_POLL: usize = 400;
    /// Messages held for the host. Reading pauses at this many, which leaves
    /// later frames queued in the host and the socket.
    const MAX_QUEUED_MESSAGES: usize = 64;
    /// The host queues four frames. While frames are flowing, an empty read
    /// waits a millisecond and reads again, at most this many times per call.
    const MAX_FLOW_WAITS: u32 = 20;
    const FLOW_WAIT: Duration = Duration::from_millis(1);
    /// Reads spent looking for the close event after a send found the socket
    /// closed.
    const MAX_DRAIN_ON_CLOSE: usize = 64;

    const USER_AGENT: &str = concat!(
        "DiscordBot (https://github.com/zeroclaw-labs/zeroclaw-plugins, ",
        env!("CARGO_PKG_VERSION"),
        ")"
    );

    /// Everything one instance keeps between calls.
    struct Instance {
        gateway: Gateway,
        /// The open gateway connection. Dropping it closes the socket and
        /// releases the host's egress lease.
        connection: Option<Connection>,
        /// Messages read from the gateway and not yet handed to the host.
        inbox: VecDeque<Inbound>,
        /// The bot's user id, decoded from the token in `configure`. The host
        /// reads the self handle and mention in calls where config and secrets
        /// are unavailable, and a rebuilt instance must report the same ones,
        /// so this one config-derived value is kept. It is public: it appears
        /// in every mention of the bot.
        self_id: String,
        /// `config.get` failed on the last poll; the gateway is paused.
        config_unavailable: bool,
        binary_frame_logged: bool,
        /// Which `channel_ids` entries this session has checked.
        channel_checks: ChannelChecks,
    }

    thread_local! {
        // The component model does not re-enter a guest during a host call, so
        // holding this borrow across one cannot be observed.
        static INSTANCE: RefCell<Option<Instance>> = const { RefCell::new(None) };
        static CLOCK: Instant = Instant::now();
    }

    fn with_instance<R>(f: impl FnOnce(&mut Instance) -> R) -> Option<R> {
        INSTANCE.with(|cell| cell.borrow_mut().as_mut().map(f))
    }

    fn now_ms() -> u64 {
        CLOCK.with(|origin| u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    fn seed() -> u64 {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(now_ms());
        hasher.finish()
    }

    // ── host services, read at the point of use ──────────────────────────────

    fn public_config() -> Result<DiscordConfig, String> {
        let json = config::get()
            .map_err(|error| format!("discord: config unavailable ({})", error.name()))?;
        DiscordConfig::from_public_json(&json)
    }

    fn bot_token() -> Result<String, SecretError> {
        secrets::get(TOKEN_PROPERTY)
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
                function_name: "discord::gateway".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: Some(attrs.to_string()),
                message: message.to_string(),
            },
        );
    }

    // ── REST over wasi:http ──────────────────────────────────────────────────

    mod http {
        use std::time::{Duration, Instant};

        use wasip2::http::outgoing_handler;
        use wasip2::http::types::{
            ErrorCode, Fields, Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme,
        };

        use crate::discord::split_http_url;

        /// Per-request bounds. `wasi:http` applies the three timeouts; the
        /// body read stops at `body` or `max_body`, whichever comes first.
        pub struct Limits {
            pub connect: Duration,
            pub first_byte: Duration,
            pub between_bytes: Duration,
            pub body: Duration,
            pub max_body: usize,
        }

        /// Discovery and replies: at most about 12 s per request.
        pub const REQUEST: Limits = Limits {
            connect: Duration::from_secs(3),
            first_byte: Duration::from_secs(5),
            between_bytes: Duration::from_secs(2),
            body: Duration::from_secs(2),
            max_body: 64 * 1024,
        };

        /// The health probe, inside `channel doctor`'s 10 s limit, and the
        /// channel checks, which share a call with a gateway pump.
        pub const PROBE: Limits = Limits {
            connect: Duration::from_secs(2),
            first_byte: Duration::from_secs(3),
            between_bytes: Duration::from_secs(1),
            body: Duration::from_secs(1),
            max_body: 16 * 1024,
        };

        pub enum Verb {
            Get,
            Post,
        }

        fn nanos(duration: Duration) -> u64 {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        }

        /// The `wasi:http` error variant's name, without its type or payload.
        fn error_name(code: &ErrorCode) -> String {
            let text = format!("{code:?}");
            let name = text.split(['(', ' ', '{']).next().unwrap_or("error");
            name.trim_start_matches("ErrorCode::").to_string()
        }

        /// One request with `headers` and an optional JSON body. Returns the
        /// status and up to `limits.max_body` bytes of the body.
        pub fn request(
            verb: Verb,
            url: &str,
            headers: &[(&str, &str)],
            body: Option<&[u8]>,
            limits: &Limits,
        ) -> Result<(u16, Vec<u8>), String> {
            let target = split_http_url(url).ok_or("not an http or https URL")?;
            let list: Vec<(String, Vec<u8>)> = headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), value.as_bytes().to_vec()))
                .collect();
            let fields =
                Fields::from_list(&list).map_err(|error| format!("invalid header ({error:?})"))?;
            let request = OutgoingRequest::new(fields);
            let method = match verb {
                Verb::Get => Method::Get,
                Verb::Post => Method::Post,
            };
            let scheme = if target.https {
                Scheme::Https
            } else {
                Scheme::Http
            };
            request
                .set_method(&method)
                .and_then(|()| request.set_scheme(Some(&scheme)))
                .and_then(|()| request.set_authority(Some(&target.authority)))
                .and_then(|()| request.set_path_with_query(Some(&target.path_with_query)))
                .map_err(|()| "the request target was refused".to_string())?;
            let options = RequestOptions::new();
            // A host that does not support a timeout keeps its own default.
            let _ = options.set_connect_timeout(Some(nanos(limits.connect)));
            let _ = options.set_first_byte_timeout(Some(nanos(limits.first_byte)));
            let _ = options.set_between_bytes_timeout(Some(nanos(limits.between_bytes)));
            let outgoing = request
                .body()
                .map_err(|()| "the request body is unavailable".to_string())?;
            let future = outgoing_handler::handle(request, Some(options))
                .map_err(|error| error_name(&error))?;
            if let Some(bytes) = body {
                let stream = outgoing
                    .write()
                    .map_err(|()| "the request body stream is unavailable".to_string())?;
                for chunk in bytes.chunks(4096) {
                    stream
                        .blocking_write_and_flush(chunk)
                        .map_err(|error| format!("writing the request failed ({error:?})"))?;
                }
            }
            OutgoingBody::finish(outgoing, None).map_err(|error| error_name(&error))?;
            let response = loop {
                match future.get() {
                    Some(result) => break result,
                    None => future.subscribe().block(),
                }
            };
            let response = response
                .map_err(|()| "the response was already taken".to_string())?
                .map_err(|error| error_name(&error))?;
            let status = response.status();
            let incoming = response
                .consume()
                .map_err(|()| "the response body is unavailable".to_string())?;
            let stream = incoming
                .stream()
                .map_err(|()| "the response body stream is unavailable".to_string())?;
            let deadline = Instant::now() + limits.body;
            let mut bytes = Vec::new();
            while bytes.len() < limits.max_body && Instant::now() < deadline {
                // The status already decides the outcome: a body that ends
                // early or stalls keeps what arrived. A 2xx whose body stalls
                // was still accepted, and reporting it as a failure would
                // invite a duplicate post.
                match stream.blocking_read(16 * 1024) {
                    Ok(chunk) => bytes.extend_from_slice(&chunk),
                    Err(_) => break,
                }
            }
            // The stream is a child of the body and must go first.
            drop(stream);
            drop(incoming);
            bytes.truncate(limits.max_body);
            Ok((status, bytes))
        }
    }

    fn authorized_get(
        url: &str,
        token: &str,
        limits: &http::Limits,
    ) -> Result<(u16, Vec<u8>), String> {
        let authorization = format!("Bot {token}");
        http::request(
            http::Verb::Get,
            url,
            &[
                ("authorization", &authorization),
                ("user-agent", USER_AGENT),
            ],
            None,
            limits,
        )
    }

    /// Posts the parts of one reply.
    struct RestReply<'a> {
        url: &'a str,
        token: &'a str,
    }

    impl ReplyTransport for RestReply<'_> {
        fn now_ms(&self) -> u64 {
            now_ms()
        }

        fn sleep_ms(&mut self, ms: u64) {
            std::thread::sleep(Duration::from_millis(ms));
        }

        fn post(&mut self, body: &Value) -> Result<(u16, Vec<u8>), String> {
            let authorization = format!("Bot {}", self.token);
            http::request(
                http::Verb::Post,
                self.url,
                &[
                    ("authorization", &authorization),
                    ("user-agent", USER_AGENT),
                    ("content-type", "application/json"),
                ],
                Some(body.to_string().as_bytes()),
                &http::REQUEST,
            )
        }
    }

    // ── gateway I/O ──────────────────────────────────────────────────────────

    fn close_code(code: &CloseCode) -> u16 {
        match code {
            CloseCode::Normal => 1000,
            CloseCode::GoingAway => 1001,
            CloseCode::ProtocolError => 1002,
            CloseCode::UnsupportedData => 1003,
            CloseCode::InvalidPayload => 1007,
            CloseCode::PolicyViolation => 1008,
            CloseCode::MessageTooBig => 1009,
            CloseCode::MandatoryExtension => 1010,
            CloseCode::InternalError => 1011,
            CloseCode::ServiceRestart => 1012,
            CloseCode::TryAgainLater => 1013,
            CloseCode::Other(code) => *code,
        }
    }

    fn connect_failure(error: WebsocketError) -> ConnectFailure {
        match error {
            WebsocketError::DestinationDenied => ConnectFailure::DestinationDenied,
            WebsocketError::AccessDenied => ConnectFailure::AccessDenied,
            WebsocketError::InvalidOptions
            | WebsocketError::ReservedHeader
            | WebsocketError::InvalidSubprotocol => ConnectFailure::InvalidUrl,
            _ => ConnectFailure::Transient,
        }
    }

    /// The outcome of one frame sent on the gateway.
    enum Sent {
        Done,
        /// A full queue or spent host calls: try again on a later call.
        Later,
        Failed(WebsocketError),
    }

    impl Instance {
        /// Take the one step the gateway allows this call.
        fn step(&mut self, cfg: &DiscordConfig) {
            let before = self.gateway.phase().clone();
            match self.gateway.next_step(now_ms(), cfg) {
                Step::Wait => {}
                Step::Discover => self.discover(cfg),
                Step::Connect { url, resume } => {
                    if self.connect(&url, resume) {
                        self.pump(cfg);
                    }
                }
                Step::Pump => {
                    let caught_up = self.pump(cfg);
                    self.check_channel(cfg, caught_up);
                }
            }
            self.report_stop(&before, cfg);
        }

        /// Log entering a state that needs the operator.
        fn report_stop(&self, before: &Phase, cfg: &DiscordConfig) {
            match (before, self.gateway.phase()) {
                (Phase::Parked { reason: was, .. }, Phase::Parked { reason, .. })
                    if was == reason => {}
                (
                    _,
                    Phase::Parked {
                        reason,
                        probe_at_ms,
                    },
                ) => log(
                    LogLevel::Error,
                    PluginAction::Fail,
                    Some(PluginOutcome::Failure),
                    "discord: gateway stopped until the next probe",
                    json!({
                        "reason": reason.as_str(),
                        "hint": reason.hint(cfg.intents()),
                        "probe_in_secs": probe_at_ms.saturating_sub(now_ms()) / 1000,
                    }),
                ),
                (Phase::Misconfigured { reason: was, .. }, Phase::Misconfigured { reason, .. })
                    if was == reason => {}
                (_, Phase::Misconfigured { reason, .. }) => log(
                    LogLevel::Error,
                    PluginAction::Fail,
                    Some(PluginOutcome::Failure),
                    "discord: gateway connection refused by the host; retrying every minute",
                    json!({ "reason": reason.as_str() }),
                ),
                _ => {}
            }
        }

        fn discover(&mut self, cfg: &DiscordConfig) {
            let url = format!("{}/gateway/bot", cfg.api_base);
            let outcome = match bot_token() {
                Ok(token) => match authorized_get(&url, &token, &http::REQUEST) {
                    Ok((status, body)) => {
                        parse_gateway_bot(status, &body, cfg.api_base.starts_with("http://"))
                    }
                    Err(error) => {
                        log(
                            LogLevel::Warn,
                            PluginAction::Query,
                            Some(PluginOutcome::Failure),
                            "discord: gateway discovery failed",
                            json!({ "host": url_host(&url), "error": error }),
                        );
                        Discovery::Failed { status: 0 }
                    }
                },
                Err(error) => {
                    log(
                        LogLevel::Warn,
                        PluginAction::Query,
                        Some(PluginOutcome::Failure),
                        "discord: bot_token unavailable for gateway discovery",
                        json!({ "error": error.name() }),
                    );
                    Discovery::Failed { status: 0 }
                }
            };
            match &outcome {
                Discovery::Ready { remaining, .. } => log(
                    LogLevel::Info,
                    PluginAction::Query,
                    Some(PluginOutcome::Success),
                    "discord: gateway discovered",
                    json!({ "sessions_left": remaining }),
                ),
                Discovery::RateLimited { retry_after_ms } => log(
                    LogLevel::Warn,
                    PluginAction::Query,
                    Some(PluginOutcome::Failure),
                    "discord: gateway discovery rate limited",
                    json!({ "retry_after_ms": retry_after_ms }),
                ),
                Discovery::Failed { status } if *status != 0 => log(
                    LogLevel::Warn,
                    PluginAction::Query,
                    Some(PluginOutcome::Failure),
                    "discord: gateway discovery failed",
                    json!({ "host": url_host(&url), "status": status }),
                ),
                Discovery::Unauthorized | Discovery::Failed { .. } => {}
            }
            self.gateway.on_discovery(now_ms(), outcome);
        }

        fn connect(&mut self, url: &str, resume: bool) -> bool {
            let options = ConnectOptions {
                url: gateway_ws_url(url),
                headers: Vec::new(),
                subprotocols: Vec::new(),
                tls_profile: None,
            };
            match websocket::connect(&options) {
                Ok(connection) => {
                    self.connection = Some(connection);
                    self.gateway.on_connected(now_ms(), url, resume);
                    log(
                        LogLevel::Info,
                        PluginAction::Connect,
                        Some(PluginOutcome::Success),
                        "discord: gateway connected",
                        json!({ "host": url_host(url), "resume": resume }),
                    );
                    true
                }
                Err(error) => {
                    log(
                        LogLevel::Warn,
                        PluginAction::Connect,
                        Some(PluginOutcome::Failure),
                        "discord: gateway connect failed",
                        json!({ "host": url_host(url), "resume": resume, "error": error.name() }),
                    );
                    self.gateway
                        .on_connect_failed(now_ms(), connect_failure(error), resume);
                    false
                }
            }
        }

        /// Read queued events, send any owed handshake, and heartbeat. Returns
        /// whether every queued event was read.
        fn pump(&mut self, cfg: &DiscordConfig) -> bool {
            if self.connection.is_none() {
                self.disconnect(Disconnect::Transport);
                return false;
            }
            let mut events = 0;
            let mut waits = 0;
            let mut caught_up = false;
            while events < MAX_EVENTS_PER_POLL && self.inbox.len() < MAX_QUEUED_MESSAGES {
                let Some(connection) = self.connection.as_ref() else {
                    return false;
                };
                match connection.receive() {
                    Ok(Some(Event::Message(Message::Text(text)))) => {
                        events += 1;
                        self.on_text(&text, cfg);
                    }
                    Ok(Some(Event::Message(Message::Binary(_)))) => {
                        events += 1;
                        self.binary_frame();
                    }
                    Ok(Some(event @ (Event::Closed(_) | Event::Failed(_)))) => {
                        self.terminal(event);
                        return false;
                    }
                    Ok(None) if events > 0 && waits < MAX_FLOW_WAITS => {
                        waits += 1;
                        std::thread::sleep(FLOW_WAIT);
                    }
                    Ok(None) => {
                        caught_up = true;
                        break;
                    }
                    // This call's host calls are spent; the connection is fine.
                    Err(WebsocketError::Unavailable) => break,
                    Err(_) => {
                        self.disconnect(Disconnect::Transport);
                        return false;
                    }
                }
                if self.connection.is_none() {
                    return false;
                }
            }
            if let Some(handshake) = self.gateway.owed_handshake().cloned() {
                self.send_handshake(&handshake, cfg);
            }
            if self.connection.is_none() {
                return false;
            }
            if self.gateway.handshake_overdue(now_ms()) {
                log(
                    LogLevel::Warn,
                    PluginAction::Timeout,
                    None,
                    "discord: gateway handshake did not complete in time; reconnecting",
                    json!({}),
                );
                self.disconnect(Disconnect::HandshakeTimeout);
                return false;
            }
            match self.gateway.heartbeat_step(now_ms(), caught_up) {
                Beat::Idle => {}
                Beat::Send(payload) => {
                    if let Sent::Failed(error) = self.send_heartbeat(payload) {
                        self.send_failed(error, cfg);
                    }
                }
                Beat::Zombie => {
                    log(
                        LogLevel::Warn,
                        PluginAction::Reconnect,
                        None,
                        "discord: heartbeat not acknowledged; reconnecting",
                        json!({}),
                    );
                    self.disconnect(Disconnect::Zombie);
                }
            }
            caught_up
        }

        fn on_text(&mut self, text: &str, cfg: &DiscordConfig) {
            match self.gateway.on_frame(now_ms(), text, cfg) {
                FrameAction::None => {}
                FrameAction::Handshake(handshake) => self.send_handshake(&handshake, cfg),
                FrameAction::Send(payload) => {
                    if let Sent::Failed(error) = self.send_heartbeat(payload) {
                        self.send_failed(error, cfg);
                    }
                }
                FrameAction::Emit(message) => self.inbox.push_back(message),
                FrameAction::Identified { resumed } => self.identified(resumed),
                FrameAction::Reconnect { keep_session } => self.server_reconnect(keep_session),
            }
        }

        fn identified(&mut self, resumed: bool) {
            self.channel_checks.on_identified(now_ms(), resumed);
            log(
                LogLevel::Info,
                PluginAction::Connect,
                Some(PluginOutcome::Success),
                if resumed {
                    "discord: gateway session resumed"
                } else {
                    "discord: gateway session ready"
                },
                json!({ "resumed": resumed }),
            );
            if self.gateway.bot_user_id() != self.self_id {
                log(
                    LogLevel::Warn,
                    PluginAction::Validate,
                    None,
                    "discord: the gateway reports a different bot id than the token",
                    json!({}),
                );
            }
        }

        /// Check one `channel_ids` entry, when one is due, with
        /// `GET /channels/{id}`. Only in a call that pumped, never beside
        /// discovery or a dial; [`ChannelChecks::due`] also requires a session,
        /// a pump that caught up, and no message waiting for the host.
        fn check_channel(&mut self, cfg: &DiscordConfig, caught_up: bool) {
            let idle = caught_up && self.inbox.is_empty();
            let Some(id) = self.channel_checks.due(now_ms(), cfg, &self.gateway, idle) else {
                return;
            };
            let url = format!("{}/channels/{id}", cfg.api_base);
            let response = match bot_token() {
                Ok(token) => authorized_get(&url, &token, &http::PROBE),
                // Retried on a later call.
                Err(SecretError::Unavailable) => return,
                Err(error) => Err(format!("bot_token unavailable ({})", error.name())),
            };
            let (access, error) = match response {
                Ok((status, body)) => (classify_channel(status, &body), None),
                Err(error) => (ChannelAccess::Failed { status: 0 }, Some(error)),
            };
            match self.channel_checks.on_checked(now_ms(), id, &access) {
                CheckReport::Quiet => {}
                CheckReport::Unusable => log(
                    LogLevel::Warn,
                    PluginAction::Validate,
                    Some(PluginOutcome::Failure),
                    if access == ChannelAccess::Hidden {
                        "discord: the bot cannot view a configured channel"
                    } else {
                        "discord: a configured channel does not exist"
                    },
                    json!({ "channel_id": id, "hint": access.hint() }),
                ),
                CheckReport::GaveUp => {
                    let status = match access {
                        ChannelAccess::Failed { status } => status,
                        _ => 0,
                    };
                    log(
                        LogLevel::Info,
                        PluginAction::Validate,
                        Some(PluginOutcome::Failure),
                        "discord: could not check a configured channel; it is checked again in the next session",
                        json!({ "channel_id": id, "status": status, "error": error }),
                    );
                }
            }
        }

        fn server_reconnect(&mut self, keep_session: bool) {
            log(
                LogLevel::Info,
                PluginAction::Reconnect,
                None,
                "discord: gateway asked for a reconnect",
                json!({ "resume": keep_session }),
            );
            self.disconnect(Disconnect::ServerReconnect { keep_session });
        }

        fn binary_frame(&mut self) {
            if !self.binary_frame_logged {
                self.binary_frame_logged = true;
                log(
                    LogLevel::Warn,
                    PluginAction::Skip,
                    None,
                    "discord: ignored a binary gateway frame",
                    json!({}),
                );
            }
        }

        /// A terminal event ends the connection with its cause.
        fn terminal(&mut self, event: Event) {
            match event {
                Event::Closed(frame) => {
                    let code = frame.as_ref().map(|frame| close_code(&frame.code));
                    self.disconnect(Disconnect::Closed(code));
                }
                Event::Failed(WebsocketError::PayloadTooLarge) => {
                    self.disconnect(Disconnect::Oversize);
                }
                Event::Failed(error) => {
                    log(
                        LogLevel::Warn,
                        PluginAction::Receive,
                        Some(PluginOutcome::Failure),
                        "discord: gateway connection failed",
                        json!({ "error": error.name() }),
                    );
                    self.disconnect(Disconnect::Transport);
                }
                Event::Message(_) => {}
            }
        }

        /// A send failed. When the socket has closed, the close event with its
        /// code is still queued behind any unread frames: read up to it, so a
        /// 4004 or 4014 is not mistaken for a dropped connection.
        fn send_failed(&mut self, error: WebsocketError, cfg: &DiscordConfig) {
            if error != WebsocketError::Closed {
                self.disconnect(Disconnect::Transport);
                return;
            }
            let mut reads = 0;
            let mut waits = 0;
            while reads < MAX_DRAIN_ON_CLOSE {
                let Some(connection) = self.connection.as_ref() else {
                    return;
                };
                match connection.receive() {
                    Ok(Some(Event::Message(Message::Text(text)))) => {
                        reads += 1;
                        // Messages before the close still count; nothing is
                        // sent on a closed socket.
                        match self.gateway.on_frame(now_ms(), &text, cfg) {
                            FrameAction::Emit(message) => self.inbox.push_back(message),
                            FrameAction::Identified { resumed } => self.identified(resumed),
                            _ => {}
                        }
                    }
                    Ok(Some(Event::Message(Message::Binary(_)))) => {
                        reads += 1;
                        self.binary_frame();
                    }
                    Ok(Some(event)) => {
                        self.terminal(event);
                        return;
                    }
                    // The host can report the socket closed a moment before it
                    // queues the close event.
                    Ok(None) if waits < MAX_FLOW_WAITS => {
                        waits += 1;
                        std::thread::sleep(FLOW_WAIT);
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            self.disconnect(Disconnect::Transport);
        }

        /// Build the handshake with the token read now, send it, and drop both.
        fn send_handshake(&mut self, handshake: &Handshake, cfg: &DiscordConfig) {
            let token = match bot_token() {
                Ok(token) => token,
                // Retried on a later call.
                Err(SecretError::Unavailable) => return,
                Err(error) => {
                    log(
                        LogLevel::Error,
                        PluginAction::Send,
                        Some(PluginOutcome::Failure),
                        "discord: cannot read bot_token for the gateway handshake",
                        json!({ "error": error.name() }),
                    );
                    self.disconnect(Disconnect::Transport);
                    return;
                }
            };
            let sent = self.send_text(handshake.payload(&token));
            drop(token);
            match sent {
                Sent::Done => {
                    self.gateway.on_handshake_sent(now_ms());
                    log(
                        LogLevel::Info,
                        PluginAction::Send,
                        Some(PluginOutcome::Success),
                        "discord: gateway handshake sent",
                        json!({ "kind": handshake.kind() }),
                    );
                }
                // Still owed; sent on a later call.
                Sent::Later => {}
                Sent::Failed(error) => self.send_failed(error, cfg),
            }
        }

        fn send_heartbeat(&mut self, payload: String) -> Sent {
            let sent = self.send_text(payload);
            if let Sent::Done = sent {
                self.gateway.on_heartbeat_sent(now_ms());
            }
            sent
        }

        fn send_text(&self, text: String) -> Sent {
            let Some(connection) = self.connection.as_ref() else {
                return Sent::Failed(WebsocketError::Closed);
            };
            match connection.send(&Message::Text(text)) {
                Ok(()) => Sent::Done,
                Err(WebsocketError::QueueFull | WebsocketError::Unavailable) => Sent::Later,
                Err(error) => Sent::Failed(error),
            }
        }

        fn disconnect(&mut self, cause: Disconnect) {
            self.connection = None;
            self.gateway.on_disconnect(now_ms(), cause);
            let close_code = match cause {
                Disconnect::Closed(code) => code,
                _ => None,
            };
            log(
                LogLevel::Warn,
                PluginAction::Disconnect,
                None,
                "discord: gateway disconnected",
                json!({
                    "cause": cause.as_str(),
                    "close_code": close_code,
                    "resumable": self.gateway.can_resume(),
                }),
            );
        }
    }

    fn to_wit(message: Inbound) -> InboundMessage {
        InboundMessage {
            id: message.id,
            sender: message.sender,
            reply_target: message.reply_target,
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

    /// Before a session is established, ask Discord whether the token works:
    /// `GET /users/@me`, as the built-in channel's health check does.
    fn token_accepted() -> bool {
        let Ok(cfg) = public_config() else {
            return false;
        };
        let Ok(token) = bot_token() else {
            return false;
        };
        let url = format!("{}/users/@me", cfg.api_base);
        matches!(authorized_get(&url, &token, &http::PROBE), Ok((200, _)))
    }

    struct DiscordChannel;

    impl PluginInfo for DiscordChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Channel for DiscordChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        /// Validate the config and token, and start over without a
        /// connection. No network here: the first `poll-message` dials.
        fn configure() -> Result<(), String> {
            let cfg = public_config()?;
            let self_id = {
                let token = bot_token().map_err(|error| {
                    format!("discord: cannot read bot_token ({})", error.name())
                })?;
                bot_user_id_from_token(&token)
                    .ok_or_else(|| "discord: bot_token is not a Discord bot token".to_string())?
            };
            let instance = Instance {
                gateway: Gateway::new(now_ms(), self_id.clone(), seed()),
                connection: None,
                inbox: VecDeque::new(),
                self_id,
                config_unavailable: false,
                binary_frame_logged: false,
                channel_checks: ChannelChecks::default(),
            };
            INSTANCE.with(|cell| *cell.borrow_mut() = Some(instance));
            log(
                LogLevel::Info,
                PluginAction::Start,
                Some(PluginOutcome::Success),
                "discord: configured",
                json!({
                    "intents": cfg.intents(),
                    "guild_filter": cfg.guild_ids.len(),
                    "channel_filter": cfg.channel_ids.len(),
                    "gateway_url_set": cfg.gateway_url.is_some(),
                }),
            );
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = public_config()?;
            let recipient = effective_recipient(&message.recipient, &cfg.channel_ids)?;
            let chunks = chunk_text(&message.content, MAX_MESSAGE_CHARS);
            if chunks.is_empty() {
                return Err("discord: the message is empty".to_string());
            }
            let url = format!("{}/channels/{recipient}/messages", cfg.api_base);
            let token = bot_token()
                .map_err(|error| format!("discord: cannot read bot_token ({})", error.name()))?;
            let result = deliver(
                &mut RestReply {
                    url: &url,
                    token: &token,
                },
                &chunks,
            );
            drop(token);
            if let Err(reason) = &result {
                log(
                    LogLevel::Warn,
                    PluginAction::Send,
                    Some(PluginOutcome::Failure),
                    "discord: send failed",
                    json!({ "reason": reason, "parts": chunks.len() }),
                );
            }
            result
        }

        fn poll_message() -> Option<InboundMessage> {
            with_instance(|instance| {
                if let Some(message) = instance.inbox.pop_front() {
                    return Some(to_wit(message));
                }
                match public_config() {
                    Ok(cfg) => {
                        if std::mem::take(&mut instance.config_unavailable) {
                            log(
                                LogLevel::Info,
                                PluginAction::Resolve,
                                Some(PluginOutcome::Success),
                                "discord: config readable again",
                                json!({}),
                            );
                        }
                        instance.step(&cfg);
                    }
                    // Without the config there is nothing to filter messages
                    // by: pause, and pick up where the gateway is when the
                    // config is readable again.
                    Err(reason) => {
                        if !instance.config_unavailable {
                            instance.config_unavailable = true;
                            log(
                                LogLevel::Error,
                                PluginAction::Resolve,
                                Some(PluginOutcome::Failure),
                                "discord: cannot read config; paused until it is readable",
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

        /// False while stopped, refused, or unable to read config; true while
        /// a session is established; otherwise whatever Discord says about the
        /// token.
        fn health_check() -> bool {
            let health =
                with_instance(|instance| instance.gateway.health(!instance.config_unavailable));
            match health {
                None | Some(Health::Unhealthy) => false,
                Some(Health::Healthy) => true,
                Some(Health::AskDiscord) => token_accepted(),
            }
        }

        /// The bot's user id, which is what inbound messages carry as their
        /// sender, so the host's self-loop guard can match it.
        fn self_handle() -> Option<String> {
            with_instance(|instance| instance.self_id.clone())
        }

        fn self_addressed_mention() -> Option<String> {
            with_instance(|instance| format!("<@{}>", instance.self_id))
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
                "discord: webhook ingress is unsupported".to_string(),
            ))
        }
    }

    export!(DiscordChannel);
}
