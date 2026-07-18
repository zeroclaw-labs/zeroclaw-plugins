//! ZeroClaw email channel plugin.
//!
//! The host-testable email core implements a conservative text-only IMAP/SMTP
//! client. The component module is a thin adapter over the host-mediated raw
//! socket WIT import.

pub mod email;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-sockets"],
    });

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::email::{
        build_outbound_email, EmailConfig, ImapAction, ImapFramer, ImapMachine, InboundEmail,
        SmtpAction, SmtpFramer, SmtpMachine, CHANNEL, PLUGIN_NAME,
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
    const MAX_SOCKET_EVENTS_PER_POLL: usize = 64;
    const MAX_INBOUND_QUEUE: usize = 64;
    const INITIAL_RETRY_MS: u64 = 1000;
    const MAX_RETRY_MS: u64 = 60_000;

    thread_local! {
        static RUNTIME: RefCell<Runtime> = RefCell::new(Runtime::default());
    }

    #[derive(Default)]
    struct RetryState {
        next_at_ms: u64,
        delay_ms: u64,
    }

    impl RetryState {
        fn ready(&self, now_ms: u64) -> bool {
            now_ms >= self.next_at_ms
        }

        fn success(&mut self) {
            self.next_at_ms = 0;
            self.delay_ms = 0;
        }

        fn fail(&mut self, now_ms: u64) {
            self.delay_ms = if self.delay_ms == 0 {
                INITIAL_RETRY_MS
            } else {
                self.delay_ms.saturating_mul(2).min(MAX_RETRY_MS)
            };
            self.next_at_ms = now_ms.saturating_add(self.delay_ms);
        }
    }

    struct Runtime {
        config: Option<EmailConfig>,
        imap_handle: Option<u64>,
        imap: Option<ImapMachine>,
        imap_framer: ImapFramer,
        imap_retry: RetryState,
        smtp_handle: Option<u64>,
        smtp: SmtpMachine,
        smtp_framer: SmtpFramer,
        smtp_retry: RetryState,
        inbound: VecDeque<InboundEmail>,
        message_sequence: u64,
    }

    impl Default for Runtime {
        fn default() -> Self {
            Self {
                config: None,
                imap_handle: None,
                imap: None,
                imap_framer: ImapFramer::default(),
                imap_retry: RetryState::default(),
                smtp_handle: None,
                smtp: SmtpMachine::default(),
                smtp_framer: SmtpFramer::default(),
                smtp_retry: RetryState::default(),
                inbound: VecDeque::new(),
                message_sequence: 1,
            }
        }
    }

    impl Runtime {
        fn with_config(config: EmailConfig) -> Self {
            Self {
                config: Some(config),
                ..Self::default()
            }
        }

        fn close(&mut self) {
            if let Some(handle) = self.imap_handle.take() {
                socket::tcp_close(handle);
            }
            if let Some(handle) = self.smtp_handle.take() {
                socket::tcp_close(handle);
            }
        }

        fn connect_imap(&mut self, config: &EmailConfig, now_ms: u64) -> Result<(), String> {
            let handle = socket::tcp_connect(&config.imap_host, config.imap_port, true)?;
            self.imap_handle = Some(handle);
            self.imap = Some(ImapMachine::new(now_ms));
            self.imap_framer = ImapFramer::default();
            self.imap_retry.success();
            emit(
                LogLevel::Info,
                PluginAction::Connect,
                Some(PluginOutcome::Success),
                "email: IMAP socket connected",
            );
            Ok(())
        }

        fn connect_smtp(&mut self, config: &EmailConfig, now_ms: u64) -> Result<(), String> {
            let handle = socket::tcp_connect(&config.smtp_host, config.smtp_port, config.smtp_tls)?;
            self.smtp_handle = Some(handle);
            self.smtp_framer = SmtpFramer::default();
            self.smtp.on_connected(now_ms);
            self.smtp_retry.success();
            emit(
                LogLevel::Info,
                PluginAction::Connect,
                Some(PluginOutcome::Success),
                "email: SMTP socket connected",
            );
            Ok(())
        }

        fn drive_imap(&mut self, config: &EmailConfig, now_ms: u64) {
            if self.imap_handle.is_none() {
                if !self.imap_retry.ready(now_ms) {
                    return;
                }
                if let Err(error) = self.connect_imap(config, now_ms) {
                    self.imap_retry.fail(now_ms);
                    emit(
                        LogLevel::Warn,
                        PluginAction::Reconnect,
                        Some(PluginOutcome::Failure),
                        &format!("email: IMAP connect failed: {error}"),
                    );
                    return;
                }
            }

            if let Err(error) = self.drain_imap(config, now_ms) {
                self.drop_imap(&error, now_ms);
            }
        }

        fn drain_imap(&mut self, config: &EmailConfig, now_ms: u64) -> Result<(), String> {
            let handle = self
                .imap_handle
                .ok_or_else(|| "email: missing IMAP socket handle".to_string())?;
            let pending = socket::tcp_pending(handle)?;
            let attempts = usize::try_from(pending)
                .unwrap_or(MAX_SOCKET_EVENTS_PER_POLL)
                .clamp(1, MAX_SOCKET_EVENTS_PER_POLL);

            for _ in 0..attempts {
                match socket::tcp_receive(handle)? {
                    SocketEvent::Data(bytes) => {
                        let frames = self.imap_framer.feed(&bytes)?;
                        for frame in frames {
                            let actions = self
                                .imap
                                .as_mut()
                                .ok_or_else(|| "email: missing IMAP state".to_string())?
                                .on_frame(frame, config, now_ms)?;
                            self.apply_imap_actions(handle, actions)?;
                        }
                    }
                    SocketEvent::Idle => break,
                    SocketEvent::Closed(reason) => {
                        return Err(format!("email: IMAP socket closed: {reason}"));
                    }
                }
            }

            let actions = self
                .imap
                .as_mut()
                .ok_or_else(|| "email: missing IMAP state".to_string())?
                .tick(config, now_ms)?;
            self.apply_imap_actions(handle, actions)
        }

        fn apply_imap_actions(
            &mut self,
            handle: u64,
            actions: Vec<ImapAction>,
        ) -> Result<(), String> {
            for action in actions {
                match action {
                    ImapAction::Send(bytes) => socket::tcp_send(handle, &bytes)?,
                    ImapAction::Message(message) => {
                        if self.inbound.len() >= MAX_INBOUND_QUEUE {
                            self.inbound.pop_front();
                            emit(
                                LogLevel::Warn,
                                PluginAction::Receive,
                                Some(PluginOutcome::Failure),
                                "email: inbound queue full; dropped oldest message",
                            );
                        }
                        self.inbound.push_back(message);
                    }
                    ImapAction::Warning(message) => emit(
                        LogLevel::Warn,
                        PluginAction::Receive,
                        Some(PluginOutcome::Failure),
                        &message,
                    ),
                }
            }
            Ok(())
        }

        fn drop_imap(&mut self, reason: &str, now_ms: u64) {
            if let Some(handle) = self.imap_handle.take() {
                socket::tcp_close(handle);
            }
            self.imap = None;
            self.imap_framer = ImapFramer::default();
            self.imap_retry.fail(now_ms);
            emit(
                LogLevel::Warn,
                PluginAction::Disconnect,
                Some(PluginOutcome::Failure),
                reason,
            );
        }

        fn drive_smtp(&mut self, config: &EmailConfig, now_ms: u64) {
            if self.smtp_handle.is_none() {
                if !self.smtp.has_work() || !self.smtp_retry.ready(now_ms) {
                    return;
                }
                if let Err(error) = self.connect_smtp(config, now_ms) {
                    self.smtp_retry.fail(now_ms);
                    emit(
                        LogLevel::Warn,
                        PluginAction::Reconnect,
                        Some(PluginOutcome::Failure),
                        &format!("email: SMTP connect failed: {error}"),
                    );
                    return;
                }
            }

            if let Err(error) = self.drain_smtp(config, now_ms) {
                self.drop_smtp(&error, now_ms);
            }
        }

        fn drain_smtp(&mut self, config: &EmailConfig, now_ms: u64) -> Result<(), String> {
            let handle = self
                .smtp_handle
                .ok_or_else(|| "email: missing SMTP socket handle".to_string())?;
            let pending = socket::tcp_pending(handle)?;
            let attempts = usize::try_from(pending)
                .unwrap_or(MAX_SOCKET_EVENTS_PER_POLL)
                .clamp(1, MAX_SOCKET_EVENTS_PER_POLL);

            for _ in 0..attempts {
                match socket::tcp_receive(handle)? {
                    SocketEvent::Data(bytes) => {
                        let replies = self.smtp_framer.feed(&bytes)?;
                        for reply in replies {
                            let actions = self.smtp.on_reply(reply, config, now_ms)?;
                            self.apply_smtp_actions(handle, actions)?;
                        }
                    }
                    SocketEvent::Idle => break,
                    SocketEvent::Closed(reason) => {
                        return Err(format!("email: SMTP socket closed: {reason}"));
                    }
                }
            }

            let actions = self.smtp.tick(now_ms)?;
            self.apply_smtp_actions(handle, actions)
        }

        fn apply_smtp_actions(
            &mut self,
            handle: u64,
            actions: Vec<SmtpAction>,
        ) -> Result<(), String> {
            for action in actions {
                match action {
                    SmtpAction::Send(bytes) => socket::tcp_send(handle, &bytes)?,
                    SmtpAction::Delivered(recipient) => emit(
                        LogLevel::Info,
                        PluginAction::Send,
                        Some(PluginOutcome::Success),
                        &format!("email: SMTP delivery accepted for {recipient}"),
                    ),
                    SmtpAction::Failed { recipient, reason } => emit(
                        LogLevel::Error,
                        PluginAction::Send,
                        Some(PluginOutcome::Failure),
                        &format!("email: SMTP delivery failed for {recipient}: {reason}"),
                    ),
                }
            }
            Ok(())
        }

        fn drop_smtp(&mut self, reason: &str, now_ms: u64) {
            if let Some(handle) = self.smtp_handle.take() {
                socket::tcp_close(handle);
            }
            self.smtp_framer = SmtpFramer::default();
            let actions = self.smtp.on_disconnected(reason);
            for action in actions {
                if let SmtpAction::Failed { recipient, reason } = action {
                    emit(
                        LogLevel::Error,
                        PluginAction::Send,
                        Some(PluginOutcome::Failure),
                        &format!("email: SMTP delivery failed for {recipient}: {reason}"),
                    );
                }
            }
            if self.smtp.has_work() {
                self.smtp_retry.fail(now_ms);
            } else {
                self.smtp_retry.success();
            }
            emit(
                LogLevel::Warn,
                PluginAction::Disconnect,
                Some(PluginOutcome::Failure),
                reason,
            );
        }
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    fn to_wit(message: InboundEmail) -> InboundMessage {
        InboundMessage {
            id: message.id,
            sender: message.sender.clone(),
            reply_target: message.sender,
            content: message.content,
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp: message.timestamp_ms.unwrap_or_else(now_millis),
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: Some(message.subject),
        }
    }

    fn emit(level: LogLevel, action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            level,
            &PluginEvent {
                function_name: "email::component".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    struct EmailChannel;

    impl PluginInfo for EmailChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for EmailChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let config = EmailConfig::from_json(&config)?;
            RUNTIME.with(|state| {
                let mut runtime = state.borrow_mut();
                runtime.close();
                *runtime = Runtime::with_config(config);
            });
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err(
                    "email: attachments are not supported by the text-only plugin".to_string(),
                );
            }
            RUNTIME.with(|state| {
                let mut runtime = state.borrow_mut();
                let config = runtime
                    .config
                    .clone()
                    .ok_or_else(|| "email: channel is not configured".to_string())?;
                if !config.enabled {
                    return Err("email: channel is disabled".to_string());
                }
                let sequence = runtime.message_sequence;
                let outbound = build_outbound_email(
                    &config,
                    &message.recipient,
                    &message.content,
                    message.subject.as_deref(),
                    message.in_reply_to.as_deref(),
                    now_secs(),
                    sequence,
                )?;
                let now_ms = now_millis();
                if runtime.smtp_handle.is_none() {
                    runtime.connect_smtp(&config, now_ms)?;
                }
                runtime.smtp.enqueue(outbound)?;
                runtime.message_sequence = sequence.wrapping_add(1).max(1);
                Ok(())
            })
        }

        fn poll_message() -> Option<InboundMessage> {
            RUNTIME.with(|state| {
                let mut runtime = state.borrow_mut();
                let config = runtime.config.clone()?;
                if !config.enabled {
                    return None;
                }
                let now_ms = now_millis();
                runtime.drive_imap(&config, now_ms);
                runtime.drive_smtp(&config, now_ms);
                runtime.inbound.pop_front().map(to_wit)
            })
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::SELF_HANDLE
                | ChannelCapabilities::DROP_SELF_MESSAGE
        }

        fn health_check() -> bool {
            RUNTIME.with(|state| {
                let runtime = state.borrow();
                runtime.imap.as_ref().is_some_and(ImapMachine::is_selected)
            })
        }

        fn self_handle() -> Option<String> {
            RUNTIME.with(|state| {
                state
                    .borrow()
                    .config
                    .as_ref()
                    .filter(|config| config.enabled)
                    .map(|config| config.from_address.clone())
            })
        }

        fn self_addressed_mention() -> Option<String> {
            None
        }

        fn drop_self_message(message: InboundMessage) -> bool {
            RUNTIME.with(|state| {
                state
                    .borrow()
                    .config
                    .as_ref()
                    .is_some_and(|config| message.sender.eq_ignore_ascii_case(&config.from_address))
            })
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

        fn update_draft(
            _recipient: String,
            _message_id: String,
            _text: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn update_draft_progress(
            _recipient: String,
            _message_id: String,
            _text: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn finalize_draft(
            _recipient: String,
            _message_id: String,
            _text: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn cancel_draft(_recipient: String, _message_id: String) -> Result<(), String> {
            Ok(())
        }

        fn supports_multi_message_streaming() -> bool {
            false
        }

        fn multi_message_delay_ms() -> u64 {
            800
        }

        fn add_reaction(
            _channel_id: String,
            _message_id: String,
            _emoji: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn remove_reaction(
            _channel_id: String,
            _message_id: String,
            _emoji: String,
        ) -> Result<(), String> {
            Ok(())
        }

        fn pin_message(_channel_id: String, _message_id: String) -> Result<(), String> {
            Ok(())
        }

        fn unpin_message(_channel_id: String, _message_id: String) -> Result<(), String> {
            Ok(())
        }

        fn redact_message(
            _channel_id: String,
            _message_id: String,
            _reason: Option<String>,
        ) -> Result<(), String> {
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
                "email: webhook ingress is not supported".to_string(),
            ))
        }
    }

    export!(EmailChannel);
}
