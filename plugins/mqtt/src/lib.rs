//! A ZeroClaw WIT channel plugin for MQTT 3.1.1.
//!
//! The pure protocol implementation lives in [`mqtt`]. The WASM component uses
//! ZeroClaw's host-mediated raw socket transport for TCP and TLS.

pub mod mqtt;

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

    use crate::mqtt::{
        encode_pingreq, MqttConfig, MqttSession, PublishPacket, ReconnectBackoff, CHANNEL,
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
    const MAX_PACKETS_PER_POLL: usize = 128;
    const MAX_QUEUED_INBOUND: usize = 256;
    const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

    #[derive(Default)]
    struct RuntimeState {
        config: Option<MqttConfig>,
        connection: Option<u64>,
        protocol: MqttSession,
        inbound: VecDeque<PublishPacket>,
        reconnect: ReconnectBackoff,
        last_transmit_ms: u64,
        ping_sent_ms: Option<u64>,
        next_message_id: u64,
    }

    thread_local! {
        static STATE: RefCell<RuntimeState> = RefCell::new(RuntimeState::default());
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }

    fn emit(
        level: LogLevel,
        action: PluginAction,
        outcome: PluginOutcome,
        message: impl Into<String>,
    ) {
        log_record(
            level,
            &PluginEvent {
                function_name: "mqtt::component::transport".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.into(),
            },
        );
    }

    fn send_frame(state: &mut RuntimeState, frame: &[u8], now: u64) -> Result<(), String> {
        let handle = state
            .connection
            .ok_or_else(|| "mqtt: socket is not connected".to_string())?;
        socket::tcp_send(handle, frame)?;
        state.last_transmit_ms = now;
        Ok(())
    }

    fn fail_connection(state: &mut RuntimeState, now: u64, reason: &str) {
        if let Some(handle) = state.connection.take() {
            socket::tcp_close(handle);
        }
        state.protocol.disconnect();
        state.ping_sent_ms = None;
        let delay = state.reconnect.record_failure(now);
        emit(
            LogLevel::Warn,
            PluginAction::Retry,
            PluginOutcome::Failure,
            format!("MQTT connection lost; retrying in {delay} ms: {reason}"),
        );
    }

    fn establish_connection(state: &mut RuntimeState, now: u64) -> Result<(), String> {
        let config = state
            .config
            .clone()
            .ok_or_else(|| "mqtt: channel is not configured".to_string())?;
        let endpoint = config.endpoint().map_err(|error| error.to_string())?;
        let handle = socket::tcp_connect(&endpoint.host, endpoint.port, endpoint.tls)?;
        let connect = match state.protocol.begin(&config) {
            Ok(connect) => connect,
            Err(error) => {
                socket::tcp_close(handle);
                return Err(error.to_string());
            }
        };
        state.connection = Some(handle);
        if let Err(error) = send_frame(state, &connect, now) {
            socket::tcp_close(handle);
            state.connection = None;
            state.protocol.disconnect();
            return Err(error);
        }
        state.ping_sent_ms = None;
        emit(
            LogLevel::Info,
            PluginAction::Connect,
            PluginOutcome::Success,
            "MQTT TCP connection opened; CONNECT sent",
        );
        Ok(())
    }

    fn drain_packets(
        state: &mut RuntimeState,
        config: &MqttConfig,
        now: u64,
        packet_budget: &mut usize,
    ) -> Result<(), String> {
        while *packet_budget > 0 && state.inbound.len() < MAX_QUEUED_INBOUND {
            let was_online = state.protocol.is_online();
            let Some(output) = state
                .protocol
                .process_next(config)
                .map_err(|error| error.to_string())?
            else {
                break;
            };
            *packet_budget -= 1;
            for frame in output.outbound {
                send_frame(state, &frame, now)?;
            }
            if output.ping_response {
                state.ping_sent_ms = None;
            }
            state.inbound.extend(output.inbound);
            if !was_online && state.protocol.is_online() {
                state.reconnect.reset();
                emit(
                    LogLevel::Info,
                    PluginAction::Complete,
                    PluginOutcome::Success,
                    "MQTT session established and subscriptions acknowledged",
                );
            }
        }
        Ok(())
    }

    fn service_keep_alive(
        state: &mut RuntimeState,
        config: &MqttConfig,
        now: u64,
    ) -> Result<(), String> {
        let keep_alive_ms = config.keep_alive_secs.saturating_mul(1000);
        if keep_alive_ms == 0 || !state.protocol.is_online() {
            return Ok(());
        }
        if let Some(sent_at) = state.ping_sent_ms {
            if now.saturating_sub(sent_at) >= keep_alive_ms {
                return Err("PINGRESP timeout".to_string());
            }
            return Ok(());
        }
        if now.saturating_sub(state.last_transmit_ms) >= keep_alive_ms {
            send_frame(state, &encode_pingreq(), now)?;
            state.ping_sent_ms = Some(now);
        }
        Ok(())
    }

    fn service_transport(state: &mut RuntimeState, now: u64) -> Result<(), String> {
        let Some(config) = state.config.clone() else {
            return Ok(());
        };
        if !config.enabled {
            return Ok(());
        }

        if state.connection.is_none() {
            if !state.reconnect.ready(now) {
                return Ok(());
            }
            if let Err(error) = establish_connection(state, now) {
                fail_connection(state, now, &error);
                return Err(error);
            }
        }

        let mut packet_budget = MAX_PACKETS_PER_POLL;
        if let Err(error) = drain_packets(state, &config, now, &mut packet_budget) {
            fail_connection(state, now, &error);
            return Err(error);
        }

        for _ in 0..MAX_SOCKET_EVENTS_PER_POLL {
            if packet_budget == 0 || state.inbound.len() >= MAX_QUEUED_INBOUND {
                break;
            }
            let Some(handle) = state.connection else {
                break;
            };
            match socket::tcp_receive(handle) {
                Ok(SocketEvent::Data(bytes)) => {
                    if let Err(error) = state.protocol.feed(&bytes) {
                        let reason = error.to_string();
                        fail_connection(state, now, &reason);
                        return Err(reason);
                    }
                    if let Err(error) = drain_packets(state, &config, now, &mut packet_budget) {
                        fail_connection(state, now, &error);
                        return Err(error);
                    }
                }
                Ok(SocketEvent::Idle) => break,
                Ok(SocketEvent::Closed(reason)) => {
                    fail_connection(state, now, &reason);
                    return Err(reason);
                }
                Err(error) => {
                    fail_connection(state, now, &error);
                    return Err(error);
                }
            }
        }

        if !state.protocol.is_online()
            && now.saturating_sub(state.last_transmit_ms) >= HANDSHAKE_TIMEOUT_MS
        {
            let error = "MQTT CONNECT/SUBSCRIBE handshake timed out".to_string();
            fail_connection(state, now, &error);
            return Err(error);
        }

        if let Err(error) = service_keep_alive(state, &config, now) {
            fail_connection(state, now, &error);
            return Err(error);
        }
        Ok(())
    }

    fn next_inbound(state: &mut RuntimeState, timestamp: u64) -> Option<InboundMessage> {
        let publish = state.inbound.pop_front()?;
        let sequence = state.next_message_id;
        state.next_message_id = state.next_message_id.wrapping_add(1);
        let id = match publish.packet_id {
            Some(packet_id) => format!("mqtt-{sequence}-{packet_id}"),
            None => format!("mqtt-{sequence}"),
        };
        Some(InboundMessage {
            id,
            sender: publish.topic.clone(),
            reply_target: publish.topic,
            content: String::from_utf8_lossy(&publish.payload).into_owned(),
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        })
    }

    struct MqttChannel;

    impl PluginInfo for MqttChannel {
        fn plugin_name() -> String {
            CHANNEL.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for MqttChannel {
        fn name() -> String {
            CHANNEL.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let config = MqttConfig::from_json(&config).map_err(|error| error.to_string())?;
            STATE.with(|cell| {
                let mut state = cell.borrow_mut();
                if let Some(handle) = state.connection.take() {
                    socket::tcp_close(handle);
                }
                *state = RuntimeState {
                    config: Some(config),
                    ..RuntimeState::default()
                };
            });
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            if !message.attachments.is_empty() {
                return Err("mqtt: media attachments are not supported".to_string());
            }
            let now = now_ms();
            STATE.with(|cell| {
                let mut state = cell.borrow_mut();
                let service_error = service_transport(&mut state, now).err();
                if !state.protocol.is_online() {
                    return Err(service_error.unwrap_or_else(|| {
                        "mqtt: session is not online; reconnect is pending".to_string()
                    }));
                }
                let config = state
                    .config
                    .clone()
                    .ok_or_else(|| "mqtt: channel is not configured".to_string())?;
                let publish = state
                    .protocol
                    .publish(&config, &message.recipient, message.content.as_bytes())
                    .map_err(|error| error.to_string())?;
                if let Err(error) = send_frame(&mut state, &publish, now) {
                    fail_connection(&mut state, now, &error);
                    return Err(error);
                }
                emit(
                    LogLevel::Info,
                    PluginAction::Send,
                    PluginOutcome::Success,
                    "MQTT PUBLISH queued",
                );
                Ok(())
            })
        }

        fn poll_message() -> Option<InboundMessage> {
            let now = now_ms();
            STATE.with(|cell| {
                let mut state = cell.borrow_mut();
                let _ = service_transport(&mut state, now);
                next_inbound(&mut state, now)
            })
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
        }

        fn health_check() -> bool {
            STATE.with(|cell| {
                let state = cell.borrow();
                state
                    .config
                    .as_ref()
                    .is_some_and(|config| config.enabled && state.protocol.is_online())
            })
        }

        fn self_handle() -> Option<String> {
            None
        }
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
                "mqtt does not serve webhooks".to_string(),
            ))
        }
    }

    export!(MqttChannel);
}
