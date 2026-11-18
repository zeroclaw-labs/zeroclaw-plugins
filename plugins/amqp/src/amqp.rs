//! Pure AMQP 0-9-1 protocol and configuration logic.
//!
//! This module has no WASM or socket dependencies. The component shim feeds
//! arbitrary TCP chunks into [`Session`] and executes the returned [`Action`]s,
//! while host tests exercise the same framing and state transitions.

use std::str;

use bytes::{Buf, BytesMut};
use serde::Deserialize;
use serde_json::Value;

pub const CHANNEL: &str = "amqp";
pub const PLUGIN_NAME: &str = "amqp";
pub const PROTOCOL_HEADER: &[u8; 8] = b"AMQP\0\0\x09\x01";

const CONNECTION_CHANNEL: u16 = 0;
const DATA_CHANNEL: u16 = 1;
const FRAME_METHOD: u8 = 1;
const FRAME_HEADER: u8 = 2;
const FRAME_BODY: u8 = 3;
const FRAME_HEARTBEAT: u8 = 8;
const FRAME_END: u8 = 0xce;

const DEFAULT_FRAME_MAX: u32 = 131_072;
const HARD_FRAME_MAX: u32 = 16 * 1024 * 1024;
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
pub const DESIRED_HEARTBEAT_SECS: u16 = 30;
const PREFETCH_COUNT: u16 = 64;
const CONSUMER_TAG: &str = "zeroclaw-amqp-plugin";

fn default_sender_label() -> String {
    CHANNEL.to_string()
}

fn default_durable_ack() -> bool {
    true
}

/// Native AMQP dispatch modes. The channel-plugin WIT can emit agent-loop
/// messages but cannot call the host SOP engine, so only `agent_loop` is
/// accepted by [`AmqpConfig::from_json`].
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Dispatch {
    #[default]
    AgentLoop,
    Sop,
    SopAndAgentLoop,
}

/// The canonical host-injected `[channels.amqp.<alias>]` configuration.
///
/// Transport/session state deliberately does not copy these values. It receives
/// `&AmqpConfig` whenever a protocol decision needs configuration.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AmqpConfig {
    #[serde(default)]
    pub enabled: bool,
    pub amqp_url: String,
    pub exchange: String,
    #[serde(default)]
    pub routing_keys: Vec<String>,
    #[serde(default)]
    pub queue: Option<String>,
    #[serde(default)]
    pub tls_profile: Option<String>,
    #[serde(default)]
    pub ca_cert: Option<String>,
    #[serde(default)]
    pub client_cert: Option<String>,
    #[serde(default)]
    pub client_key: Option<String>,
    #[serde(default = "default_sender_label")]
    pub sender_label: String,
    #[serde(default)]
    pub content_template: String,
    #[serde(default)]
    pub thread_id_field: String,
    #[serde(default = "default_durable_ack")]
    pub durable_ack: bool,
    #[serde(default)]
    pub dispatch: Dispatch,
}

impl AmqpConfig {
    pub fn from_json(input: &str) -> Result<Self, String> {
        let config: Self = serde_json::from_str(input)
            .map_err(|error| format!("amqp: invalid channel configuration: {error}"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn endpoint(&self) -> Result<Endpoint, String> {
        Endpoint::parse(&self.amqp_url)
    }

    fn validate(&self) -> Result<(), String> {
        let endpoint = self.endpoint()?;
        validate_shortstr("virtual host", &endpoint.virtual_host)?;
        validate_shortstr("exchange", &self.exchange)?;
        if self.exchange.is_empty() {
            return Err("amqp: exchange must not be empty".to_string());
        }
        if self.routing_keys.is_empty() {
            return Err("amqp: at least one routing key must be configured".to_string());
        }
        for routing_key in &self.routing_keys {
            validate_shortstr("routing key", routing_key)?;
        }
        if let Some(queue) = self.queue.as_deref() {
            validate_shortstr("queue", queue)?;
        }
        if self.sender_label.trim().is_empty() {
            return Err("amqp: sender_label must not be empty".to_string());
        }
        if self.ca_cert.is_some() || self.client_cert.is_some() || self.client_key.is_some() {
            return Err(
                "amqp: configure the TLS material on a host TLS profile and select tls_profile"
                    .into(),
            );
        }
        if self.tls_profile.is_some() && !endpoint.tls {
            return Err("amqp: tls_profile requires amqps://".into());
        }
        if self.dispatch != Dispatch::AgentLoop {
            return Err(
                "amqp: dispatch must be 'agent_loop'; channel plugins cannot invoke the host SOP engine"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// A materialized, on-demand view of `amqp_url` used for one connection or
/// authentication exchange. It is never retained alongside [`AmqpConfig`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub username: String,
    pub password: String,
    pub virtual_host: String,
}

impl Endpoint {
    pub fn parse(input: &str) -> Result<Self, String> {
        let (tls, rest, default_port) = if let Some(rest) = input.strip_prefix("amqp://") {
            (false, rest, 5672)
        } else if let Some(rest) = input.strip_prefix("amqps://") {
            (true, rest, 5671)
        } else {
            return Err("amqp: amqp_url must start with amqp:// or amqps://".to_string());
        };

        if rest.contains(['?', '#']) {
            return Err("amqp: URI query parameters and fragments are unsupported".to_string());
        }
        let (authority, raw_vhost) = match rest.split_once('/') {
            Some((authority, path)) => {
                if path.contains('/') {
                    return Err("amqp: virtual host slash must be percent-encoded".to_string());
                }
                (authority, Some(path))
            }
            None => (rest, None),
        };
        if authority.is_empty() {
            return Err("amqp: broker host must not be empty".to_string());
        }

        let (userinfo, host_port) = match authority.rsplit_once('@') {
            Some((userinfo, host_port)) => (Some(userinfo), host_port),
            None => (None, authority),
        };
        let (username, password) = match userinfo {
            Some(userinfo) => {
                let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                (percent_decode(username)?, percent_decode(password)?)
            }
            None => ("guest".to_string(), "guest".to_string()),
        };
        if username.contains('\0') || password.contains('\0') {
            return Err("amqp: PLAIN credentials must not contain NUL bytes".to_string());
        }

        let (host, port) = parse_host_port(host_port, default_port)?;
        let virtual_host = match raw_vhost {
            Some(path) => percent_decode(path)?,
            None => "/".to_string(),
        };
        if virtual_host.contains('\0') {
            return Err("amqp: virtual host must not contain NUL bytes".to_string());
        }

        Ok(Self {
            host,
            port,
            tls,
            username,
            password,
            virtual_host,
        })
    }
}

fn parse_host_port(input: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(bracketed) = input.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| "amqp: unterminated IPv6 broker address".to_string())?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            parse_port(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| "amqp: invalid IPv6 broker authority".to_string())?,
            )?
        };
        if host.is_empty() {
            return Err("amqp: broker host must not be empty".to_string());
        }
        return Ok((host.to_string(), port));
    }

    let (host, port) = match input.rsplit_once(':') {
        Some((host, port)) => {
            if host.contains(':') {
                return Err("amqp: IPv6 broker addresses must use brackets".to_string());
            }
            (host, parse_port(port)?)
        }
        None => (input, default_port),
    };
    if host.is_empty() {
        return Err("amqp: broker host must not be empty".to_string());
    }
    Ok((host.to_string(), port))
}

fn parse_port(input: &str) -> Result<u16, String> {
    input
        .parse::<u16>()
        .map_err(|_| "amqp: broker port must be an integer from 1 to 65535".to_string())
        .and_then(|port| {
            if port == 0 {
                Err("amqp: broker port must be an integer from 1 to 65535".to_string())
            } else {
                Ok(port)
            }
        })
}

fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("amqp: invalid percent-encoding in amqp_url".to_string());
            }
            let high = hex_value(bytes[index + 1])?;
            let low = hex_value(bytes[index + 2])?;
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| "amqp: amqp_url must decode as UTF-8".to_string())
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("amqp: invalid percent-encoding in amqp_url".to_string()),
    }
}

/// One complete broker delivery assembled from `basic.deliver`, content header,
/// and any number of content-body frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub delivery_tag: u64,
    pub redelivered: bool,
    pub exchange: String,
    pub routing_key: String,
    pub body: Vec<u8>,
}

/// Host-facing fields derived from a delivery using the canonical config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedDelivery {
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub thread_ts: Option<String>,
}

pub fn map_delivery(config: &AmqpConfig, delivery: &Delivery) -> MappedDelivery {
    let parsed: Option<Value> = serde_json::from_slice(&delivery.body).ok();
    let content = match &parsed {
        Some(json) if !config.content_template.is_empty() => {
            interpolate(&config.content_template, json)
        }
        _ => String::from_utf8_lossy(&delivery.body).to_string(),
    };
    let thread_ts = match &parsed {
        Some(json) if !config.thread_id_field.is_empty() => {
            dotted_get(json, &config.thread_id_field).map(stringify_json)
        }
        _ => None,
    };
    MappedDelivery {
        sender: config.sender_label.clone(),
        reply_target: config.sender_label.clone(),
        content,
        thread_ts,
    }
}

pub fn interpolate(template: &str, json: &Value) -> String {
    let mut output = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        output.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            output.push_str(&rest[open..]);
            return output;
        };
        let key = &after_open[..close];
        if let Some(value) = dotted_get(json, key) {
            output.push_str(&stringify_json(value));
        } else {
            output.push('{');
            output.push_str(key);
            output.push('}');
        }
        rest = &after_open[close + 1..];
    }
    output.push_str(rest);
    output
}

fn dotted_get<'a>(json: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = json;
    for segment in path.split('.') {
        cursor = cursor.get(segment)?;
    }
    Some(cursor)
}

fn stringify_json(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

/// Side effects requested by the pure protocol session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Send(Vec<u8>),
    Delivery(Delivery),
    Ready,
    Reconnect {
        reply: Option<Vec<u8>>,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    AwaitStart,
    AwaitTune,
    AwaitConnectionOpenOk,
    AwaitChannelOpenOk,
    AwaitQueueDeclareOk,
    AwaitQueueBindOk { index: usize },
    AwaitQosOk,
    AwaitConsumeOk,
    Ready,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingDelivery {
    delivery_tag: u64,
    redelivered: bool,
    exchange: String,
    routing_key: String,
    expected_body_size: Option<usize>,
    body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Frame {
    frame_type: u8,
    channel: u16,
    payload: Vec<u8>,
}

/// A single AMQP connection's protocol state.
#[derive(Clone, Debug)]
pub struct Session {
    phase: Phase,
    receive_buffer: BytesMut,
    negotiated_frame_max: Option<u32>,
    heartbeat_secs: u16,
    queue_name: Option<String>,
    pending_delivery: Option<PendingDelivery>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self {
            phase: Phase::AwaitStart,
            receive_buffer: BytesMut::new(),
            negotiated_frame_max: None,
            heartbeat_secs: 0,
            queue_name: None,
            pending_delivery: None,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.phase == Phase::Ready
    }

    pub fn heartbeat_secs(&self) -> u16 {
        self.heartbeat_secs
    }

    pub fn frame_max(&self) -> u32 {
        self.negotiated_frame_max.unwrap_or(DEFAULT_FRAME_MAX)
    }

    /// Consume an arbitrary raw TCP chunk and return every complete protocol
    /// action it produced. Partial frames remain buffered for the next call.
    pub fn receive(&mut self, config: &AmqpConfig, bytes: &[u8]) -> Result<Vec<Action>, String> {
        self.receive_buffer.extend_from_slice(bytes);
        let mut actions = Vec::new();
        while let Some(frame) = self.next_frame()? {
            actions.extend(self.handle_frame(config, frame)?);
        }
        Ok(actions)
    }

    pub fn encode_publish(
        &self,
        exchange: &str,
        routing_key: &str,
        body: &[u8],
        subject: Option<&str>,
        correlation_id: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        if !self.is_ready() {
            return Err("amqp: connection is not ready for publishing".to_string());
        }
        validate_shortstr("exchange", exchange)?;
        validate_shortstr("routing key", routing_key)?;
        if routing_key.is_empty() {
            return Err("amqp: publish recipient/routing key must not be empty".to_string());
        }
        if body.len() > MAX_BODY_BYTES {
            return Err(format!(
                "amqp: publish body exceeds the {MAX_BODY_BYTES}-byte limit"
            ));
        }
        if let Some(subject) = subject {
            validate_shortstr("subject", subject)?;
        }
        if let Some(correlation_id) = correlation_id {
            validate_shortstr("correlation id", correlation_id)?;
        }

        let mut publish_args = Vec::new();
        put_u16(&mut publish_args, 0);
        put_shortstr(&mut publish_args, exchange)?;
        put_shortstr(&mut publish_args, routing_key)?;
        publish_args.push(0); // mandatory=false, immediate=false
        let publish = method_frame(DATA_CHANNEL, 60, 40, &publish_args);

        let mut header = Vec::new();
        put_u16(&mut header, 60);
        put_u16(&mut header, 0);
        put_u64(&mut header, body.len() as u64);
        let mut flags = 0x8000 | 0x1000; // content-type + persistent delivery-mode
        if correlation_id.is_some() {
            flags |= 0x0400;
        }
        if subject.is_some() {
            flags |= 0x0020;
        }
        put_u16(&mut header, flags);
        put_shortstr(&mut header, "text/plain; charset=utf-8")?;
        header.push(2); // delivery-mode=persistent
        if let Some(correlation_id) = correlation_id {
            put_shortstr(&mut header, correlation_id)?;
        }
        if let Some(subject) = subject {
            put_shortstr(&mut header, subject)?;
        }
        let content_header = encode_frame(FRAME_HEADER, DATA_CHANNEL, &header);

        let frame_max = self.frame_max() as usize;
        if publish.len() > frame_max || content_header.len() > frame_max {
            return Err("amqp: publish metadata exceeds negotiated frame_max".to_string());
        }
        let body_frame_payload = frame_max
            .checked_sub(8)
            .filter(|size| *size > 0)
            .ok_or_else(|| "amqp: negotiated frame_max is too small".to_string())?;

        let mut output = Vec::with_capacity(publish.len() + content_header.len() + body.len() + 8);
        output.extend_from_slice(&publish);
        output.extend_from_slice(&content_header);
        for chunk in body.chunks(body_frame_payload) {
            output.extend_from_slice(&encode_frame(FRAME_BODY, DATA_CHANNEL, chunk));
        }
        Ok(output)
    }

    fn next_frame(&mut self) -> Result<Option<Frame>, String> {
        if self.receive_buffer.len() < 7 {
            return Ok(None);
        }
        let payload_len = u32::from_be_bytes([
            self.receive_buffer[3],
            self.receive_buffer[4],
            self.receive_buffer[5],
            self.receive_buffer[6],
        ]);
        if payload_len > HARD_FRAME_MAX {
            return Err(format!(
                "amqp: peer frame payload exceeds the {HARD_FRAME_MAX}-byte hard limit"
            ));
        }
        let total_len = payload_len as usize + 8;
        if let Some(frame_max) = self.negotiated_frame_max {
            if total_len > frame_max as usize {
                return Err("amqp: peer frame exceeds negotiated frame_max".to_string());
            }
        }
        if self.receive_buffer.len() < total_len {
            return Ok(None);
        }
        if self.receive_buffer[total_len - 1] != FRAME_END {
            return Err("amqp: invalid frame terminator".to_string());
        }

        let frame_type = self.receive_buffer[0];
        let channel = u16::from_be_bytes([self.receive_buffer[1], self.receive_buffer[2]]);
        let payload = self.receive_buffer[7..total_len - 1].to_vec();
        self.receive_buffer.advance(total_len);
        Ok(Some(Frame {
            frame_type,
            channel,
            payload,
        }))
    }

    fn handle_frame(&mut self, config: &AmqpConfig, frame: Frame) -> Result<Vec<Action>, String> {
        match frame.frame_type {
            FRAME_HEARTBEAT => {
                if frame.channel != CONNECTION_CHANNEL || !frame.payload.is_empty() {
                    return Err("amqp: malformed heartbeat frame".to_string());
                }
                Ok(Vec::new())
            }
            FRAME_METHOD => self.handle_method(config, frame.channel, &frame.payload),
            FRAME_HEADER => self.handle_content_header(frame.channel, &frame.payload),
            FRAME_BODY => self.handle_content_body(frame.channel, &frame.payload),
            other => Err(format!("amqp: unsupported frame type {other}")),
        }
    }

    fn handle_method(
        &mut self,
        config: &AmqpConfig,
        channel: u16,
        payload: &[u8],
    ) -> Result<Vec<Action>, String> {
        let mut reader = Reader::new(payload);
        let class_id = reader.u16()?;
        let method_id = reader.u16()?;

        match (class_id, method_id) {
            (10, 50) => {
                let reason = parse_close_reason(&mut reader, "connection")?;
                self.phase = Phase::Closed;
                return Ok(vec![Action::Reconnect {
                    reply: Some(method_frame(CONNECTION_CHANNEL, 10, 51, &[])),
                    reason,
                }]);
            }
            (20, 40) => {
                let reason = parse_close_reason(&mut reader, "channel")?;
                self.phase = Phase::Closed;
                return Ok(vec![Action::Reconnect {
                    reply: Some(method_frame(DATA_CHANNEL, 20, 41, &[])),
                    reason,
                }]);
            }
            (20, 20) => {
                require_channel(channel, DATA_CHANNEL, "channel.flow")?;
                let active = reader.octet()? & 1;
                reader.finish()?;
                return Ok(vec![Action::Send(method_frame(
                    DATA_CHANNEL,
                    20,
                    21,
                    &[active],
                ))]);
            }
            (60, 30) => {
                require_channel(channel, DATA_CHANNEL, "basic.cancel")?;
                let consumer_tag = reader.shortstr_string()?;
                let _no_wait = reader.octet()?;
                reader.finish()?;
                let mut args = Vec::new();
                put_shortstr(&mut args, &consumer_tag)?;
                self.phase = Phase::Closed;
                return Ok(vec![Action::Reconnect {
                    reply: Some(method_frame(DATA_CHANNEL, 60, 31, &args)),
                    reason: format!("broker cancelled consumer {consumer_tag}"),
                }]);
            }
            // RabbitMQ connection.blocked / connection.unblocked extensions.
            (10, 60) | (10, 61) => return Ok(Vec::new()),
            _ => {}
        }

        match self.phase.clone() {
            Phase::AwaitStart => {
                require_method(channel, class_id, method_id, CONNECTION_CHANNEL, 10, 10)?;
                self.handle_connection_start(config, &mut reader)
            }
            Phase::AwaitTune => {
                if (class_id, method_id) == (10, 20) {
                    return Err(
                        "amqp: connection.secure challenge authentication is unsupported"
                            .to_string(),
                    );
                }
                require_method(channel, class_id, method_id, CONNECTION_CHANNEL, 10, 30)?;
                self.handle_connection_tune(config, &mut reader)
            }
            Phase::AwaitConnectionOpenOk => {
                require_method(channel, class_id, method_id, CONNECTION_CHANNEL, 10, 41)?;
                let _known_hosts = reader.longstr()?;
                reader.finish()?;
                self.phase = Phase::AwaitChannelOpenOk;
                Ok(vec![Action::Send(build_channel_open()?)])
            }
            Phase::AwaitChannelOpenOk => {
                require_method(channel, class_id, method_id, DATA_CHANNEL, 20, 11)?;
                let _channel_id = reader.longstr()?;
                reader.finish()?;
                self.phase = Phase::AwaitQueueDeclareOk;
                Ok(vec![Action::Send(build_queue_declare(config)?)])
            }
            Phase::AwaitQueueDeclareOk => {
                require_method(channel, class_id, method_id, DATA_CHANNEL, 50, 11)?;
                let queue = reader.shortstr_string()?;
                let _message_count = reader.u32()?;
                let _consumer_count = reader.u32()?;
                reader.finish()?;
                if queue.is_empty() {
                    return Err("amqp: broker returned an empty queue name".to_string());
                }
                self.queue_name = Some(queue);
                self.phase = Phase::AwaitQueueBindOk { index: 0 };
                Ok(vec![Action::Send(self.build_queue_bind(config, 0)?)])
            }
            Phase::AwaitQueueBindOk { index } => {
                require_method(channel, class_id, method_id, DATA_CHANNEL, 50, 21)?;
                reader.finish()?;
                let next = index + 1;
                if next < config.routing_keys.len() {
                    self.phase = Phase::AwaitQueueBindOk { index: next };
                    Ok(vec![Action::Send(self.build_queue_bind(config, next)?)])
                } else if config.durable_ack {
                    self.phase = Phase::AwaitQosOk;
                    Ok(vec![Action::Send(build_basic_qos())])
                } else {
                    self.phase = Phase::AwaitConsumeOk;
                    Ok(vec![Action::Send(self.build_basic_consume(config)?)])
                }
            }
            Phase::AwaitQosOk => {
                require_method(channel, class_id, method_id, DATA_CHANNEL, 60, 11)?;
                reader.finish()?;
                self.phase = Phase::AwaitConsumeOk;
                Ok(vec![Action::Send(self.build_basic_consume(config)?)])
            }
            Phase::AwaitConsumeOk => {
                require_method(channel, class_id, method_id, DATA_CHANNEL, 60, 21)?;
                let _consumer_tag = reader.shortstr_string()?;
                reader.finish()?;
                self.phase = Phase::Ready;
                Ok(vec![Action::Ready])
            }
            Phase::Ready => {
                require_method(channel, class_id, method_id, DATA_CHANNEL, 60, 60)?;
                if self.pending_delivery.is_some() {
                    return Err(
                        "amqp: basic.deliver interleaved with unfinished content".to_string()
                    );
                }
                let _consumer_tag = reader.shortstr_string()?;
                let delivery_tag = reader.u64()?;
                let redelivered = reader.octet()? & 1 != 0;
                let exchange = reader.shortstr_string()?;
                let routing_key = reader.shortstr_string()?;
                reader.finish()?;
                self.pending_delivery = Some(PendingDelivery {
                    delivery_tag,
                    redelivered,
                    exchange,
                    routing_key,
                    expected_body_size: None,
                    body: Vec::new(),
                });
                Ok(Vec::new())
            }
            Phase::Closed => Err("amqp: received a method after session close".to_string()),
        }
    }

    fn handle_connection_start(
        &mut self,
        config: &AmqpConfig,
        reader: &mut Reader<'_>,
    ) -> Result<Vec<Action>, String> {
        let major = reader.octet()?;
        let minor = reader.octet()?;
        if (major, minor) != (0, 9) {
            return Err(format!(
                "amqp: broker offered unsupported protocol version {major}.{minor}"
            ));
        }
        reader.skip_table()?;
        let mechanisms = str::from_utf8(reader.longstr()?)
            .map_err(|_| "amqp: broker mechanisms are not UTF-8".to_string())?;
        if !mechanisms
            .split_ascii_whitespace()
            .any(|item| item == "PLAIN")
        {
            return Err("amqp: broker does not offer the PLAIN SASL mechanism".to_string());
        }
        let locales = str::from_utf8(reader.longstr()?)
            .map_err(|_| "amqp: broker locales are not UTF-8".to_string())?;
        if !locales.split_ascii_whitespace().any(|item| item == "en_US") {
            return Err("amqp: broker does not offer the en_US locale".to_string());
        }
        reader.finish()?;

        let endpoint = config.endpoint()?;
        let mut response =
            Vec::with_capacity(endpoint.username.len() + endpoint.password.len() + 2);
        response.push(0);
        response.extend_from_slice(endpoint.username.as_bytes());
        response.push(0);
        response.extend_from_slice(endpoint.password.as_bytes());

        let mut args = Vec::new();
        put_u32(&mut args, 0); // empty client-properties field table
        put_shortstr(&mut args, "PLAIN")?;
        put_longstr(&mut args, &response)?;
        put_shortstr(&mut args, "en_US")?;
        self.phase = Phase::AwaitTune;
        Ok(vec![Action::Send(method_frame(
            CONNECTION_CHANNEL,
            10,
            11,
            &args,
        ))])
    }

    fn handle_connection_tune(
        &mut self,
        config: &AmqpConfig,
        reader: &mut Reader<'_>,
    ) -> Result<Vec<Action>, String> {
        let server_channel_max = reader.u16()?;
        let server_frame_max = reader.u32()?;
        let server_heartbeat = reader.u16()?;
        reader.finish()?;

        if server_channel_max != 0 && server_channel_max < DATA_CHANNEL {
            return Err("amqp: broker channel_max cannot accommodate channel 1".to_string());
        }
        if server_frame_max != 0 && server_frame_max < 4096 {
            return Err("amqp: broker frame_max is below the AMQP minimum".to_string());
        }
        let frame_max = if server_frame_max == 0 {
            DEFAULT_FRAME_MAX
        } else {
            server_frame_max.min(DEFAULT_FRAME_MAX)
        };
        let heartbeat = if server_heartbeat == 0 {
            DESIRED_HEARTBEAT_SECS
        } else {
            server_heartbeat.min(DESIRED_HEARTBEAT_SECS)
        };
        self.negotiated_frame_max = Some(frame_max);
        self.heartbeat_secs = heartbeat;

        let mut tune_ok = Vec::new();
        put_u16(&mut tune_ok, DATA_CHANNEL);
        put_u32(&mut tune_ok, frame_max);
        put_u16(&mut tune_ok, heartbeat);
        let endpoint = config.endpoint()?;
        let mut open = Vec::new();
        put_shortstr(&mut open, &endpoint.virtual_host)?;
        put_shortstr(&mut open, "")?;
        open.push(0); // insist=false

        self.phase = Phase::AwaitConnectionOpenOk;
        Ok(vec![
            Action::Send(method_frame(CONNECTION_CHANNEL, 10, 31, &tune_ok)),
            Action::Send(method_frame(CONNECTION_CHANNEL, 10, 40, &open)),
        ])
    }

    fn build_queue_bind(&self, config: &AmqpConfig, index: usize) -> Result<Vec<u8>, String> {
        let queue = self
            .queue_name
            .as_deref()
            .ok_or_else(|| "amqp: queue name is unavailable before queue.bind".to_string())?;
        let routing_key = config
            .routing_keys
            .get(index)
            .ok_or_else(|| "amqp: routing key index is out of bounds".to_string())?;
        let mut args = Vec::new();
        put_u16(&mut args, 0);
        put_shortstr(&mut args, queue)?;
        put_shortstr(&mut args, &config.exchange)?;
        put_shortstr(&mut args, routing_key)?;
        args.push(0); // no-wait=false
        put_u32(&mut args, 0); // empty arguments field table
        Ok(method_frame(DATA_CHANNEL, 50, 20, &args))
    }

    fn build_basic_consume(&self, config: &AmqpConfig) -> Result<Vec<u8>, String> {
        let queue = self
            .queue_name
            .as_deref()
            .ok_or_else(|| "amqp: queue name is unavailable before basic.consume".to_string())?;
        let mut args = Vec::new();
        put_u16(&mut args, 0);
        put_shortstr(&mut args, queue)?;
        put_shortstr(&mut args, CONSUMER_TAG)?;
        args.push(if config.durable_ack { 0 } else { 0x02 });
        put_u32(&mut args, 0); // empty arguments field table
        Ok(method_frame(DATA_CHANNEL, 60, 20, &args))
    }

    fn handle_content_header(
        &mut self,
        channel: u16,
        payload: &[u8],
    ) -> Result<Vec<Action>, String> {
        require_channel(channel, DATA_CHANNEL, "content header")?;
        if self.phase != Phase::Ready {
            return Err("amqp: content header received before consumer readiness".to_string());
        }
        let pending = self
            .pending_delivery
            .as_mut()
            .ok_or_else(|| "amqp: content header without basic.deliver".to_string())?;
        if pending.expected_body_size.is_some() {
            return Err("amqp: duplicate content header for delivery".to_string());
        }

        let mut reader = Reader::new(payload);
        let class_id = reader.u16()?;
        let weight = reader.u16()?;
        let body_size = reader.u64()?;
        let _property_flags = reader.u16()?;
        if class_id != 60 || weight != 0 {
            return Err("amqp: invalid basic content header".to_string());
        }
        let body_size = usize::try_from(body_size)
            .map_err(|_| "amqp: delivery body size does not fit this target".to_string())?;
        if body_size > MAX_BODY_BYTES {
            return Err(format!(
                "amqp: delivery body exceeds the {MAX_BODY_BYTES}-byte limit"
            ));
        }
        pending.expected_body_size = Some(body_size);
        pending.body.reserve(body_size);
        if body_size == 0 {
            return Ok(vec![Action::Delivery(self.take_complete_delivery()?)]);
        }
        Ok(Vec::new())
    }

    fn handle_content_body(&mut self, channel: u16, payload: &[u8]) -> Result<Vec<Action>, String> {
        require_channel(channel, DATA_CHANNEL, "content body")?;
        if self.phase != Phase::Ready {
            return Err("amqp: content body received before consumer readiness".to_string());
        }
        let pending = self
            .pending_delivery
            .as_mut()
            .ok_or_else(|| "amqp: content body without basic.deliver".to_string())?;
        let expected = pending
            .expected_body_size
            .ok_or_else(|| "amqp: content body arrived before content header".to_string())?;
        if pending.body.len() + payload.len() > expected {
            return Err("amqp: content body exceeds advertised body size".to_string());
        }
        pending.body.extend_from_slice(payload);
        if pending.body.len() == expected {
            Ok(vec![Action::Delivery(self.take_complete_delivery()?)])
        } else {
            Ok(Vec::new())
        }
    }

    fn take_complete_delivery(&mut self) -> Result<Delivery, String> {
        let pending = self
            .pending_delivery
            .take()
            .ok_or_else(|| "amqp: no complete delivery is pending".to_string())?;
        Ok(Delivery {
            delivery_tag: pending.delivery_tag,
            redelivered: pending.redelivered,
            exchange: pending.exchange,
            routing_key: pending.routing_key,
            body: pending.body,
        })
    }
}

pub fn encode_ack(delivery_tag: u64) -> Vec<u8> {
    let mut args = Vec::new();
    put_u64(&mut args, delivery_tag);
    args.push(0); // multiple=false
    method_frame(DATA_CHANNEL, 60, 80, &args)
}

pub fn encode_heartbeat() -> Vec<u8> {
    encode_frame(FRAME_HEARTBEAT, CONNECTION_CHANNEL, &[])
}

fn build_channel_open() -> Result<Vec<u8>, String> {
    let mut args = Vec::new();
    put_shortstr(&mut args, "")?;
    Ok(method_frame(DATA_CHANNEL, 20, 10, &args))
}

fn build_queue_declare(config: &AmqpConfig) -> Result<Vec<u8>, String> {
    let queue = config.queue.as_deref().unwrap_or("");
    let mut args = Vec::new();
    put_u16(&mut args, 0);
    put_shortstr(&mut args, queue)?;
    args.push(if config.queue.is_none() { 0x0c } else { 0 });
    put_u32(&mut args, 0); // empty arguments field table
    Ok(method_frame(DATA_CHANNEL, 50, 10, &args))
}

fn build_basic_qos() -> Vec<u8> {
    let mut args = Vec::new();
    put_u32(&mut args, 0);
    put_u16(&mut args, PREFETCH_COUNT);
    args.push(0); // global=false
    method_frame(DATA_CHANNEL, 60, 10, &args)
}

fn parse_close_reason(reader: &mut Reader<'_>, scope: &str) -> Result<String, String> {
    let code = reader.u16()?;
    let text = reader.shortstr_string()?;
    let failing_class = reader.u16()?;
    let failing_method = reader.u16()?;
    reader.finish()?;
    Ok(format!(
        "broker {scope} close {code}: {text} (method {failing_class}.{failing_method})"
    ))
}

fn require_method(
    actual_channel: u16,
    actual_class: u16,
    actual_method: u16,
    expected_channel: u16,
    expected_class: u16,
    expected_method: u16,
) -> Result<(), String> {
    if (actual_channel, actual_class, actual_method)
        == (expected_channel, expected_class, expected_method)
    {
        Ok(())
    } else {
        Err(format!(
            "amqp: expected method {expected_class}.{expected_method} on channel {expected_channel}, got {actual_class}.{actual_method} on channel {actual_channel}"
        ))
    }
}

fn require_channel(actual: u16, expected: u16, context: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "amqp: {context} arrived on channel {actual}, expected {expected}"
        ))
    }
}

fn validate_shortstr(field: &str, value: &str) -> Result<(), String> {
    if value.len() > u8::MAX as usize {
        Err(format!("amqp: {field} exceeds the 255-byte shortstr limit"))
    } else {
        Ok(())
    }
}

fn method_frame(channel: u16, class_id: u16, method_id: u16, args: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + args.len());
    put_u16(&mut payload, class_id);
    put_u16(&mut payload, method_id);
    payload.extend_from_slice(args);
    encode_frame(FRAME_METHOD, channel, &payload)
}

fn encode_frame(frame_type: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload.len() + 8);
    output.push(frame_type);
    put_u16(&mut output, channel);
    put_u32(&mut output, payload.len() as u32);
    output.extend_from_slice(payload);
    output.push(FRAME_END);
    output
}

fn put_shortstr(output: &mut Vec<u8>, value: &str) -> Result<(), String> {
    validate_shortstr("string", value)?;
    output.push(value.len() as u8);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_longstr(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let len = u32::try_from(value.len())
        .map_err(|_| "amqp: longstr exceeds the 32-bit length limit".to_string())?;
    put_u32(output, len);
    output.extend_from_slice(value);
    Ok(())
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn octet(&mut self) -> Result<u8, String> {
        let value = *self
            .bytes
            .get(self.cursor)
            .ok_or_else(|| "amqp: truncated method payload".to_string())?;
        self.cursor += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, String> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn shortstr(&mut self) -> Result<&'a [u8], String> {
        let len = self.octet()? as usize;
        self.take(len)
    }

    fn shortstr_string(&mut self) -> Result<String, String> {
        str::from_utf8(self.shortstr()?)
            .map(str::to_string)
            .map_err(|_| "amqp: shortstr is not UTF-8".to_string())
    }

    fn longstr(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn skip_table(&mut self) -> Result<(), String> {
        let len = self.u32()? as usize;
        self.take(len)?;
        Ok(())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| "amqp: method payload length overflow".to_string())?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| "amqp: truncated method payload".to_string())?;
        self.cursor = end;
        Ok(value)
    }

    fn finish(&self) -> Result<(), String> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err("amqp: trailing bytes in method payload".to_string())
        }
    }
}
