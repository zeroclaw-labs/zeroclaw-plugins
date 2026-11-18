//! Pure, host-testable IMAP/SMTP protocol core for the email channel.
//!
//! This module performs no I/O. It owns byte framing, protocol state,
//! native-compatible config parsing, MIME text extraction, and outbound
//! message encoding. The WASM component shim supplies socket bytes and sends
//! the returned actions through the host transport.

use std::collections::VecDeque;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use mail_parser::MessageParser;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const CHANNEL: &str = "email";
pub const PLUGIN_NAME: &str = "email";

pub const MAX_IMAP_LITERAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTBOUND_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_SMTP_QUEUE: usize = 32;

const MAX_PROTOCOL_LINE_BYTES: usize = 16 * 1024;
const MAX_IMAP_BUFFER_BYTES: usize = MAX_IMAP_LITERAL_BYTES + (4 * MAX_PROTOCOL_LINE_BYTES);
const MAX_SMTP_BUFFER_BYTES: usize = 64 * 1024;
const COMMAND_TIMEOUT_MS: u64 = 30_000;
const SOP_SUBJECT_PREFIX: &str = "zeroclaw:sop-event:";

#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct EmailOAuth2Config {
    pub client_id: String,
    pub token_url: String,
    pub device_code_url: String,
    pub scopes: Vec<String>,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct EmailConfig {
    #[serde(default)]
    pub enabled: bool,
    pub imap_host: String,
    #[serde(default = "default_imap_port")]
    pub imap_port: u16,
    #[serde(default = "default_imap_folder")]
    pub imap_folder: String,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default = "default_true")]
    pub smtp_tls: bool,
    #[serde(default)]
    pub smtp_username: Option<String>,
    #[serde(default)]
    pub smtp_password: Option<String>,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub from_address: String,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_subject")]
    pub default_subject: String,
    #[serde(default = "default_max_attachment_bytes")]
    pub max_attachment_bytes: usize,
    #[serde(default)]
    pub excluded_tools: Vec<String>,
    #[serde(default = "default_true")]
    pub html_body: bool,
    #[serde(default)]
    pub oauth2: Option<EmailOAuth2Config>,
    #[serde(default)]
    pub observer_mode: bool,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            imap_host: String::new(),
            imap_port: default_imap_port(),
            imap_folder: default_imap_folder(),
            smtp_host: String::new(),
            smtp_port: default_smtp_port(),
            smtp_tls: true,
            smtp_username: None,
            smtp_password: None,
            username: String::new(),
            password: String::new(),
            from_address: String::new(),
            idle_timeout_secs: default_idle_timeout_secs(),
            poll_interval_secs: default_poll_interval_secs(),
            default_subject: default_subject(),
            max_attachment_bytes: default_max_attachment_bytes(),
            excluded_tools: Vec::new(),
            html_body: true,
            oauth2: None,
            observer_mode: false,
        }
    }
}

impl EmailConfig {
    pub fn from_json(input: &str) -> Result<Self, String> {
        let config = serde_json::from_str::<Self>(input)
            .map_err(|error| format!("email: invalid channel config: {error}"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        validate_host("imap_host", &self.imap_host)?;
        if self.imap_port == 0 {
            return Err("email: imap_port must be greater than zero".to_string());
        }
        if self.smtp_port == 0 {
            return Err("email: smtp_port must be greater than zero".to_string());
        }
        validate_imap_value("imap_folder", &self.imap_folder)?;
        validate_imap_value("username", &self.username)?;
        validate_imap_value("password", &self.password)?;
        if self.username.trim().is_empty() || self.password.is_empty() {
            return Err("email: username and password are required".to_string());
        }
        validate_header_value("default_subject", &self.default_subject)?;
        if self.poll_interval_secs == 0 {
            return Err("email: poll_interval_secs must be greater than zero".to_string());
        }
        if self.oauth2.is_some() {
            return Err(
                "email: oauth2 is not supported by the socket plugin; use password authentication"
                    .to_string(),
            );
        }
        if !self.outbound_configured()? {
            return Ok(());
        }
        validate_host("smtp_host", &self.smtp_host)?;
        validate_mailbox(&self.from_address)
            .map_err(|error| format!("email: invalid from_address: {error}"))?;
        let (smtp_username, smtp_password) = self.smtp_credentials();
        validate_imap_value("smtp_username", smtp_username)?;
        validate_imap_value("smtp_password", smtp_password)?;
        if smtp_username.trim().is_empty() || smtp_password.is_empty() {
            return Err("email: SMTP credentials must not be empty".to_string());
        }
        Ok(())
    }

    fn outbound_configured(&self) -> Result<bool, String> {
        let host = !self.smtp_host.trim().is_empty();
        let address = !self.from_address.trim().is_empty();
        if host != address {
            return Err("email: configure smtp_host and from_address together, or leave both unset for inbound-only mail".into());
        }
        Ok(host)
    }

    pub fn smtp_credentials(&self) -> (&str, &str) {
        (
            nonblank(self.smtp_username.as_deref()).unwrap_or(&self.username),
            nonblank(self.smtp_password.as_deref()).unwrap_or(&self.password),
        )
    }

    fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_secs.saturating_mul(1000).max(1000)
    }
}

fn default_imap_port() -> u16 {
    993
}

fn default_smtp_port() -> u16 {
    465
}

fn default_imap_folder() -> String {
    "INBOX".to_string()
}

fn default_idle_timeout_secs() -> u64 {
    1740
}

fn default_poll_interval_secs() -> u64 {
    60
}

fn default_subject() -> String {
    "Re: Message".to_string()
}

fn default_max_attachment_bytes() -> usize {
    25 * 1024 * 1024
}

fn default_true() -> bool {
    true
}

fn nonblank(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

fn validate_host(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.chars().any(char::is_whitespace)
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(format!("email: {field} must be a non-empty ASCII host"));
    }
    Ok(())
}

fn validate_imap_value(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(format!(
            "email: {field} must not be empty or contain CR/LF/NUL"
        ));
    }
    Ok(())
}

fn validate_header_value(field: &str, value: &str) -> Result<(), String> {
    if value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == b'\0')
    {
        return Err(format!("email: {field} must not contain CR/LF/NUL"));
    }
    Ok(())
}

pub fn validate_mailbox(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 254
        || !value.is_ascii()
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("expected a single ASCII addr-spec".to_string());
    }
    let (local, domain) = value
        .rsplit_once('@')
        .ok_or_else(|| "expected local@domain".to_string())?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.bytes().all(is_atext_or_dot)
    {
        return Err("unsupported local-part".to_string());
    }
    if domain.is_empty()
        || domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("unsupported domain".to_string());
    }
    Ok(())
}

fn is_atext_or_dot(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | 0x60
                | b'{'
                | b'|'
                | b'}'
                | b'~'
                | b'.'
        )
}

fn imap_quote(value: &str) -> Result<String, String> {
    validate_imap_value("IMAP value", value)?;
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if matches!(character, '\\' | '"') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    Ok(quoted)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundEmail {
    pub id: String,
    pub sender: String,
    pub subject: String,
    pub content: String,
    pub timestamp_ms: Option<u64>,
}

pub fn parse_rfc822(
    raw: &[u8],
    uid: u32,
    uid_validity: Option<u32>,
    config: &EmailConfig,
) -> Result<InboundEmail, String> {
    let parsed = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| "email: failed to parse RFC 5322 message".to_string())?;
    let sender = parsed
        .from()
        .and_then(|addresses| addresses.first())
        .and_then(|address| address.address())
        .unwrap_or("unknown")
        .trim()
        .to_string();
    let subject = sanitize_subject(parsed.subject().unwrap_or("(no subject)"));
    let body = if let Some(text) = parsed.body_text(0) {
        text.into_owned()
    } else if let Some(html) = parsed.body_html(0) {
        strip_html(html.as_ref())
    } else {
        "(no readable text body)".to_string()
    };
    let id = parsed
        .message_id()
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 998)
        .map(str::to_string)
        .unwrap_or_else(|| {
            synthetic_message_id(&parsed, uid, uid_validity, &sender, &body, config)
        });
    let timestamp_ms = parsed
        .date()
        .map(|date| date.to_timestamp())
        .filter(|timestamp| *timestamp >= 0)
        .and_then(|timestamp| u64::try_from(timestamp).ok())
        .map(|timestamp| timestamp.saturating_mul(1000));

    Ok(InboundEmail {
        id,
        sender,
        subject: subject.clone(),
        content: format!("Subject: {subject}\n\n{body}"),
        timestamp_ms,
    })
}

fn sanitize_subject(subject: &str) -> String {
    let mut cleaned = subject;
    while let Some(remainder) = cleaned.strip_prefix(SOP_SUBJECT_PREFIX) {
        cleaned = remainder;
    }
    cleaned.trim_start().to_string()
}

fn strip_html(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for character in html.chars() {
        match character {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => text.push(character),
            _ => {}
        }
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn synthetic_message_id(
    parsed: &mail_parser::Message<'_>,
    uid: u32,
    uid_validity: Option<u32>,
    sender: &str,
    body: &str,
    config: &EmailConfig,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(config.imap_host.as_bytes());
    hasher.update(b"\0");
    hasher.update(config.username.as_bytes());
    hasher.update(b"\0");
    hasher.update(config.imap_folder.as_bytes());
    if let Some(uid_validity) = uid_validity.filter(|_| uid != 0) {
        hasher.update(b"\0uidvalidity\0");
        hasher.update(uid_validity.to_be_bytes());
        hasher.update(b"\0uid\0");
        hasher.update(uid.to_be_bytes());
        return format!("email-imap-{}-{uid}", hex_prefix(&hasher.finalize()));
    }

    hasher.update(b"\0content\0");
    hasher.update(sender.as_bytes());
    hasher.update(b"\0");
    hasher.update(parsed.subject().unwrap_or_default().as_bytes());
    hasher.update(b"\0");
    if let Some(date) = parsed.date() {
        hasher.update(date.to_timestamp().to_be_bytes());
    }
    hasher.update(b"\0");
    hasher.update(body.as_bytes());
    format!("email-fallback-{}", hex_prefix(&hasher.finalize()))
}

fn hex_prefix(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in bytes.iter().take(16) {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImapFrame {
    Line(Vec<u8>),
    Literal(Vec<u8>),
}

#[derive(Default)]
pub struct ImapFramer {
    buffer: Vec<u8>,
    literal_remaining: Option<usize>,
}

impl ImapFramer {
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<ImapFrame>, String> {
        if self.buffer.len().saturating_add(chunk.len()) > MAX_IMAP_BUFFER_BYTES {
            return Err("email: IMAP receive buffer limit exceeded".to_string());
        }
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();

        loop {
            if let Some(length) = self.literal_remaining {
                if self.buffer.len() < length {
                    break;
                }
                let literal = self.buffer.drain(..length).collect();
                self.literal_remaining = None;
                frames.push(ImapFrame::Literal(literal));
                continue;
            }

            let Some(line_end) = find_crlf(&self.buffer) else {
                if self.buffer.len() > MAX_PROTOCOL_LINE_BYTES {
                    return Err("email: IMAP response line limit exceeded".to_string());
                }
                break;
            };
            if line_end > MAX_PROTOCOL_LINE_BYTES {
                return Err("email: IMAP response line limit exceeded".to_string());
            }
            let line: Vec<u8> = self.buffer.drain(..line_end).collect();
            self.buffer.drain(..2);
            self.literal_remaining = literal_length(&line)?;
            frames.push(ImapFrame::Line(line));
        }

        Ok(frames)
    }
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|pair| pair == b"\r\n")
}

fn literal_length(line: &[u8]) -> Result<Option<usize>, String> {
    if !line.ends_with(b"}") {
        return Ok(None);
    }
    let Some(open) = line.iter().rposition(|byte| *byte == b'{') else {
        return Ok(None);
    };
    let mut digits = &line[open + 1..line.len() - 1];
    if let Some(without_plus) = digits.strip_suffix(b"+") {
        digits = without_plus;
    }
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Ok(None);
    }
    let text = std::str::from_utf8(digits)
        .map_err(|_| "email: invalid IMAP literal length".to_string())?;
    let length = text
        .parse::<usize>()
        .map_err(|_| "email: invalid IMAP literal length".to_string())?;
    if length > MAX_IMAP_LITERAL_BYTES {
        return Err(format!(
            "email: IMAP literal exceeds {MAX_IMAP_LITERAL_BYTES} byte limit"
        ));
    }
    Ok(Some(length))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImapAction {
    Send(Vec<u8>),
    Message(InboundEmail),
    Warning(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SearchKind {
    InitialActive,
    Incremental,
}

#[derive(Debug, PartialEq, Eq)]
enum ImapState {
    Transitioning,
    AwaitGreeting,
    AwaitLogin {
        tag: String,
    },
    AwaitSelect {
        tag: String,
    },
    AwaitSearch {
        tag: String,
        kind: SearchKind,
    },
    AwaitFetch {
        tag: String,
        uid: u32,
        kind: SearchKind,
    },
    Ready,
}

pub struct ImapMachine {
    state: ImapState,
    next_tag: u32,
    uid_next: u32,
    saw_uid_next: bool,
    uid_validity: Option<u32>,
    search_results: Vec<u32>,
    pending_uids: VecDeque<u32>,
    fetch_body: Option<Vec<u8>>,
    next_poll_at_ms: u64,
    deadline_ms: Option<u64>,
}

impl ImapMachine {
    pub fn new(now_ms: u64) -> Self {
        Self {
            state: ImapState::AwaitGreeting,
            next_tag: 1,
            uid_next: 1,
            saw_uid_next: false,
            uid_validity: None,
            search_results: Vec::new(),
            pending_uids: VecDeque::new(),
            fetch_body: None,
            next_poll_at_ms: now_ms,
            deadline_ms: Some(now_ms.saturating_add(COMMAND_TIMEOUT_MS)),
        }
    }

    pub fn is_selected(&self) -> bool {
        matches!(
            self.state,
            ImapState::AwaitSearch { .. } | ImapState::AwaitFetch { .. } | ImapState::Ready
        )
    }

    pub fn tick(&mut self, _config: &EmailConfig, now_ms: u64) -> Result<Vec<ImapAction>, String> {
        if self.deadline_ms.is_some_and(|deadline| now_ms >= deadline) {
            return Err("email: IMAP command timed out".to_string());
        }
        if self.state == ImapState::Ready && now_ms >= self.next_poll_at_ms {
            return self.begin_search(SearchKind::Incremental, now_ms);
        }
        Ok(Vec::new())
    }

    pub fn on_frame(
        &mut self,
        frame: ImapFrame,
        config: &EmailConfig,
        now_ms: u64,
    ) -> Result<Vec<ImapAction>, String> {
        match frame {
            ImapFrame::Literal(literal) => {
                if !matches!(self.state, ImapState::AwaitFetch { .. }) {
                    return Err("email: unexpected IMAP literal".to_string());
                }
                if self.fetch_body.replace(literal).is_some() {
                    return Err("email: multiple literals in one IMAP FETCH".to_string());
                }
                Ok(Vec::new())
            }
            ImapFrame::Line(line) => self.on_line(&line, config, now_ms),
        }
    }

    fn on_line(
        &mut self,
        line: &[u8],
        config: &EmailConfig,
        now_ms: u64,
    ) -> Result<Vec<ImapAction>, String> {
        let text = String::from_utf8_lossy(line);
        if starts_ascii_case_insensitive(&text, "* BYE") {
            return Err(format!("email: IMAP server closed the session: {text}"));
        }
        if let Some(value) = response_code_number(&text, "UIDNEXT") {
            self.uid_next = value.max(1);
            self.saw_uid_next = true;
        }
        if let Some(value) = response_code_number(&text, "UIDVALIDITY") {
            self.uid_validity = Some(value);
        }

        let state = std::mem::replace(&mut self.state, ImapState::Transitioning);
        match state {
            ImapState::AwaitGreeting => {
                if starts_ascii_case_insensitive(&text, "* OK") {
                    self.begin_login(config, now_ms)
                } else if starts_ascii_case_insensitive(&text, "* PREAUTH") {
                    self.begin_select(config, now_ms)
                } else {
                    self.state = ImapState::AwaitGreeting;
                    Ok(Vec::new())
                }
            }
            ImapState::AwaitLogin { tag } => {
                let Some(status) = tagged_status(&text, &tag) else {
                    self.state = ImapState::AwaitLogin { tag };
                    return Ok(Vec::new());
                };
                require_imap_ok(&status, &text, "LOGIN")?;
                self.begin_select(config, now_ms)
            }
            ImapState::AwaitSelect { tag } => {
                let Some(status) = tagged_status(&text, &tag) else {
                    self.state = ImapState::AwaitSelect { tag };
                    return Ok(Vec::new());
                };
                require_imap_ok(&status, &text, "SELECT")?;
                if config.observer_mode && !self.saw_uid_next {
                    return Err(
                        "email: observer_mode requires UIDNEXT in the IMAP SELECT response"
                            .to_string(),
                    );
                }
                let kind = if config.observer_mode {
                    SearchKind::Incremental
                } else {
                    SearchKind::InitialActive
                };
                self.begin_search(kind, now_ms)
            }
            ImapState::AwaitSearch { tag, kind } => {
                if let Some(mut uids) = parse_search_response(&text) {
                    self.search_results.append(&mut uids);
                    self.state = ImapState::AwaitSearch { tag, kind };
                    return Ok(Vec::new());
                }
                let Some(status) = tagged_status(&text, &tag) else {
                    self.state = ImapState::AwaitSearch { tag, kind };
                    return Ok(Vec::new());
                };
                require_imap_ok(&status, &text, "UID SEARCH")?;
                self.finish_search(kind, config, now_ms)
            }
            ImapState::AwaitFetch { tag, uid, kind } => {
                let Some(status) = tagged_status(&text, &tag) else {
                    self.state = ImapState::AwaitFetch { tag, uid, kind };
                    return Ok(Vec::new());
                };
                let mut actions = Vec::new();
                if status == "OK" {
                    match self.fetch_body.take() {
                        Some(body) => match parse_rfc822(&body, uid, self.uid_validity, config) {
                            Ok(message) => actions.push(ImapAction::Message(message)),
                            Err(error) => actions.push(ImapAction::Warning(error)),
                        },
                        None => actions.push(ImapAction::Warning(format!(
                            "email: IMAP FETCH for UID {uid} returned no message body"
                        ))),
                    }
                } else {
                    self.fetch_body = None;
                    actions.push(ImapAction::Warning(format!(
                        "email: IMAP FETCH for UID {uid} failed: {text}"
                    )));
                }
                self.uid_next = self.uid_next.max(uid.saturating_add(1));
                actions.extend(self.start_next_fetch(kind, config, now_ms)?);
                Ok(actions)
            }
            ImapState::Ready => {
                self.state = ImapState::Ready;
                Ok(Vec::new())
            }
            ImapState::Transitioning => Err("email: invalid IMAP state transition".to_string()),
        }
    }

    fn begin_login(
        &mut self,
        config: &EmailConfig,
        now_ms: u64,
    ) -> Result<Vec<ImapAction>, String> {
        let tag = self.allocate_tag();
        let command = format!(
            "{tag} LOGIN {} {}\r\n",
            imap_quote(&config.username)?,
            imap_quote(&config.password)?
        );
        self.state = ImapState::AwaitLogin { tag };
        self.deadline_ms = Some(now_ms.saturating_add(COMMAND_TIMEOUT_MS));
        Ok(vec![ImapAction::Send(command.into_bytes())])
    }

    fn begin_select(
        &mut self,
        config: &EmailConfig,
        now_ms: u64,
    ) -> Result<Vec<ImapAction>, String> {
        let tag = self.allocate_tag();
        let command = format!("{tag} SELECT {}\r\n", imap_quote(&config.imap_folder)?);
        self.state = ImapState::AwaitSelect { tag };
        self.deadline_ms = Some(now_ms.saturating_add(COMMAND_TIMEOUT_MS));
        Ok(vec![ImapAction::Send(command.into_bytes())])
    }

    fn begin_search(&mut self, kind: SearchKind, now_ms: u64) -> Result<Vec<ImapAction>, String> {
        let tag = self.allocate_tag();
        let criteria = match kind {
            SearchKind::InitialActive => "UNSEEN".to_string(),
            SearchKind::Incremental => format!("UID {}:*", self.uid_next),
        };
        self.search_results.clear();
        self.state = ImapState::AwaitSearch {
            tag: tag.clone(),
            kind,
        };
        self.deadline_ms = Some(now_ms.saturating_add(COMMAND_TIMEOUT_MS));
        Ok(vec![ImapAction::Send(
            format!("{tag} UID SEARCH {criteria}\r\n").into_bytes(),
        )])
    }

    fn finish_search(
        &mut self,
        kind: SearchKind,
        config: &EmailConfig,
        now_ms: u64,
    ) -> Result<Vec<ImapAction>, String> {
        self.search_results.sort_unstable();
        self.search_results.dedup();
        if kind == SearchKind::Incremental {
            self.search_results.retain(|uid| *uid >= self.uid_next);
        }
        self.pending_uids = std::mem::take(&mut self.search_results).into();
        self.start_next_fetch(kind, config, now_ms)
    }

    fn start_next_fetch(
        &mut self,
        kind: SearchKind,
        config: &EmailConfig,
        now_ms: u64,
    ) -> Result<Vec<ImapAction>, String> {
        let Some(uid) = self.pending_uids.pop_front() else {
            self.state = ImapState::Ready;
            self.deadline_ms = None;
            self.next_poll_at_ms = now_ms.saturating_add(config.poll_interval_ms());
            return Ok(Vec::new());
        };
        let tag = self.allocate_tag();
        let item = if kind == SearchKind::InitialActive {
            "RFC822"
        } else {
            "BODY.PEEK[]"
        };
        self.fetch_body = None;
        self.state = ImapState::AwaitFetch {
            tag: tag.clone(),
            uid,
            kind,
        };
        self.deadline_ms = Some(now_ms.saturating_add(COMMAND_TIMEOUT_MS));
        Ok(vec![ImapAction::Send(
            format!("{tag} UID FETCH {uid} (UID {item})\r\n").into_bytes(),
        )])
    }

    fn allocate_tag(&mut self) -> String {
        let tag = format!("ZC{:04}", self.next_tag);
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        tag
    }
}

fn starts_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn response_code_number(line: &str, code: &str) -> Option<u32> {
    line.split(['[', ']']).find_map(|section| {
        let mut words = section.split_whitespace();
        if words.next()?.eq_ignore_ascii_case(code) {
            words.next()?.parse().ok()
        } else {
            None
        }
    })
}

fn parse_search_response(line: &str) -> Option<Vec<u32>> {
    let mut words = line.split_whitespace();
    if words.next()? != "*" || !words.next()?.eq_ignore_ascii_case("SEARCH") {
        return None;
    }
    Some(words.filter_map(|word| word.parse().ok()).collect())
}

fn tagged_status(line: &str, tag: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    if words.next()? != tag {
        return None;
    }
    Some(words.next()?.to_ascii_uppercase())
}

fn require_imap_ok(status: &str, line: &str, command: &str) -> Result<(), String> {
    if status == "OK" {
        Ok(())
    } else {
        Err(format!("email: IMAP {command} failed: {line}"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundEmail {
    pub envelope_from: String,
    pub recipient: String,
    pub message: Vec<u8>,
}

pub fn build_outbound_email(
    config: &EmailConfig,
    recipient: &str,
    content: &str,
    subject: Option<&str>,
    in_reply_to: Option<&str>,
    timestamp_secs: u64,
    sequence: u64,
) -> Result<OutboundEmail, String> {
    if !config.outbound_configured()? {
        return Err("email: this channel is inbound-only; configure smtp_host and from_address to send mail".into());
    }
    validate_mailbox(&config.from_address)
        .map_err(|error| format!("email: invalid from_address: {error}"))?;
    validate_mailbox(recipient).map_err(|error| format!("email: invalid recipient: {error}"))?;

    let (subject, body) = outbound_subject_and_body(config, content, subject);
    validate_header_value("subject", &subject)?;
    let reply_header = match in_reply_to {
        Some(value) if is_synthetic_message_id(value) => None,
        Some(value) => Some(normalize_message_id(value)?),
        None => None,
    };
    let date = format_rfc5322_date(timestamp_secs)?;
    let domain = config
        .from_address
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or("zeroclaw.local");
    let message_id = format!("<zeroclaw-{timestamp_secs}-{sequence}@{domain}>");
    let encoded_subject = encode_subject(&subject);
    let canonical_body = normalize_crlf(&body);
    let encoded_body = wrap_base64(&BASE64.encode(canonical_body.as_bytes()));

    let mut message = String::new();
    message.push_str("Date: ");
    message.push_str(&date);
    message.push_str("\r\nFrom: <");
    message.push_str(&config.from_address);
    message.push_str(">\r\nTo: <");
    message.push_str(recipient);
    message.push_str(">\r\nSubject: ");
    message.push_str(&encoded_subject);
    message.push_str("\r\nMessage-ID: ");
    message.push_str(&message_id);
    message.push_str("\r\n");
    if let Some(reply_id) = reply_header.as_deref() {
        message.push_str("In-Reply-To: ");
        message.push_str(reply_id);
        message.push_str("\r\nReferences: ");
        message.push_str(reply_id);
        message.push_str("\r\n");
    }
    message.push_str(
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n",
    );
    message.push_str(&encoded_body);
    if !message.ends_with("\r\n") {
        message.push_str("\r\n");
    }
    if message.len() > MAX_OUTBOUND_MESSAGE_BYTES {
        return Err(format!(
            "email: encoded message exceeds {MAX_OUTBOUND_MESSAGE_BYTES} byte limit"
        ));
    }

    Ok(OutboundEmail {
        envelope_from: config.from_address.clone(),
        recipient: recipient.to_string(),
        message: message.into_bytes(),
    })
}

fn outbound_subject_and_body(
    config: &EmailConfig,
    content: &str,
    subject: Option<&str>,
) -> (String, String) {
    if let Some(subject) = subject {
        return (subject.to_string(), content.to_string());
    }
    if let Some(rest) = content.strip_prefix("Subject: ") {
        if let Some(newline) = rest.find('\n') {
            let subject = rest[..newline].trim_end_matches('\r').to_string();
            let body = rest[newline + 1..].trim().to_string();
            return (subject, body);
        }
    }
    (config.default_subject.clone(), content.to_string())
}

fn is_synthetic_message_id(value: &str) -> bool {
    value.starts_with("email-imap-") || value.starts_with("email-fallback-")
}

fn normalize_message_id(value: &str) -> Result<String, String> {
    let inner = value
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(value);
    let valid = !inner.is_empty()
        && inner.len() <= 996
        && inner.is_ascii()
        && inner.contains('@')
        && !inner.contains(['<', '>'])
        && !inner
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control());
    if !valid {
        return Err("email: in_reply_to must be a single RFC 5322 message ID".to_string());
    }
    Ok(format!("<{inner}>"))
}

fn encode_subject(subject: &str) -> String {
    if subject.is_ascii() && subject.len() <= 70 {
        return subject.to_string();
    }

    let mut words = Vec::new();
    let mut chunk = String::new();
    for character in subject.chars() {
        if !chunk.is_empty() && chunk.len() + character.len_utf8() > 36 {
            words.push(format!("=?UTF-8?B?{}?=", BASE64.encode(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(character);
    }
    if !chunk.is_empty() || words.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", BASE64.encode(chunk.as_bytes())));
    }
    words.join("\r\n ")
}

fn normalize_crlf(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                output.push_str("\r\n");
            }
            '\n' => output.push_str("\r\n"),
            _ => output.push(character),
        }
    }
    output
}

fn wrap_base64(encoded: &str) -> String {
    let mut output = String::with_capacity(encoded.len() + (encoded.len() / 76 + 1) * 2);
    for chunk in encoded.as_bytes().chunks(76) {
        output.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        output.push_str("\r\n");
    }
    output
}

fn format_rfc5322_date(timestamp_secs: u64) -> Result<String, String> {
    let timestamp = i64::try_from(timestamp_secs)
        .map_err(|_| "email: timestamp is outside the supported date range".to_string())?;
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(1900..=9999).contains(&year) {
        return Err("email: timestamp is outside the supported date range".to_string());
    }
    let hour = seconds / 3600;
    let minute = (seconds % 3600) / 60;
    let second = seconds % 60;
    let weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        [usize::try_from((days + 4).rem_euclid(7)).unwrap_or(0)];
    let month_name = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][usize::try_from(month.saturating_sub(1)).unwrap_or(0)];
    Ok(format!(
        "{weekday}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} +0000"
    ))
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

pub fn smtp_data_block(message: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(message.len() + 8);
    let mut line_start = true;
    for byte in message {
        if line_start && *byte == b'.' {
            output.push(b'.');
        }
        output.push(*byte);
        if *byte == b'\n' {
            line_start = true;
        } else if *byte != b'\r' {
            line_start = false;
        }
    }
    if !output.ends_with(b"\r\n") {
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b".\r\n");
    output
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtpReply {
    pub code: u16,
    pub lines: Vec<String>,
}

#[derive(Default)]
pub struct SmtpFramer {
    buffer: Vec<u8>,
    multiline: Option<(u16, Vec<String>)>,
}

impl SmtpFramer {
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<SmtpReply>, String> {
        if self.buffer.len().saturating_add(chunk.len()) > MAX_SMTP_BUFFER_BYTES {
            return Err("email: SMTP receive buffer limit exceeded".to_string());
        }
        self.buffer.extend_from_slice(chunk);
        let mut replies = Vec::new();
        while let Some(line_end) = find_crlf(&self.buffer) {
            if line_end > MAX_PROTOCOL_LINE_BYTES {
                return Err("email: SMTP response line limit exceeded".to_string());
            }
            let line: Vec<u8> = self.buffer.drain(..line_end).collect();
            self.buffer.drain(..2);
            let line = std::str::from_utf8(&line)
                .map_err(|_| "email: SMTP response was not UTF-8/ASCII".to_string())?;
            let bytes = line.as_bytes();
            if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
                return Err(format!("email: malformed SMTP response line: {line}"));
            }
            let code = line[..3]
                .parse::<u16>()
                .map_err(|_| "email: invalid SMTP response code".to_string())?;
            let separator = bytes.get(3).copied().unwrap_or(b' ');
            let detail = line.get(4..).unwrap_or_default().to_string();

            if let Some((expected, lines)) = &mut self.multiline {
                if *expected != code {
                    return Err("email: inconsistent SMTP multiline response code".to_string());
                }
                lines.push(detail);
                if separator == b' ' {
                    let (_, lines) = self.multiline.take().unwrap_or_default();
                    replies.push(SmtpReply { code, lines });
                } else if separator != b'-' {
                    return Err("email: malformed SMTP multiline separator".to_string());
                }
            } else if separator == b'-' {
                self.multiline = Some((code, vec![detail]));
            } else if separator == b' ' || bytes.len() == 3 {
                replies.push(SmtpReply {
                    code,
                    lines: vec![detail],
                });
            } else {
                return Err("email: malformed SMTP response separator".to_string());
            }
        }
        if self.buffer.len() > MAX_PROTOCOL_LINE_BYTES {
            return Err("email: SMTP response line limit exceeded".to_string());
        }
        Ok(replies)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmtpAction {
    Send(Vec<u8>),
    Delivered(String),
    Failed { recipient: String, reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmtpState {
    Disconnected,
    AwaitGreeting,
    AwaitEhlo,
    AwaitAuthPlain,
    AwaitAuthLoginChallenge,
    AwaitAuthLoginUser,
    AwaitAuthLoginPassword,
    Ready,
    AwaitMailFrom,
    AwaitRcptTo,
    AwaitData,
    AwaitBodyResult,
    AwaitRset,
}

pub struct SmtpMachine {
    state: SmtpState,
    queue: VecDeque<OutboundEmail>,
    current: Option<OutboundEmail>,
    deadline_ms: Option<u64>,
}

impl Default for SmtpMachine {
    fn default() -> Self {
        Self {
            state: SmtpState::Disconnected,
            queue: VecDeque::new(),
            current: None,
            deadline_ms: None,
        }
    }
}

impl SmtpMachine {
    pub fn enqueue(&mut self, message: OutboundEmail) -> Result<(), String> {
        if self.queue.len() + usize::from(self.current.is_some()) >= MAX_SMTP_QUEUE {
            return Err(format!(
                "email: SMTP queue is full ({MAX_SMTP_QUEUE} messages)"
            ));
        }
        self.queue.push_back(message);
        Ok(())
    }

    pub fn has_work(&self) -> bool {
        self.current.is_some() || !self.queue.is_empty()
    }

    pub fn is_connected(&self) -> bool {
        self.state != SmtpState::Disconnected
    }

    pub fn on_connected(&mut self, now_ms: u64) {
        self.state = SmtpState::AwaitGreeting;
        self.deadline_ms = Some(now_ms.saturating_add(COMMAND_TIMEOUT_MS));
    }

    pub fn on_disconnected(&mut self, reason: &str) -> Vec<SmtpAction> {
        let mut actions = Vec::new();
        if let Some(current) = self.current.take() {
            if self.state == SmtpState::AwaitBodyResult {
                actions.push(SmtpAction::Failed {
                    recipient: current.recipient,
                    reason: format!(
                        "SMTP connection closed after DATA; delivery status is unknown and the message will not be retried: {reason}"
                    ),
                });
            } else {
                self.queue.push_front(current);
            }
        }
        self.state = SmtpState::Disconnected;
        self.deadline_ms = None;
        actions
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<SmtpAction>, String> {
        if self.deadline_ms.is_some_and(|deadline| now_ms >= deadline) {
            return Err("email: SMTP command timed out".to_string());
        }
        if self.state == SmtpState::Ready {
            return Ok(self.start_next(now_ms));
        }
        Ok(Vec::new())
    }

    pub fn on_reply(
        &mut self,
        reply: SmtpReply,
        config: &EmailConfig,
        now_ms: u64,
    ) -> Result<Vec<SmtpAction>, String> {
        match self.state {
            SmtpState::Disconnected => {
                Err("email: SMTP reply arrived while disconnected".to_string())
            }
            SmtpState::AwaitGreeting => {
                require_smtp_code(&reply, &[220], "greeting")?;
                self.state = SmtpState::AwaitEhlo;
                self.set_deadline(now_ms);
                Ok(vec![SmtpAction::Send(b"EHLO zeroclaw.local\r\n".to_vec())])
            }
            SmtpState::AwaitEhlo => {
                require_smtp_code(&reply, &[250], "EHLO")?;
                let (supports_plain, supports_login) = smtp_auth_mechanisms(&reply);
                let (username, password) = config.smtp_credentials();
                if supports_plain {
                    let payload = BASE64.encode(format!("\0{username}\0{password}"));
                    self.state = SmtpState::AwaitAuthPlain;
                    self.set_deadline(now_ms);
                    Ok(vec![SmtpAction::Send(
                        format!("AUTH PLAIN {payload}\r\n").into_bytes(),
                    )])
                } else if supports_login {
                    self.state = SmtpState::AwaitAuthLoginChallenge;
                    self.set_deadline(now_ms);
                    Ok(vec![SmtpAction::Send(b"AUTH LOGIN\r\n".to_vec())])
                } else {
                    Err("email: SMTP server did not advertise AUTH PLAIN or AUTH LOGIN".to_string())
                }
            }
            SmtpState::AwaitAuthPlain => {
                if reply.code == 334 {
                    let (username, password) = config.smtp_credentials();
                    let payload = BASE64.encode(format!("\0{username}\0{password}"));
                    self.set_deadline(now_ms);
                    return Ok(vec![SmtpAction::Send(
                        format!("{payload}\r\n").into_bytes(),
                    )]);
                }
                require_smtp_code(&reply, &[235, 503], "AUTH PLAIN")?;
                self.state = SmtpState::Ready;
                self.deadline_ms = None;
                Ok(self.start_next(now_ms))
            }
            SmtpState::AwaitAuthLoginChallenge => {
                require_smtp_code(&reply, &[334], "AUTH LOGIN")?;
                let (username, _) = config.smtp_credentials();
                self.state = SmtpState::AwaitAuthLoginUser;
                self.set_deadline(now_ms);
                Ok(vec![SmtpAction::Send(
                    format!("{}\r\n", BASE64.encode(username)).into_bytes(),
                )])
            }
            SmtpState::AwaitAuthLoginUser => {
                require_smtp_code(&reply, &[334], "AUTH LOGIN username")?;
                let (_, password) = config.smtp_credentials();
                self.state = SmtpState::AwaitAuthLoginPassword;
                self.set_deadline(now_ms);
                Ok(vec![SmtpAction::Send(
                    format!("{}\r\n", BASE64.encode(password)).into_bytes(),
                )])
            }
            SmtpState::AwaitAuthLoginPassword => {
                require_smtp_code(&reply, &[235, 503], "AUTH LOGIN password")?;
                self.state = SmtpState::Ready;
                self.deadline_ms = None;
                Ok(self.start_next(now_ms))
            }
            SmtpState::Ready => {
                if reply.code == 421 {
                    Err(format!(
                        "email: SMTP service unavailable: {}",
                        smtp_detail(&reply)
                    ))
                } else {
                    Ok(Vec::new())
                }
            }
            SmtpState::AwaitMailFrom => {
                if reply.code == 250 {
                    let recipient = self.current_recipient()?.to_string();
                    self.state = SmtpState::AwaitRcptTo;
                    self.set_deadline(now_ms);
                    Ok(vec![SmtpAction::Send(
                        format!("RCPT TO:<{recipient}>\r\n").into_bytes(),
                    )])
                } else {
                    Ok(self.reject_current(&reply, "MAIL FROM", now_ms))
                }
            }
            SmtpState::AwaitRcptTo => {
                if matches!(reply.code, 250 | 251) {
                    self.state = SmtpState::AwaitData;
                    self.set_deadline(now_ms);
                    Ok(vec![SmtpAction::Send(b"DATA\r\n".to_vec())])
                } else {
                    Ok(self.reject_current(&reply, "RCPT TO", now_ms))
                }
            }
            SmtpState::AwaitData => {
                if reply.code == 354 {
                    let data = smtp_data_block(&self.current_message()?.message);
                    self.state = SmtpState::AwaitBodyResult;
                    self.set_deadline(now_ms);
                    Ok(vec![SmtpAction::Send(data)])
                } else {
                    Ok(self.reject_current(&reply, "DATA", now_ms))
                }
            }
            SmtpState::AwaitBodyResult => {
                if reply.code == 250 {
                    let delivered = self
                        .current
                        .take()
                        .ok_or_else(|| "email: missing SMTP transaction".to_string())?;
                    self.state = SmtpState::Ready;
                    self.deadline_ms = None;
                    let mut actions = vec![SmtpAction::Delivered(delivered.recipient)];
                    actions.extend(self.start_next(now_ms));
                    Ok(actions)
                } else {
                    Ok(self.reject_current(&reply, "message body", now_ms))
                }
            }
            SmtpState::AwaitRset => {
                self.state = SmtpState::Ready;
                self.deadline_ms = None;
                Ok(self.start_next(now_ms))
            }
        }
    }

    fn start_next(&mut self, now_ms: u64) -> Vec<SmtpAction> {
        if self.current.is_some() {
            return Vec::new();
        }
        let Some(message) = self.queue.pop_front() else {
            self.state = SmtpState::Ready;
            self.deadline_ms = None;
            return Vec::new();
        };
        let sender = message.envelope_from.clone();
        self.current = Some(message);
        self.state = SmtpState::AwaitMailFrom;
        self.set_deadline(now_ms);
        vec![SmtpAction::Send(
            format!("MAIL FROM:<{sender}>\r\n").into_bytes(),
        )]
    }

    fn reject_current(&mut self, reply: &SmtpReply, phase: &str, now_ms: u64) -> Vec<SmtpAction> {
        let recipient = self
            .current
            .take()
            .map(|message| message.recipient)
            .unwrap_or_else(|| "unknown".to_string());
        self.state = SmtpState::AwaitRset;
        self.set_deadline(now_ms);
        vec![
            SmtpAction::Failed {
                recipient,
                reason: format!(
                    "SMTP {phase} rejected with {}: {}",
                    reply.code,
                    smtp_detail(reply)
                ),
            },
            SmtpAction::Send(b"RSET\r\n".to_vec()),
        ]
    }

    fn current_message(&self) -> Result<&OutboundEmail, String> {
        self.current
            .as_ref()
            .ok_or_else(|| "email: missing SMTP transaction".to_string())
    }

    fn current_recipient(&self) -> Result<&str, String> {
        Ok(&self.current_message()?.recipient)
    }

    fn set_deadline(&mut self, now_ms: u64) {
        self.deadline_ms = Some(now_ms.saturating_add(COMMAND_TIMEOUT_MS));
    }
}

fn require_smtp_code(reply: &SmtpReply, expected: &[u16], phase: &str) -> Result<(), String> {
    if expected.contains(&reply.code) {
        Ok(())
    } else {
        Err(format!(
            "email: SMTP {phase} failed with {}: {}",
            reply.code,
            smtp_detail(reply)
        ))
    }
}

fn smtp_detail(reply: &SmtpReply) -> String {
    reply.lines.join(" | ")
}

fn smtp_auth_mechanisms(reply: &SmtpReply) -> (bool, bool) {
    let mut plain = false;
    let mut login = false;
    for line in &reply.lines {
        let uppercase = line.to_ascii_uppercase();
        let mechanisms = uppercase
            .strip_prefix("AUTH ")
            .or_else(|| uppercase.strip_prefix("AUTH="));
        if let Some(mechanisms) = mechanisms {
            for mechanism in mechanisms.split_whitespace() {
                plain |= mechanism == "PLAIN";
                login |= mechanism == "LOGIN";
            }
        }
    }
    (plain, login)
}
