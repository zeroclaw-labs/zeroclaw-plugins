//! Pure Twitch IRC protocol and configuration logic.
//!
//! The WASM component owns the host socket calls. This module owns only
//! host-testable parsing, framing, registration, routing, and message encoding.

use std::collections::BTreeMap;

use serde::Deserialize;

pub const CHANNEL: &str = "twitch";
pub const IRC_HOST: &str = "irc.chat.twitch.tv";
pub const IRC_PORT: u16 = 6697;

const REQUIRED_CAPABILITIES: &str = "twitch.tv/tags twitch.tv/commands";
const MAX_IRC_WIRE_BYTES: usize = 512;
const MAX_INBOUND_LINE_BYTES: usize = 16 * 1024;
const SENDER_PREFIX_RESERVE: usize = 64;

const TWITCH_STYLE_PREFIX: &str = "\
[context: you are responding over Twitch chat. \
Plain text only. No markdown, no tables, no XML/HTML tags. \
Never use triple backtick code fences. Use a single blank line to separate blocks instead. \
Be terse and concise. \
Use short lines. Avoid walls of text.]\n";

/// Name of the `x-secret` config property holding the OAuth token.
pub const OAUTH_TOKEN: &str = "oauth_token";

/// The public, schema-validated config object from `config.get`. The OAuth
/// token is not part of it: it is read through `secrets.get` when registering.
///
/// Derived wire values are intentionally computed on demand instead of being
/// cached beside these fields.
#[derive(Default, Deserialize)]
pub struct TwitchConfig {
    pub bot_username: String,
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub mention_only: bool,
}

impl TwitchConfig {
    pub fn from_public_json(input: &str) -> Result<Self, String> {
        let config: Self = serde_json::from_str(input)
            .map_err(|error| format!("twitch: invalid channel configuration: {error}"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.normalized_username()?;
        self.normalized_channels()?;
        Ok(())
    }

    pub fn normalized_username(&self) -> Result<String, String> {
        let username = self.bot_username.trim().to_ascii_lowercase();
        if !is_twitch_login(&username) {
            return Err(
                "twitch: bot_username must contain only ASCII letters, digits, or underscores"
                    .to_string(),
            );
        }
        Ok(username)
    }

    pub fn normalized_channels(&self) -> Result<Vec<String>, String> {
        self.channels
            .iter()
            .filter_map(|raw| normalize_twitch_channel(raw).map(|channel| (raw, channel)))
            .map(|(raw, channel)| {
                let login = channel.trim_start_matches('#');
                if is_twitch_login(login) {
                    Ok(channel)
                } else {
                    Err(format!("twitch: invalid channel name `{}`", raw.trim()))
                }
            })
            .collect()
    }
}

/// The `PASS` value for a raw OAuth token, refusing one that is empty or could
/// inject another IRC command.
pub fn oauth_pass(raw: &str) -> Result<String, String> {
    let token = normalize_oauth_token(raw);
    let secret = token.strip_prefix("oauth:").unwrap_or_default();
    if secret.is_empty()
        || secret
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("twitch: oauth_token is missing or malformed".to_string());
    }
    Ok(token)
}

/// Normalize a raw OAuth token into the PASS value Twitch expects.
pub fn normalize_oauth_token(raw: &str) -> String {
    let token = raw.trim();
    if token.starts_with("oauth:") {
        token.to_string()
    } else {
        format!("oauth:{token}")
    }
}

/// Normalize a Twitch login into the IRC channel target form.
pub fn normalize_twitch_channel(raw: &str) -> Option<String> {
    let channel = raw.trim().to_ascii_lowercase();
    let login = channel.trim_start_matches('#');
    if login.is_empty() {
        None
    } else {
        Some(format!("#{login}"))
    }
}

fn is_twitch_login(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Encode Twitch IRCv3 capabilities followed by PASS and NICK registration.
pub fn registration_frame(config: &TwitchConfig, oauth_token: &str) -> Result<Vec<u8>, String> {
    let token = oauth_pass(oauth_token)?;
    let username = config.normalized_username()?;
    encode_lines(&[
        format!("CAP REQ :{REQUIRED_CAPABILITIES}"),
        format!("PASS {token}"),
        format!("NICK {username}"),
    ])
}

fn join_frame(config: &TwitchConfig) -> Result<Vec<u8>, String> {
    let lines = config
        .normalized_channels()?
        .into_iter()
        .map(|channel| format!("JOIN {channel}"))
        .collect::<Vec<_>>();
    encode_lines(&lines)
}

fn encode_lines(lines: &[String]) -> Result<Vec<u8>, String> {
    let mut frame = Vec::new();
    for line in lines {
        frame.extend(encode_line(line)?);
    }
    Ok(frame)
}

fn encode_line(line: &str) -> Result<Vec<u8>, String> {
    if line.contains(['\r', '\n']) {
        return Err("twitch: IRC command contains a line break".to_string());
    }
    if line.len().saturating_add(2) > MAX_IRC_WIRE_BYTES {
        return Err("twitch: IRC command exceeds the 512-byte wire limit".to_string());
    }
    let mut encoded = Vec::with_capacity(line.len() + 2);
    encoded.extend_from_slice(line.as_bytes());
    encoded.extend_from_slice(b"\r\n");
    Ok(encoded)
}

/// Incrementally reassembles CRLF-delimited IRC lines from arbitrary TCP chunks.
#[derive(Default)]
pub struct IrcLineBuffer {
    pending: Vec<u8>,
}

impl IrcLineBuffer {
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<String>, String> {
        self.pending.extend_from_slice(chunk);
        let mut lines = Vec::new();
        let mut consumed = 0;

        while let Some(offset) = memchr::memchr(b'\n', &self.pending[consumed..]) {
            let newline = consumed + offset;
            let mut end = newline;
            if end > consumed && self.pending[end - 1] == b'\r' {
                end -= 1;
            }
            let line = &self.pending[consumed..end];
            if line.len() > MAX_INBOUND_LINE_BYTES {
                self.pending.clear();
                return Err("twitch: inbound IRC line exceeds the safety limit".to_string());
            }
            if !line.is_empty() {
                lines.push(String::from_utf8_lossy(line).into_owned());
            }
            consumed = newline + 1;
        }

        if consumed > 0 {
            self.pending.drain(..consumed);
        }
        if self.pending.len() > MAX_INBOUND_LINE_BYTES {
            self.pending.clear();
            return Err("twitch: unterminated IRC line exceeds the safety limit".to_string());
        }
        Ok(lines)
    }
}

/// One parsed IRC message, including IRCv3 tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrcMessage {
    tags: BTreeMap<String, String>,
    prefix: Option<String>,
    command: String,
    params: Vec<String>,
}

impl IrcMessage {
    pub fn parse(line: &str) -> Option<Self> {
        let mut rest = line.trim_end_matches(['\r', '\n']);
        if rest.is_empty() {
            return None;
        }

        let mut tags = BTreeMap::new();
        if let Some(tagged) = rest.strip_prefix('@') {
            let separator = tagged.find(' ')?;
            for tag in tagged[..separator].split(';') {
                let (key, value) = tag.split_once('=').unwrap_or((tag, ""));
                if !key.is_empty() {
                    tags.insert(key.to_string(), unescape_tag_value(value));
                }
            }
            rest = tagged[separator + 1..].trim_start();
        }

        let prefix = if let Some(prefixed) = rest.strip_prefix(':') {
            let separator = prefixed.find(' ')?;
            let prefix = prefixed[..separator].to_string();
            rest = prefixed[separator + 1..].trim_start();
            Some(prefix)
        } else {
            None
        };

        let (middle, trailing) = if let Some(separator) = rest.find(" :") {
            (&rest[..separator], Some(&rest[separator + 2..]))
        } else {
            (rest, None)
        };
        let mut parts = middle.split_whitespace();
        let command = parts.next()?.to_ascii_uppercase();
        let mut params = parts.map(str::to_string).collect::<Vec<_>>();
        if let Some(trailing) = trailing {
            params.push(trailing.to_string());
        }

        Some(Self {
            tags,
            prefix,
            command,
            params,
        })
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn params(&self) -> &[String] {
        &self.params
    }

    pub fn tag(&self, key: &str) -> Option<&str> {
        self.tags.get(key).map(String::as_str)
    }

    pub fn nick(&self) -> Option<&str> {
        self.prefix.as_deref().and_then(|prefix| {
            let end = prefix.find('!').unwrap_or(prefix.len());
            let nick = &prefix[..end];
            (!nick.is_empty()).then_some(nick)
        })
    }
}

fn unescape_tag_value(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        match chars.next() {
            Some('s') => output.push(' '),
            Some(':') => output.push(';'),
            Some('r') => output.push('\r'),
            Some('n') => output.push('\n'),
            Some('\\') => output.push('\\'),
            Some(other) => output.push(other),
            None => output.push('\\'),
        }
    }
    output
}

/// Normalized inbound data ready for the WIT channel record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub timestamp_ms: Option<u64>,
    pub thread_id: Option<String>,
}

pub fn privmsg_to_inbound(message: &IrcMessage, config: &TwitchConfig) -> Option<Inbound> {
    if message.command != "PRIVMSG" {
        return None;
    }
    // Twitch chat delivers channel messages only; whispers are not carried
    // over IRC, and a reply to anything else would land in `#<bot login>`.
    let target = message
        .params
        .first()
        .filter(|target| target.starts_with('#'))?;
    let target = normalize_twitch_channel(target)?;
    let text = message.params.get(1)?;
    let sender = message.nick()?.to_ascii_lowercase();
    if !is_twitch_login(&sender) {
        return None;
    }
    let bot_username = config.normalized_username().ok()?;
    if config.mention_only && !is_mentioned(&bot_username, text) {
        return None;
    }

    let display_name = message
        .tag("display-name")
        .filter(|name| !name.is_empty())
        .unwrap_or(&sender);
    let tagged_id = message.tag("id").filter(|id| !id.is_empty());
    let timestamp_ms = message
        .tag("tmi-sent-ts")
        .and_then(|value| value.parse::<u64>().ok());
    let id = tagged_id.map(str::to_string).unwrap_or_else(|| {
        fallback_message_id(&sender, &target, text, timestamp_ms.unwrap_or_default())
    });
    let thread_id = message
        .tag("reply-thread-parent-msg-id")
        .filter(|id| !id.is_empty())
        .or_else(|| {
            message
                .tag("reply-parent-msg-id")
                .filter(|id| !id.is_empty())
        })
        .or(tagged_id)
        .map(str::to_string);
    let content = format!("{TWITCH_STYLE_PREFIX}<{display_name}> {text}");

    Some(Inbound {
        id,
        sender,
        reply_target: target,
        content,
        timestamp_ms,
        thread_id,
    })
}

fn fallback_message_id(sender: &str, target: &str, text: &str, timestamp_ms: u64) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in sender
        .bytes()
        .chain(target.bytes())
        .chain(text.bytes())
        .chain(timestamp_ms.to_le_bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("twitch-{timestamp_ms}-{hash:016x}")
}

fn is_irc_nick_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

pub fn is_mentioned(bot_username: &str, text: &str) -> bool {
    let username = bot_username.to_ascii_lowercase();
    if username.is_empty() {
        return false;
    }
    let text = text.to_ascii_lowercase();
    text.match_indices(&username).any(|(start, matched)| {
        let before = (start != 0)
            .then(|| text[..start].chars().next_back())
            .flatten();
        let end = start + matched.len();
        let after = text[end..].chars().next();
        before.is_none_or(|ch| !is_irc_nick_char(ch))
            && after.is_none_or(|ch| !is_irc_nick_char(ch))
    })
}

/// Encode one or more Twitch PRIVMSG commands, preserving UTF-8 boundaries.
pub fn encode_privmsg(
    recipient: &str,
    content: &str,
    reply_parent_id: Option<&str>,
) -> Result<Vec<Vec<u8>>, String> {
    let target = normalize_twitch_channel(recipient)
        .filter(|channel| is_twitch_login(channel.trim_start_matches('#')))
        .ok_or_else(|| format!("twitch: invalid PRIVMSG recipient `{}`", recipient.trim()))?;

    let tag_prefix = match reply_parent_id.filter(|id| !id.is_empty()) {
        Some(id) => {
            if !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err("twitch: invalid reply parent message id".to_string());
            }
            format!("@reply-parent-msg-id={id} ")
        }
        None => String::new(),
    };

    let fixed_bytes = SENDER_PREFIX_RESERVE
        .saturating_add(tag_prefix.len())
        .saturating_add("PRIVMSG ".len())
        .saturating_add(target.len())
        .saturating_add(" :".len())
        .saturating_add(2);
    let max_payload = MAX_IRC_WIRE_BYTES
        .checked_sub(fixed_bytes)
        .filter(|limit| *limit > 0)
        .ok_or_else(|| "twitch: PRIVMSG target or reply tag leaves no payload space".to_string())?;

    split_message(content, max_payload)
        .into_iter()
        .map(|chunk| encode_line(&format!("{tag_prefix}PRIVMSG {target} :{chunk}")))
        .collect()
}

pub fn split_message(message: &str, max_bytes: usize) -> Vec<String> {
    if max_bytes == 0 {
        return vec![message.replace(['\r', '\n'], " ")];
    }

    let mut chunks = Vec::new();
    for line in message.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let mut remaining = line;
        while !remaining.is_empty() {
            if remaining.len() <= max_bytes {
                chunks.push(remaining.to_string());
                break;
            }
            let mut split_at = max_bytes;
            while split_at > 0 && !remaining.is_char_boundary(split_at) {
                split_at -= 1;
            }
            if split_at == 0 {
                split_at = max_bytes;
                while split_at < remaining.len() && !remaining.is_char_boundary(split_at) {
                    split_at += 1;
                }
            }
            chunks.push(remaining[..split_at].to_string());
            remaining = &remaining[split_at..];
        }
    }
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    chunks
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolAction {
    Send(Vec<u8>),
    Inbound(Inbound),
    Ready,
    /// Drop the connection and reconnect with backoff.
    Disconnect(String),
    /// Twitch rejected the credentials or capabilities: reconnecting soon
    /// cannot help and risks a ban for login flooding.
    Rejected(String),
}

impl ProtocolAction {
    fn ends_connection(&self) -> bool {
        matches!(self, Self::Disconnect(_) | Self::Rejected(_))
    }
}

/// Stateful IRC registration/framing machine with no transport dependency.
#[derive(Default)]
pub struct ProtocolSession {
    lines: IrcLineBuffer,
    welcomed: bool,
    tags_acknowledged: bool,
    commands_acknowledged: bool,
    ready: bool,
}

impl ProtocolSession {
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn receive(&mut self, chunk: &[u8], config: &TwitchConfig) -> Vec<ProtocolAction> {
        let lines = match self.lines.push(chunk) {
            Ok(lines) => lines,
            Err(error) => return vec![ProtocolAction::Disconnect(error)],
        };
        let mut actions = Vec::new();
        for line in lines {
            let Some(message) = IrcMessage::parse(&line) else {
                continue;
            };
            self.handle_message(&message, config, &mut actions);
            if actions.last().is_some_and(ProtocolAction::ends_connection) {
                break;
            }
        }
        actions
    }

    fn handle_message(
        &mut self,
        message: &IrcMessage,
        config: &TwitchConfig,
        actions: &mut Vec<ProtocolAction>,
    ) {
        match message.command() {
            "PING" => {
                let token = message.params().first().map_or("", String::as_str);
                match encode_line(&format!("PONG :{token}")) {
                    Ok(frame) => actions.push(ProtocolAction::Send(frame)),
                    Err(error) => actions.push(ProtocolAction::Disconnect(error)),
                }
                return;
            }
            "CAP" => self.handle_capabilities(message, actions),
            "001" => self.welcomed = true,
            "PRIVMSG" if self.ready => {
                if let Some(inbound) = privmsg_to_inbound(message, config) {
                    actions.push(ProtocolAction::Inbound(inbound));
                }
            }
            "RECONNECT" | "ERROR" => actions.push(ProtocolAction::Disconnect(
                "twitch: IRC server requested reconnect".to_string(),
            )),
            "464" => actions.push(ProtocolAction::Rejected(
                "twitch: IRC authentication failed".to_string(),
            )),
            "NOTICE" if is_authentication_failure(message) => {
                actions.push(ProtocolAction::Rejected(
                    "twitch: IRC authentication failed".to_string(),
                ));
            }
            _ => {}
        }

        if !actions.last().is_some_and(ProtocolAction::ends_connection) {
            self.activate_if_ready(config, actions);
        }
    }

    fn handle_capabilities(&mut self, message: &IrcMessage, actions: &mut Vec<ProtocolAction>) {
        let tokens = message
            .params()
            .iter()
            .flat_map(|param| param.split_whitespace())
            .collect::<Vec<_>>();
        if tokens.iter().any(|token| token.eq_ignore_ascii_case("NAK"))
            && tokens
                .iter()
                .any(|token| matches!(*token, "twitch.tv/tags" | "twitch.tv/commands"))
        {
            actions.push(ProtocolAction::Rejected(
                "twitch: IRC server rejected required tags/commands capabilities".to_string(),
            ));
            return;
        }
        if tokens.iter().any(|token| token.eq_ignore_ascii_case("ACK")) {
            self.tags_acknowledged |= tokens.contains(&"twitch.tv/tags");
            self.commands_acknowledged |= tokens.contains(&"twitch.tv/commands");
        }
    }

    fn activate_if_ready(&mut self, config: &TwitchConfig, actions: &mut Vec<ProtocolAction>) {
        if self.ready || !self.welcomed || !self.tags_acknowledged || !self.commands_acknowledged {
            return;
        }
        match join_frame(config) {
            Ok(frame) => {
                if !frame.is_empty() {
                    actions.push(ProtocolAction::Send(frame));
                }
                self.ready = true;
                actions.push(ProtocolAction::Ready);
            }
            Err(error) => actions.push(ProtocolAction::Disconnect(error)),
        }
    }
}

fn is_authentication_failure(message: &IrcMessage) -> bool {
    if message.tag("msg-id").is_some_and(|id| {
        matches!(
            id,
            "login_authentication_failed" | "improperly_formatted_auth"
        )
    }) {
        return true;
    }
    message.params().last().is_some_and(|text| {
        let text = text.to_ascii_lowercase();
        text.contains("login authentication failed") || text.contains("improperly formatted auth")
    })
}
