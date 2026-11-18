//! Pure IRC protocol logic: configuration, registration with IRCv3 capability
//! negotiation and SASL, liveness, inbound shaping, outbound framing and
//! pacing, and reconnect policy.
//!
//! Nothing here performs I/O or reads a clock. The component shim in `lib.rs`
//! owns the host socket and passes the current time in, which keeps every
//! decision below testable with plain `cargo test`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Deserialize;

pub const CHANNEL: &str = "irc";
pub const DEFAULT_PORT: u16 = 6697;

/// RFC 1459 line limit, CRLF included.
const IRC_LINE_BYTES: usize = 512;
/// An IRCv3 server may send up to 8191 bytes of tags ahead of a 512-byte
/// message; anything longer without a newline is a broken or hostile peer.
pub const MAX_INBOUND_LINE_BYTES: usize = 16 * 1024;
/// Bytes the server prepends when relaying our line: `:nick!user@host `.
/// The nick is added at use; this covers `:`, `!`, `@`, the space, a 10-byte
/// ident, and a 64-byte host or cloak.
const RELAY_PREFIX_RESERVE: usize = 78;
/// SASL payloads are sent in 400-byte `AUTHENTICATE` chunks.
const SASL_CHUNK: usize = 400;
/// Nick collisions retried during registration by appending `_`.
const MAX_NICK_RETRIES: u8 = 3;

/// Registration must reach `001` within this long after connecting.
pub const REGISTRATION_TIMEOUT_MS: u64 = 60_000;
/// Silence before the client checks the link with its own `PING`.
pub const IDLE_BEFORE_PING_MS: u64 = 120_000;
/// How long a client `PING` may go unanswered before the link is dead.
pub const PING_TIMEOUT_MS: u64 = 60_000;

/// Outbound pacing, after irssi's defaults: a burst of five lines, then one
/// line every two seconds. Networks disconnect clients for excess flood.
pub const PACE_INTERVAL_MS: u64 = 2_000;
pub const PACE_BURST: u64 = 5;
/// Lines waiting for the pacer. A reply that would overflow it is refused.
pub const MAX_OUTBOUND_LINES: usize = 256;

pub const IRC_STYLE_PREFIX: &str = "\
[context: you are responding over IRC. Plain text only. No markdown, tables, \
or XML/HTML tags. Never use triple backtick code fences. Be terse and use \
short lines.]\n";

// ── configuration ───────────────────────────────────────────────────────────

/// SASL mechanism used during registration.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SaslMechanism {
    /// Account name and the `sasl_password` secret.
    Plain,
    /// The client certificate of the instance's `tls_profile` (CertFP).
    External,
}

impl SaslMechanism {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::External => "EXTERNAL",
        }
    }
}

/// Which identity an inbound message carries as its sender.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SenderIdentity {
    /// The sender's nickname. Anyone can use an unregistered nick.
    #[default]
    Nick,
    /// The services account from the IRCv3 `account-tag` capability.
    /// Messages from users who are not logged in are dropped.
    Account,
}

/// The public, schema-validated config object from `config.get`. Secrets
/// (`server_password`, `nickserv_password`, `sasl_password`) are not part of
/// it; they are read through [`Secrets`] at the moment they are sent.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct IrcConfig {
    pub server: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub nickname: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub mention_only: bool,
    #[serde(default)]
    pub sasl_mechanism: Option<SaslMechanism>,
    #[serde(default)]
    pub sasl_username: Option<String>,
    #[serde(default)]
    pub tls_profile: Option<String>,
    #[serde(default)]
    pub sender_identity: SenderIdentity,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl IrcConfig {
    pub fn from_public_json(input: &str) -> Result<Self, String> {
        let config: Self = serde_json::from_str(input)
            .map_err(|error| format!("irc: invalid config ({error})"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !is_host(&self.server) {
            return Err("irc: server must be a hostname without whitespace".into());
        }
        if self.port == 0 {
            return Err("irc: port must be between 1 and 65535".into());
        }
        if !is_nick(&self.nickname) {
            return Err("irc: nickname is not a valid IRC nickname".into());
        }
        if !is_atom(self.username()) {
            return Err(
                "irc: username must not contain spaces, colons, or control characters".into(),
            );
        }
        if self
            .sasl_username
            .as_deref()
            .is_some_and(|name| !is_atom(name))
        {
            return Err(
                "irc: sasl_username must not contain spaces, colons, or control characters".into(),
            );
        }
        if let Some(channel) = self
            .channels
            .iter()
            .find(|channel| !is_channel_name(channel))
        {
            return Err(format!(
                "irc: `{}` is not a valid channel name",
                channel.trim()
            ));
        }
        if self
            .tls_profile
            .as_deref()
            .is_some_and(|profile| profile.trim().is_empty())
        {
            return Err("irc: tls_profile must not be empty".into());
        }
        if self.sasl_mechanism == Some(SaslMechanism::External) && self.tls_profile.is_none() {
            return Err(
                "irc: sasl_mechanism = \"external\" needs a tls_profile with a client certificate"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn nickname(&self) -> &str {
        self.nickname.trim()
    }

    pub fn username(&self) -> &str {
        self.username
            .as_deref()
            .map(str::trim)
            .filter(|username| !username.is_empty())
            .unwrap_or_else(|| self.nickname())
    }

    /// The account SASL authenticates as. It defaults to the configured
    /// nickname, never to a collision-renamed one.
    pub fn sasl_account(&self) -> &str {
        self.sasl_username
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| self.nickname())
    }

    pub fn tls_profile(&self) -> Option<&str> {
        self.tls_profile.as_deref().map(str::trim)
    }
}

fn is_host(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 253
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

fn is_atom(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == ':'
        })
}

fn is_nick(value: &str) -> bool {
    let value = value.trim();
    is_atom(value)
        && !value.starts_with(['#', '&', '$', '+', '!', '-'])
        && !value.starts_with(|character: char| character.is_ascii_digit())
        && !value.contains([',', '*', '?', '!', '@', '.'])
}

/// Channel prefixes (`CHANTYPES`) in common use.
fn is_channel_target(target: &str) -> bool {
    target.starts_with(['#', '&', '+', '!'])
}

fn is_channel_name(value: &str) -> bool {
    let value = value.trim();
    is_channel_target(value) && value.len() > 1 && is_target(value)
}

fn is_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && !value.starts_with(':')
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == ','
        })
}

/// Secret properties, read at the point of use. `Ok(None)` means the secret is
/// not set; `Err` means the host could not serve it right now.
pub trait Secrets {
    fn get(&mut self, name: &str) -> Result<Option<String>, String>;
}

pub const SERVER_PASSWORD: &str = "server_password";
pub const NICKSERV_PASSWORD: &str = "nickserv_password";
pub const SASL_PASSWORD: &str = "sasl_password";

fn credential(secrets: &mut dyn Secrets, name: &str) -> Result<Option<String>, Disconnect> {
    let value = secrets
        .get(name)
        .map_err(|_| Disconnect::transient("a credential is temporarily unavailable"))?;
    match value {
        Some(value) if value.contains(['\r', '\n', '\0']) => Err(Disconnect::fatal(
            "a credential contains a line break or NUL",
        )),
        Some(value) if value.is_empty() => Ok(None),
        other => Ok(other),
    }
}

// ── wire format ─────────────────────────────────────────────────────────────

/// One parsed IRC message, IRCv3 tags included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrcMessage {
    pub tags: BTreeMap<String, String>,
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

impl IrcMessage {
    pub fn parse(line: &str) -> Option<Self> {
        let mut rest = line.trim_end_matches(['\r', '\n']);
        let mut tags = BTreeMap::new();
        if let Some(tagged) = rest.strip_prefix('@') {
            let end = tagged.find(' ')?;
            for tag in tagged[..end].split(';') {
                let (key, value) = tag.split_once('=').unwrap_or((tag, ""));
                if !key.is_empty() {
                    tags.insert(key.to_string(), unescape_tag_value(value));
                }
            }
            rest = tagged[end + 1..].trim_start_matches(' ');
        }
        let prefix = match rest.strip_prefix(':') {
            Some(prefixed) => {
                let end = prefixed.find(' ')?;
                rest = prefixed[end + 1..].trim_start_matches(' ');
                Some(prefixed[..end].to_string())
            }
            None => None,
        };
        let (middle, trailing) = match rest.find(" :") {
            Some(index) => (&rest[..index], Some(&rest[index + 2..])),
            None => match rest.strip_prefix(':') {
                Some(trailing) => ("", Some(trailing)),
                None => (rest, None),
            },
        };
        let mut parts = middle.split(' ').filter(|part| !part.is_empty());
        let command = parts.next()?.to_ascii_uppercase();
        let mut params: Vec<String> = parts.map(str::to_string).collect();
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

    pub fn nick(&self) -> Option<&str> {
        let prefix = self.prefix.as_deref()?;
        let nick = &prefix[..prefix.find(['!', '@']).unwrap_or(prefix.len())];
        (!nick.is_empty()).then_some(nick)
    }

    pub fn tag(&self, key: &str) -> Option<&str> {
        self.tags.get(key).map(String::as_str)
    }

    fn param(&self, index: usize) -> &str {
        self.params.get(index).map_or("", String::as_str)
    }
}

fn unescape_tag_value(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match characters.next() {
            Some(':') => output.push(';'),
            Some('s') => output.push(' '),
            Some('r') => output.push('\r'),
            Some('n') => output.push('\n'),
            Some(other) => output.push(other),
            None => {}
        }
    }
    output
}

/// Reassembles CRLF-delimited lines from arbitrary socket chunks.
#[derive(Debug, Default)]
pub struct LineBuffer {
    pending: Vec<u8>,
}

impl LineBuffer {
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<String>, String> {
        self.pending.extend_from_slice(chunk);
        let mut lines = Vec::new();
        let mut start = 0;
        while let Some(offset) = self.pending[start..].iter().position(|byte| *byte == b'\n') {
            let newline = start + offset;
            let mut end = newline;
            if end > start && self.pending[end - 1] == b'\r' {
                end -= 1;
            }
            if end - start > MAX_INBOUND_LINE_BYTES {
                self.pending.clear();
                return Err("irc: inbound line exceeds 16 KiB".into());
            }
            if end > start {
                lines.push(String::from_utf8_lossy(&self.pending[start..end]).into_owned());
            }
            start = newline + 1;
        }
        self.pending.drain(..start);
        if self.pending.len() > MAX_INBOUND_LINE_BYTES {
            self.pending.clear();
            return Err("irc: unterminated inbound line exceeds 16 KiB".into());
        }
        Ok(lines)
    }
}

/// Append CRLF to each line, refusing any that would inject another command.
pub fn encode_lines<S: AsRef<str>>(lines: &[S]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for line in lines {
        let line = line.as_ref();
        if line.contains(['\r', '\n', '\0']) {
            return Err("irc: refusing to send a line containing CR, LF, or NUL".into());
        }
        if line.len() + 2 > IRC_LINE_BYTES {
            return Err("irc: refusing to send a line over 512 bytes".into());
        }
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    Ok(bytes)
}

// ── session ─────────────────────────────────────────────────────────────────

/// How a connection ended, and how soon to try again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disconnect {
    pub retry: Retry,
    pub reason: String,
}

impl Disconnect {
    pub fn transient(reason: impl Into<String>) -> Self {
        Self {
            retry: Retry::Backoff,
            reason: reason.into(),
        }
    }

    /// Retrying soon cannot help: bad credentials or a refused capability.
    pub fn fatal(reason: impl Into<String>) -> Self {
        Self {
            retry: Retry::Park,
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    /// Exponential backoff.
    Backoff,
    /// The host refused the destination or TLS profile; an operator must act.
    Refused,
    /// The server rejected our credentials or configuration.
    Park,
}

/// Inbound data ready for the WIT record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    pub sender: String,
    pub reply_target: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// A protocol line to send now, ahead of paced chat.
    Send(String),
    Inbound(Inbound),
    /// Registration completed (`001`).
    Registered,
    Disconnect(Disconnect),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sasl {
    Off,
    Wanted(SaslMechanism),
    Authenticating(SaslMechanism),
    Done,
}

/// Protocol state for one connection. A new connection gets a new session.
#[derive(Debug)]
pub struct Session {
    nick: String,
    nick_retries: u8,
    registered: bool,
    sasl: Sasl,
    want_account_tag: bool,
    account_tag: bool,
    available_caps: BTreeSet<String>,
    cap_negotiating: bool,
    connected_ms: u64,
    last_rx_ms: u64,
    ping_sent_ms: Option<u64>,
}

impl Session {
    pub fn new(config: &IrcConfig, now_ms: u64) -> Self {
        Self {
            nick: config.nickname().to_string(),
            nick_retries: 0,
            registered: false,
            sasl: config.sasl_mechanism.map_or(Sasl::Off, Sasl::Wanted),
            want_account_tag: config.sender_identity == SenderIdentity::Account,
            account_tag: false,
            available_caps: BTreeSet::new(),
            cap_negotiating: true,
            connected_ms: now_ms,
            last_rx_ms: now_ms,
            ping_sent_ms: None,
        }
    }

    pub fn nick(&self) -> &str {
        &self.nick
    }

    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// The opening burst: capability discovery, then `PASS`, `NICK`, `USER`.
    /// A server without IRCv3 ignores `CAP LS` and registers normally.
    pub fn registration(
        &self,
        config: &IrcConfig,
        secrets: &mut dyn Secrets,
    ) -> Result<Vec<String>, Disconnect> {
        let mut lines = vec!["CAP LS 302".to_string()];
        if let Some(password) = credential(secrets, SERVER_PASSWORD)? {
            lines.push(format!("PASS {}", trailing_if_needed(&password)));
        }
        lines.push(format!("NICK {}", self.nick));
        lines.push(format!("USER {} 0 * :ZeroClaw", config.username()));
        Ok(lines)
    }

    pub fn handle_line(
        &mut self,
        config: &IrcConfig,
        secrets: &mut dyn Secrets,
        line: &str,
        now_ms: u64,
    ) -> Vec<Action> {
        self.last_rx_ms = now_ms;
        self.ping_sent_ms = None;
        let Some(message) = IrcMessage::parse(line) else {
            return Vec::new();
        };
        match self.handle_message(config, secrets, &message) {
            Ok(actions) => actions,
            Err(disconnect) => vec![Action::Disconnect(disconnect)],
        }
    }

    fn handle_message(
        &mut self,
        config: &IrcConfig,
        secrets: &mut dyn Secrets,
        message: &IrcMessage,
    ) -> Result<Vec<Action>, Disconnect> {
        let send = |line: String| Ok(vec![Action::Send(line)]);
        match message.command.as_str() {
            "PING" => send(format!("PONG :{}", message.param(0))),
            "CAP" => self.handle_cap(message),
            "AUTHENTICATE" if message.param(0) == "+" => self.authenticate(config, secrets),
            // RPL_SASLSUCCESS, ERR_SASLALREADY
            "903" | "907" => {
                self.sasl = Sasl::Done;
                self.end_cap()
            }
            // ERR_NICKLOCKED, ERR_SASLFAIL, ERR_SASLTOOLONG, ERR_SASLABORTED
            "902" | "904" | "905" | "906" => Err(Disconnect::fatal(format!(
                "SASL authentication failed ({})",
                message.command
            ))),
            "001" => self.welcome(config, secrets, message),
            // ERR_NICKNAMEINUSE, ERR_UNAVAILRESOURCE
            "433" | "437" if !self.registered => {
                if self.nick_retries >= MAX_NICK_RETRIES {
                    return Err(Disconnect::transient(
                        "the nickname and its alternates are in use",
                    ));
                }
                self.nick_retries += 1;
                self.nick.push('_');
                send(format!("NICK {}", self.nick))
            }
            // ERR_ERRONEUSNICKNAME
            "432" if !self.registered => Err(Disconnect::fatal(
                "the server rejected the nickname as invalid",
            )),
            // ERR_PASSWDMISMATCH, ERR_YOUREBANNEDCREEP
            "464" => Err(Disconnect::fatal("the server rejected the server password")),
            "465" => Err(Disconnect::fatal(
                "the server reports this client is banned",
            )),
            "ERROR" => Err(Disconnect::transient(format!(
                "the server closed the link: {}",
                truncate(message.param(0), 120)
            ))),
            "NICK" => {
                if message
                    .nick()
                    .is_some_and(|nick| nick.eq_ignore_ascii_case(&self.nick))
                {
                    let new = message.param(0);
                    if is_nick(new) {
                        self.nick = new.to_string();
                    }
                }
                Ok(Vec::new())
            }
            "PRIVMSG" if self.registered => Ok(self
                .inbound(config, message)
                .map(Action::Inbound)
                .into_iter()
                .collect()),
            _ => Ok(Vec::new()),
        }
    }

    fn handle_cap(&mut self, message: &IrcMessage) -> Result<Vec<Action>, Disconnect> {
        let subcommand = message.param(1).to_ascii_uppercase();
        let list = message.params.last().map_or("", String::as_str);
        let caps = || list.split(' ').filter(|cap| !cap.is_empty());
        match subcommand.as_str() {
            "LS" if self.cap_negotiating => {
                for cap in caps() {
                    let name = cap.split_once('=').map_or(cap, |(name, _)| name);
                    self.available_caps.insert(name.to_ascii_lowercase());
                }
                // `CAP * LS * :...` continues on the next line.
                if message.params.len() >= 4 && message.param(2) == "*" {
                    return Ok(Vec::new());
                }
                let mut wanted = Vec::new();
                if let Sasl::Wanted(_) = self.sasl {
                    if !self.available_caps.contains("sasl") {
                        return Err(Disconnect::fatal(
                            "SASL is configured but the server does not offer it",
                        ));
                    }
                    wanted.push("sasl");
                }
                if self.want_account_tag {
                    if !self.available_caps.contains("account-tag") {
                        return Err(Disconnect::fatal(
                            "sender_identity = \"account\" needs the account-tag capability, \
                             which the server does not offer",
                        ));
                    }
                    wanted.push("account-tag");
                }
                if wanted.is_empty() {
                    return self.end_cap();
                }
                Ok(vec![Action::Send(format!("CAP REQ :{}", wanted.join(" ")))])
            }
            "ACK" => {
                let acked: Vec<String> = caps().map(str::to_ascii_lowercase).collect();
                if acked.iter().any(|cap| cap == "account-tag") {
                    self.account_tag = true;
                }
                match self.sasl {
                    Sasl::Wanted(mechanism) if acked.iter().any(|cap| cap == "sasl") => {
                        self.sasl = Sasl::Authenticating(mechanism);
                        Ok(vec![Action::Send(format!(
                            "AUTHENTICATE {}",
                            mechanism.wire_name()
                        ))])
                    }
                    Sasl::Wanted(_) => Err(Disconnect::fatal(
                        "the server did not acknowledge the SASL capability",
                    )),
                    _ => self.end_cap(),
                }
            }
            "NAK" => Err(Disconnect::fatal(format!(
                "the server refused the capabilities `{}`",
                truncate(list, 120)
            ))),
            _ => Ok(Vec::new()),
        }
    }

    fn end_cap(&mut self) -> Result<Vec<Action>, Disconnect> {
        if !self.cap_negotiating {
            return Ok(Vec::new());
        }
        self.cap_negotiating = false;
        Ok(vec![Action::Send("CAP END".to_string())])
    }

    fn authenticate(
        &mut self,
        config: &IrcConfig,
        secrets: &mut dyn Secrets,
    ) -> Result<Vec<Action>, Disconnect> {
        match self.sasl {
            Sasl::Authenticating(SaslMechanism::External) => {
                Ok(vec![Action::Send("AUTHENTICATE +".to_string())])
            }
            Sasl::Authenticating(SaslMechanism::Plain) => {
                let password = credential(secrets, SASL_PASSWORD)?.ok_or_else(|| {
                    Disconnect::fatal("sasl_mechanism = \"plain\" needs the sasl_password secret")
                })?;
                Ok(sasl_plain_lines(config.sasl_account(), &password)
                    .into_iter()
                    .map(Action::Send)
                    .collect())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn welcome(
        &mut self,
        config: &IrcConfig,
        secrets: &mut dyn Secrets,
        message: &IrcMessage,
    ) -> Result<Vec<Action>, Disconnect> {
        if matches!(self.sasl, Sasl::Wanted(_) | Sasl::Authenticating(_)) {
            return Err(Disconnect::fatal(
                "the server completed registration without SASL authentication",
            ));
        }
        if self.want_account_tag && !self.account_tag {
            return Err(Disconnect::fatal(
                "the server completed registration without the account-tag capability",
            ));
        }
        self.registered = true;
        self.cap_negotiating = false;
        if is_nick(message.param(0)) {
            self.nick = message.param(0).to_string();
        }
        let mut actions = vec![Action::Registered];
        if let Some(password) = credential(secrets, NICKSERV_PASSWORD)? {
            actions.push(Action::Send(format!(
                "PRIVMSG NickServ :IDENTIFY {password}"
            )));
        }
        actions.extend(join_lines(&config.channels).into_iter().map(Action::Send));
        Ok(actions)
    }

    fn inbound(&self, config: &IrcConfig, message: &IrcMessage) -> Option<Inbound> {
        let target = message.params.first()?;
        let nick = message.nick()?;
        if nick.eq_ignore_ascii_case(&self.nick)
            || nick.eq_ignore_ascii_case("NickServ")
            || nick.eq_ignore_ascii_case("ChanServ")
        {
            return None;
        }
        let text = match ctcp(message.param(1)) {
            Ctcp::None(text) => strip_formatting(text),
            Ctcp::Action(action) => format!("* {nick} {}", strip_formatting(action)),
            Ctcp::Other => return None,
        };
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let in_channel = is_channel_target(target);
        if config.mention_only && in_channel && !is_mentioned(&self.nick, text) {
            return None;
        }
        let sender = match config.sender_identity {
            SenderIdentity::Nick => nick.to_ascii_lowercase(),
            SenderIdentity::Account => match message.tag("account") {
                Some(account) if !account.is_empty() && account != "*" => {
                    account.to_ascii_lowercase()
                }
                _ => return None,
            },
        };
        let (reply_target, content) = if in_channel {
            (target.clone(), format!("{IRC_STYLE_PREFIX}<{nick}> {text}"))
        } else {
            (nick.to_string(), format!("{IRC_STYLE_PREFIX}{text}"))
        };
        Some(Inbound {
            sender,
            reply_target,
            content,
        })
    }

    /// Liveness checks, run on every poll.
    pub fn tick(&mut self, now_ms: u64) -> Option<Action> {
        if !self.registered && now_ms.saturating_sub(self.connected_ms) > REGISTRATION_TIMEOUT_MS {
            return Some(Action::Disconnect(Disconnect::transient(
                "registration did not complete in time",
            )));
        }
        match self.ping_sent_ms {
            Some(sent) if now_ms.saturating_sub(sent) > PING_TIMEOUT_MS => Some(
                Action::Disconnect(Disconnect::transient("the server stopped answering PING")),
            ),
            None if now_ms.saturating_sub(self.last_rx_ms) > IDLE_BEFORE_PING_MS => {
                self.ping_sent_ms = Some(now_ms);
                Some(Action::Send(format!("PING :zeroclaw-{now_ms}")))
            }
            _ => None,
        }
    }
}

fn trailing_if_needed(value: &str) -> String {
    if value.contains(' ') || value.starts_with(':') {
        format!(":{value}")
    } else {
        value.to_string()
    }
}

fn truncate(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// `JOIN` lines with as many comma-joined channels as fit in one line.
pub fn join_lines(channels: &[String]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for channel in channels.iter().map(|channel| channel.trim()) {
        if channel.is_empty() {
            continue;
        }
        if !current.is_empty()
            && "JOIN ".len() + current.len() + 1 + channel.len() + 2 > IRC_LINE_BYTES
        {
            lines.push(format!("JOIN {current}"));
            current.clear();
        }
        if !current.is_empty() {
            current.push(',');
        }
        current.push_str(channel);
    }
    if !current.is_empty() {
        lines.push(format!("JOIN {current}"));
    }
    lines
}

fn sasl_plain_lines(account: &str, password: &str) -> Vec<String> {
    let encoded = base64(format!("\0{account}\0{password}").as_bytes());
    let mut lines: Vec<String> = encoded
        .as_bytes()
        .chunks(SASL_CHUNK)
        .map(|chunk| format!("AUTHENTICATE {}", String::from_utf8_lossy(chunk)))
        .collect();
    if encoded.len().is_multiple_of(SASL_CHUNK) {
        lines.push("AUTHENTICATE +".to_string());
    }
    lines
}

pub fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let triple = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        let sextet = |shift: u32| char::from(ALPHABET[((triple >> shift) & 0x3f) as usize]);
        output.push(sextet(18));
        output.push(sextet(12));
        output.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        output.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    output
}

enum Ctcp<'a> {
    None(&'a str),
    Action(&'a str),
    Other,
}

fn ctcp(text: &str) -> Ctcp<'_> {
    let Some(body) = text.strip_prefix('\u{1}') else {
        return Ctcp::None(text);
    };
    let body = body.strip_suffix('\u{1}').unwrap_or(body);
    match body.strip_prefix("ACTION") {
        Some(rest) if rest.is_empty() || rest.starts_with(' ') => Ctcp::Action(rest.trim_start()),
        _ => Ctcp::Other,
    }
}

/// Remove mIRC formatting: bold, italics, underline, strikethrough,
/// monospace, reverse, reset, and colour codes with their arguments.
pub fn strip_formatting(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\u{2}' | '\u{1d}' | '\u{1f}' | '\u{1e}' | '\u{11}' | '\u{16}' | '\u{f}' => {}
            '\u{3}' => {
                skip_digits(&mut characters, |c| c.is_ascii_digit(), 2);
            }
            '\u{4}' => {
                skip_digits(&mut characters, |c| c.is_ascii_hexdigit(), 6);
            }
            other => output.push(other),
        }
    }
    output
}

/// Skip a `fg[,bg]` colour argument of up to `width` characters each.
fn skip_digits(
    characters: &mut std::iter::Peekable<std::str::Chars<'_>>,
    accept: fn(&char) -> bool,
    width: usize,
) {
    let mut taken = 0;
    while taken < width && characters.peek().is_some_and(accept) {
        characters.next();
        taken += 1;
    }
    if taken == 0 {
        return;
    }
    let mut lookahead = characters.clone();
    if lookahead.next() == Some(',') && lookahead.peek().is_some_and(accept) {
        characters.next();
        let mut taken = 0;
        while taken < width && characters.peek().is_some_and(accept) {
            characters.next();
            taken += 1;
        }
    }
}

fn is_nick_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

/// Whether `text` addresses `nick` as a whole word, ignoring ASCII case.
pub fn is_mentioned(nick: &str, text: &str) -> bool {
    let nick = nick.to_ascii_lowercase();
    if nick.is_empty() {
        return false;
    }
    let text = text.to_ascii_lowercase();
    text.match_indices(&nick).any(|(start, matched)| {
        let before = text[..start].chars().next_back();
        let after = text[start + matched.len()..].chars().next();
        before.is_none_or(|character| !is_nick_char(character))
            && after.is_none_or(|character| !is_nick_char(character))
    })
}

// ── outbound ────────────────────────────────────────────────────────────────

/// `PRIVMSG` lines for one reply, each short enough to survive the server
/// relaying it with our prefix. CTCP delimiters and NUL are removed so a reply
/// can never smuggle a CTCP request.
pub fn format_privmsg(own_nick: &str, target: &str, content: &str) -> Result<Vec<String>, String> {
    let target = target.trim();
    if !is_target(target) {
        return Err("irc: recipient is not a valid IRC target".into());
    }
    let overhead =
        RELAY_PREFIX_RESERVE + own_nick.len() + "PRIVMSG ".len() + target.len() + " :\r\n".len();
    let max_payload = IRC_LINE_BYTES
        .checked_sub(overhead)
        .filter(|max| *max >= 32)
        .ok_or_else(|| "irc: recipient is too long for an IRC line".to_string())?;
    let content: String = content
        .chars()
        .filter(|character| !matches!(character, '\0' | '\u{1}'))
        .collect();
    let lines: Vec<String> = split_message(&content, max_payload)
        .into_iter()
        .map(|chunk| format!("PRIVMSG {target} :{chunk}"))
        .collect();
    if lines.is_empty() {
        return Err("irc: the message is empty".into());
    }
    Ok(lines)
}

/// Split on newlines, drop blank lines, and wrap long lines at UTF-8
/// boundaries, preferring the last space in the second half of the chunk.
pub fn split_message(message: &str, max_bytes: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    if max_bytes == 0 {
        return chunks;
    }
    for line in message.split('\n') {
        let mut remaining = line.trim_end_matches('\r').trim_end();
        while !remaining.is_empty() {
            if remaining.len() <= max_bytes {
                chunks.push(remaining.to_string());
                break;
            }
            let mut split = max_bytes;
            while !remaining.is_char_boundary(split) {
                split -= 1;
            }
            if split == 0 {
                split = remaining
                    .char_indices()
                    .nth(1)
                    .map_or(remaining.len(), |(index, _)| index);
            } else if let Some(space) = remaining[..split]
                .rfind(' ')
                .filter(|space| *space >= split / 2)
            {
                split = space;
            }
            chunks.push(remaining[..split].trim_end().to_string());
            remaining = remaining[split..].trim_start();
        }
    }
    chunks
}

/// Paced outbound chat. Protocol replies bypass it; chat lines wait their turn.
#[derive(Debug, Default)]
pub struct Outbox {
    lines: VecDeque<String>,
    /// Time up to which the send allowance is spent.
    spent_until_ms: u64,
}

impl Outbox {
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Queue every line of one reply, or none if they do not all fit.
    pub fn enqueue(&mut self, lines: Vec<String>) -> Result<(), String> {
        if self.lines.len() + lines.len() > MAX_OUTBOUND_LINES {
            return Err(format!(
                "irc: {} lines are already waiting to be sent; refusing {} more",
                self.lines.len(),
                lines.len()
            ));
        }
        self.lines.extend(lines);
        Ok(())
    }

    /// Lines the pace allows at `now_ms`, removed from the queue.
    pub fn take_due(&mut self, now_ms: u64) -> Vec<String> {
        let window = PACE_INTERVAL_MS * PACE_BURST;
        let mut due = Vec::new();
        while !self.lines.is_empty() {
            let base = self.spent_until_ms.max(now_ms);
            if base - now_ms >= window {
                break;
            }
            self.spent_until_ms = base + PACE_INTERVAL_MS;
            due.extend(self.lines.pop_front());
        }
        due
    }

    /// Put lines that could not be written back at the front, in order.
    pub fn requeue(&mut self, lines: Vec<String>) {
        for line in lines.into_iter().rev() {
            self.lines.push_front(line);
        }
    }

    /// Drop everything queued, returning how many lines were lost.
    pub fn clear(&mut self) -> usize {
        let dropped = self.lines.len();
        self.lines.clear();
        dropped
    }
}

// ── reconnect policy ────────────────────────────────────────────────────────

const BACKOFF_BASE_MS: u64 = 2_000;
const BACKOFF_MAX_MS: u64 = 300_000;
/// After a refused destination or TLS profile: an operator must grant it.
const REFUSED_DELAY_MS: u64 = 60_000;
/// After rejected credentials: hammering a network with bad credentials gets
/// the host banned.
const PARK_DELAY_MS: u64 = 900_000;

/// When the next connection attempt may start.
#[derive(Debug, Default)]
pub struct Backoff {
    failures: u32,
    next_attempt_ms: u64,
}

impl Backoff {
    pub fn ready(&self, now_ms: u64) -> bool {
        now_ms >= self.next_attempt_ms
    }

    /// Record a failed or lost connection; `jitter` is any random value.
    /// Returns the delay chosen.
    pub fn failed(&mut self, now_ms: u64, retry: Retry, jitter: u64) -> u64 {
        let delay = match retry {
            Retry::Backoff => {
                let exponential = BACKOFF_BASE_MS
                    .saturating_mul(1_u64 << self.failures.min(16))
                    .min(BACKOFF_MAX_MS);
                // Up to 25% jitter so many clients do not reconnect in step.
                exponential + jitter % (exponential / 4 + 1)
            }
            Retry::Refused => REFUSED_DELAY_MS,
            Retry::Park => PARK_DELAY_MS,
        };
        self.failures = self.failures.saturating_add(1);
        self.next_attempt_ms = now_ms.saturating_add(delay);
        delay
    }

    /// Registration completed: the next loss starts from the base delay.
    pub fn succeeded(&mut self) {
        self.failures = 0;
    }
}
