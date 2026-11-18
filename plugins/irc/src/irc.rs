//! Pure IRC protocol logic for registration, SASL, framing, and messages.

use serde::Deserialize;

pub const CHANNEL: &str = "irc";
pub const DEFAULT_PORT: u16 = 6697;
pub const MAX_RECEIVE_BUFFER: usize = 64 * 1024;
const IRC_LINE_BYTES: usize = 512;
const SENDER_PREFIX_RESERVE: usize = 64;

pub const IRC_STYLE_PREFIX: &str = "\
[context: you are responding over IRC. Plain text only. No markdown, tables, \
or XML/HTML tags. Never use triple backtick code fences. Be terse and use \
short lines.]\n";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct IrcConfig {
    #[serde(default)]
    pub enabled: bool,
    pub server: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub nickname: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub server_password: Option<String>,
    #[serde(default)]
    pub nickserv_password: Option<String>,
    #[serde(default)]
    pub sasl_password: Option<String>,
    #[serde(default)]
    pub verify_tls: Option<bool>,
    #[serde(default)]
    pub mention_only: bool,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl IrcConfig {
    pub fn from_json(input: &str) -> Result<Self, String> {
        let config: Self =
            serde_json::from_str(input).map_err(|error| format!("irc config: {error}"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !is_host(&self.server) {
            return Err("irc: server must be a non-empty hostname without whitespace".into());
        }
        if self.port == 0 {
            return Err("irc: port must be greater than zero".into());
        }
        if !is_atom(&self.nickname) {
            return Err("irc: nickname contains an invalid IRC command character".into());
        }
        if !is_atom(self.username()) {
            return Err("irc: username contains an invalid IRC command character".into());
        }
        if self.verify_tls == Some(false) {
            return Err(
                "irc: verify_tls=false is unsupported by the host socket capability".into(),
            );
        }
        for channel in &self.channels {
            validate_target(channel)?;
        }
        for secret in [
            self.server_password.as_deref(),
            self.nickserv_password.as_deref(),
            self.sasl_password.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if secret.contains(['\r', '\n']) {
                return Err("irc: credentials must not contain CR or LF".into());
            }
        }
        Ok(())
    }

    pub fn username(&self) -> &str {
        self.username
            .as_deref()
            .filter(|username| !username.trim().is_empty())
            .unwrap_or(&self.nickname)
    }
}

fn is_host(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && !value.chars().any(char::is_whitespace) && !value.contains(['\r', '\n'])
}

fn is_atom(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == ':'
        })
}

pub fn validate_target(target: &str) -> Result<&str, String> {
    let target = target.trim();
    if target.is_empty()
        || target.len() > 200
        || target.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, ',' | ':')
        })
    {
        return Err("irc: recipient is not a valid IRC target".into());
    }
    Ok(target)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrcMessage {
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

impl IrcMessage {
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return None;
        }
        let (prefix, rest) = if let Some(stripped) = line.strip_prefix(':') {
            let space = stripped.find(' ')?;
            (Some(stripped[..space].to_string()), &stripped[space + 1..])
        } else {
            (None, line)
        };
        let (params_part, trailing) = if let Some(colon) = rest.find(" :") {
            (&rest[..colon], Some(&rest[colon + 2..]))
        } else {
            (rest, None)
        };
        let mut parts = params_part.split_whitespace();
        let command = parts.next()?.to_ascii_uppercase();
        let mut params: Vec<String> = parts.map(str::to_string).collect();
        if let Some(trailing) = trailing {
            params.push(trailing.to_string());
        }
        Some(Self {
            prefix,
            command,
            params,
        })
    }

    pub fn nick(&self) -> Option<&str> {
        self.prefix.as_deref().and_then(|prefix| {
            let end = prefix.find('!').unwrap_or(prefix.len());
            (!prefix[..end].is_empty()).then_some(&prefix[..end])
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    pub sender: String,
    pub reply_target: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionAction {
    Send(String),
    Message(Inbound),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrcSession {
    current_nick: String,
    registered: bool,
    sasl_pending: bool,
}

impl IrcSession {
    pub fn new(config: &IrcConfig) -> Self {
        Self {
            current_nick: config.nickname.clone(),
            registered: false,
            sasl_pending: config.sasl_password.is_some(),
        }
    }

    pub fn current_nick(&self) -> &str {
        &self.current_nick
    }

    pub fn is_registered(&self) -> bool {
        self.registered
    }

    pub fn registration_commands(&self, config: &IrcConfig) -> Vec<String> {
        let mut commands = Vec::new();
        if let Some(password) = config
            .server_password
            .as_deref()
            .filter(|password| !password.is_empty())
        {
            commands.push(format!("PASS {password}"));
        }
        if self.sasl_pending {
            commands.push("CAP REQ :sasl".to_string());
        }
        commands.push(format!("NICK {}", self.current_nick));
        commands.push(format!("USER {} 0 * :ZeroClaw", config.username()));
        commands
    }

    pub fn handle_line(
        &mut self,
        config: &IrcConfig,
        line: &str,
    ) -> Result<Vec<SessionAction>, String> {
        let Some(message) = IrcMessage::parse(line) else {
            return Ok(Vec::new());
        };
        let send = |line: String| vec![SessionAction::Send(line)];
        match message.command.as_str() {
            "PING" => {
                let token = message.params.first().map_or("", String::as_str);
                Ok(send(format!("PONG :{token}")))
            }
            "CAP"
                if self.sasl_pending
                    && message.params.iter().any(|param| param.contains("sasl")) =>
            {
                if message.params.iter().any(|param| param == "ACK") {
                    Ok(send("AUTHENTICATE PLAIN".to_string()))
                } else if message.params.iter().any(|param| param == "NAK") {
                    self.sasl_pending = false;
                    Ok(send("CAP END".to_string()))
                } else {
                    Ok(Vec::new())
                }
            }
            "AUTHENTICATE"
                if self.sasl_pending
                    && message.params.first().is_some_and(|param| param == "+") =>
            {
                let password = config
                    .sasl_password
                    .as_deref()
                    .ok_or_else(|| "irc: SASL requested without a password".to_string())?;
                Ok(sasl_authenticate_commands(&self.current_nick, password)
                    .into_iter()
                    .map(SessionAction::Send)
                    .collect())
            }
            "903" => {
                self.sasl_pending = false;
                Ok(send("CAP END".to_string()))
            }
            "904" | "905" | "906" | "907" => {
                self.sasl_pending = false;
                Ok(send("CAP END".to_string()))
            }
            "001" => {
                self.registered = true;
                if let Some(nick) = message.params.first().filter(|nick| is_atom(nick)) {
                    self.current_nick.clone_from(nick);
                }
                let mut actions = Vec::new();
                if let Some(password) = config
                    .nickserv_password
                    .as_deref()
                    .filter(|password| !password.is_empty())
                {
                    actions.push(SessionAction::Send(format!(
                        "PRIVMSG NickServ :IDENTIFY {password}"
                    )));
                }
                actions.extend(
                    config
                        .channels
                        .iter()
                        .map(|channel| SessionAction::Send(format!("JOIN {}", channel.trim()))),
                );
                Ok(actions)
            }
            "433" => {
                self.current_nick.push('_');
                Ok(send(format!("NICK {}", self.current_nick)))
            }
            "464" => Err("irc: server password mismatch".into()),
            "PRIVMSG" if self.registered => {
                Ok(self.message_action(config, &message).into_iter().collect())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn message_action(&self, config: &IrcConfig, message: &IrcMessage) -> Option<SessionAction> {
        let target = message.params.first()?;
        let text = message.params.get(1)?.trim();
        let sender = message.nick()?;
        if text.is_empty()
            || sender.eq_ignore_ascii_case("NickServ")
            || sender.eq_ignore_ascii_case("ChanServ")
        {
            return None;
        }
        let is_channel = target.starts_with('#') || target.starts_with('&');
        if config.mention_only && is_channel && !is_mentioned(&self.current_nick, text) {
            return None;
        }
        let reply_target = if is_channel { target } else { sender };
        let content = if is_channel {
            format!("{IRC_STYLE_PREFIX}<{sender}> {text}")
        } else {
            format!("{IRC_STYLE_PREFIX}{text}")
        };
        Some(SessionAction::Message(Inbound {
            sender: sender.to_string(),
            reply_target: reply_target.to_string(),
            content,
        }))
    }
}

fn is_irc_nick_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

pub fn is_mentioned(nick: &str, text: &str) -> bool {
    let nick = nick.to_ascii_lowercase();
    if nick.is_empty() {
        return false;
    }
    let text = text.to_ascii_lowercase();
    text.match_indices(&nick).any(|(start, matched)| {
        let before = (start != 0)
            .then(|| text[..start].chars().next_back())
            .flatten();
        let after = text[start + matched.len()..].chars().next();
        before.is_none_or(|character| !is_irc_nick_char(character))
            && after.is_none_or(|character| !is_irc_nick_char(character))
    })
}

pub fn drain_lines(buffer: &mut Vec<u8>, chunk: &[u8]) -> Result<Vec<String>, String> {
    if buffer.len().saturating_add(chunk.len()) > MAX_RECEIVE_BUFFER {
        buffer.clear();
        return Err("irc: receive buffer exceeded 64 KiB without a complete line".into());
    }
    buffer.extend_from_slice(chunk);
    let mut lines = Vec::new();
    while let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
        let mut raw: Vec<u8> = buffer.drain(..=newline).collect();
        while matches!(raw.last(), Some(b'\r' | b'\n')) {
            raw.pop();
        }
        lines.push(String::from_utf8_lossy(&raw).into_owned());
    }
    Ok(lines)
}

pub fn format_privmsg(target: &str, content: &str) -> Result<Vec<String>, String> {
    let target = validate_target(target)?;
    let overhead = SENDER_PREFIX_RESERVE
        .saturating_add("PRIVMSG ".len())
        .saturating_add(target.len())
        .saturating_add(" :\r\n".len());
    let max_payload = IRC_LINE_BYTES
        .checked_sub(overhead)
        .ok_or_else(|| "irc: recipient is too long for an IRC line".to_string())?;
    Ok(split_message(content, max_payload)
        .into_iter()
        .map(|chunk| format!("PRIVMSG {target} :{chunk}"))
        .collect())
}

pub fn split_message(message: &str, max_bytes: usize) -> Vec<String> {
    if max_bytes == 0 {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    for line in message.split('\n') {
        let mut remaining = line.trim_end_matches('\r');
        if remaining.is_empty() {
            continue;
        }
        while remaining.len() > max_bytes {
            let mut split = max_bytes;
            while split > 0 && !remaining.is_char_boundary(split) {
                split -= 1;
            }
            if split == 0 {
                split = remaining
                    .char_indices()
                    .nth(1)
                    .map_or(remaining.len(), |(index, _)| index);
            }
            chunks.push(remaining[..split].to_string());
            remaining = &remaining[split..];
        }
        if !remaining.is_empty() {
            chunks.push(remaining.to_string());
        }
    }
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    chunks
}

pub fn encode_sasl_plain(nick: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("\0{nick}\0{password}");
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.as_bytes().chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (first << 16) | (second << 8) | third;
        output.push(char::from(ALPHABET[((triple >> 18) & 0x3f) as usize]));
        output.push(char::from(ALPHABET[((triple >> 12) & 0x3f) as usize]));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[((triple >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[(triple & 0x3f) as usize])
        } else {
            '='
        });
    }
    output
}

fn sasl_authenticate_commands(nick: &str, password: &str) -> Vec<String> {
    let encoded = encode_sasl_plain(nick, password);
    let mut commands: Vec<String> = encoded
        .as_bytes()
        .chunks(400)
        .map(|chunk| format!("AUTHENTICATE {}", String::from_utf8_lossy(chunk)))
        .collect();
    if encoded.len().is_multiple_of(400) {
        commands.push("AUTHENTICATE +".to_string());
    }
    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> IrcConfig {
        IrcConfig::from_json(
            r##"{"server":"irc.example","nickname":"bot","channels":["#room"],"sasl_password":"secret"}"##,
        )
        .unwrap()
    }

    #[test]
    fn parses_partial_lines_and_privmsg() {
        let mut buffer = Vec::new();
        assert!(drain_lines(&mut buffer, b":a!u@h PRIVMSG #room :hel")
            .unwrap()
            .is_empty());
        let lines = drain_lines(&mut buffer, b"lo\r\nPING :server\r\n").unwrap();
        assert_eq!(lines.len(), 2);
        let message = IrcMessage::parse(&lines[0]).unwrap();
        assert_eq!(message.nick(), Some("a"));
        assert_eq!(message.params, ["#room", "hello"]);
    }

    #[test]
    fn registration_sasl_and_welcome_flow() {
        let config = config();
        let mut session = IrcSession::new(&config);
        assert!(session
            .registration_commands(&config)
            .contains(&"CAP REQ :sasl".to_string()));
        assert_eq!(
            session.handle_line(&config, ":s CAP * ACK :sasl").unwrap(),
            [SessionAction::Send("AUTHENTICATE PLAIN".into())]
        );
        let auth = session.handle_line(&config, "AUTHENTICATE +").unwrap();
        assert_eq!(
            auth,
            [SessionAction::Send("AUTHENTICATE AGJvdABzZWNyZXQ=".into())]
        );
        let welcome = session.handle_line(&config, ":s 001 bot :welcome").unwrap();
        assert!(session.is_registered());
        assert_eq!(welcome, [SessionAction::Send("JOIN #room".into())]);
    }

    #[test]
    fn ping_and_messages_map_to_actions() {
        let config = config();
        let mut session = IrcSession::new(&config);
        session.handle_line(&config, ":s 001 bot :welcome").unwrap();
        assert_eq!(
            session.handle_line(&config, "PING :token").unwrap(),
            [SessionAction::Send("PONG :token".into())]
        );
        let actions = session
            .handle_line(&config, ":alice!u@h PRIVMSG #room :hello")
            .unwrap();
        let SessionAction::Message(message) = &actions[0] else {
            panic!("expected message")
        };
        assert_eq!(message.sender, "alice");
        assert_eq!(message.reply_target, "#room");
        assert!(message.content.ends_with("<alice> hello"));
    }

    #[test]
    fn mention_only_uses_nick_boundaries() {
        let mut config = config();
        config.mention_only = true;
        let mut session = IrcSession::new(&config);
        session.handle_line(&config, ":s 001 bot :welcome").unwrap();
        assert!(session
            .handle_line(&config, ":a!u@h PRIVMSG #room :robotic")
            .unwrap()
            .is_empty());
        assert_eq!(
            session
                .handle_line(&config, ":a!u@h PRIVMSG #room :bot: hi")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn text_split_is_utf8_safe_and_blocks_target_injection() {
        assert_eq!(split_message("ééé", 3), ["é", "é", "é"]);
        assert_eq!(
            format_privmsg("#room", "one\ntwo").unwrap(),
            ["PRIVMSG #room :one", "PRIVMSG #room :two"]
        );
        assert!(format_privmsg("#room\r\nQUIT", "bad").is_err());
    }

    #[test]
    fn rejects_insecure_tls_override() {
        let error =
            IrcConfig::from_json(r#"{"server":"irc.example","nickname":"bot","verify_tls":false}"#)
                .unwrap_err();
        assert!(error.contains("verify_tls=false"));
    }
}
