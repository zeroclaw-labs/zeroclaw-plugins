//! Pure QQ Official Bot protocol logic for OAuth, gateway frames, and text send.

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use serde_json::{json, Value};

pub const CHANNEL: &str = "qq";
pub const API_BASE: &str = "https://api.sgroup.qq.com";
pub const AUTH_URL: &str = "https://bots.qq.com/app/getAppAccessToken";
pub const DEFAULT_HEARTBEAT_MS: u64 = 41_250;
pub const INTENTS: u64 = (1 << 25) | (1 << 30);

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct QQConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub app_secret: String,
}

fn default_enabled() -> bool {
    true
}

impl QQConfig {
    pub fn from_json(input: &str) -> Self {
        serde_json::from_str(input).unwrap_or_default()
    }

    pub fn is_configured(&self) -> bool {
        self.enabled && !self.app_id.trim().is_empty() && !self.app_secret.trim().is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessToken {
    pub value: String,
    pub expires_in: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayEvent {
    Hello { heartbeat_interval_ms: u64 },
    HeartbeatRequest,
    HeartbeatAck,
    Reconnect,
    InvalidSession,
    Ready { session_id: Option<String> },
    Message(Inbound),
    Ignore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFrame {
    pub sequence: Option<i64>,
    pub event: GatewayEvent,
}

pub fn auth_body(cfg: &QQConfig) -> Value {
    json!({
        "appId": cfg.app_id,
        "clientSecret": cfg.app_secret,
    })
}

pub fn parse_access_token(value: &Value) -> Option<AccessToken> {
    let token = value
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())?;
    let expires_in = value
        .get("expires_in")
        .and_then(|expiry| {
            expiry
                .as_u64()
                .or_else(|| expiry.as_str().and_then(|raw| raw.parse().ok()))
        })
        .unwrap_or(7_200);
    Some(AccessToken {
        value: token.to_string(),
        expires_in,
    })
}

pub fn gateway_url(value: &Value) -> Option<String> {
    value
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| url.starts_with("wss://") || url.starts_with("ws://"))
        .map(str::to_string)
}

pub fn identify_frame(token: &str) -> String {
    json!({
        "op": 2,
        "d": {
            "token": format!("QQBot {token}"),
            "intents": INTENTS,
            "properties": {
                "os": "linux",
                "browser": "zeroclaw",
                "device": "zeroclaw",
            }
        }
    })
    .to_string()
}

pub fn resume_frame(token: &str, session_id: &str, sequence: i64) -> String {
    json!({
        "op": 6,
        "d": {
            "token": format!("QQBot {token}"),
            "session_id": session_id,
            "seq": sequence,
        }
    })
    .to_string()
}

pub fn heartbeat_frame(sequence: Option<i64>) -> String {
    json!({ "op": 1, "d": sequence }).to_string()
}

fn message_from_dispatch(event_type: &str, data: &Value) -> Option<Inbound> {
    let id = data
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())?;
    let content = data
        .get("content")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|content| !content.is_empty())?;
    match event_type {
        "C2C_MESSAGE_CREATE" => {
            let author = data.get("author")?;
            let sender = author
                .get("user_openid")
                .and_then(Value::as_str)
                .or_else(|| author.get("id").and_then(Value::as_str))
                .filter(|sender| !sender.is_empty())?;
            Some(Inbound {
                id: id.to_string(),
                sender: sender.to_string(),
                reply_target: format!("user:{sender}"),
                content: content.to_string(),
            })
        }
        "GROUP_AT_MESSAGE_CREATE" => {
            let sender = data
                .pointer("/author/member_openid")
                .and_then(Value::as_str)
                .or_else(|| data.pointer("/author/id").and_then(Value::as_str))
                .filter(|sender| !sender.is_empty())?;
            let group = data
                .get("group_openid")
                .and_then(Value::as_str)
                .filter(|group| !group.is_empty())?;
            Some(Inbound {
                id: id.to_string(),
                sender: sender.to_string(),
                reply_target: format!("group:{group}"),
                content: content.to_string(),
            })
        }
        _ => None,
    }
}

pub fn decode_gateway_frame(input: &str) -> DecodedFrame {
    let Ok(value) = serde_json::from_str::<Value>(input) else {
        return DecodedFrame {
            sequence: None,
            event: GatewayEvent::Ignore,
        };
    };
    let sequence = value.get("s").and_then(Value::as_i64);
    let op = value.get("op").and_then(Value::as_u64).unwrap_or(u64::MAX);
    let event = match op {
        0 => {
            let event_type = value.get("t").and_then(Value::as_str).unwrap_or("");
            let data = value.get("d").unwrap_or(&Value::Null);
            if matches!(event_type, "READY" | "RESUMED") {
                GatewayEvent::Ready {
                    session_id: data
                        .get("session_id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.is_empty())
                        .map(str::to_string),
                }
            } else {
                message_from_dispatch(event_type, data)
                    .map(GatewayEvent::Message)
                    .unwrap_or(GatewayEvent::Ignore)
            }
        }
        1 => GatewayEvent::HeartbeatRequest,
        7 => GatewayEvent::Reconnect,
        9 => GatewayEvent::InvalidSession,
        10 => GatewayEvent::Hello {
            heartbeat_interval_ms: value
                .pointer("/d/heartbeat_interval")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_HEARTBEAT_MS),
        },
        11 => GatewayEvent::HeartbeatAck,
        _ => GatewayEvent::Ignore,
    };
    DecodedFrame { sequence, event }
}

pub fn resolve_recipient(recipient: &str) -> Option<(&'static str, String)> {
    if let Some(group) = recipient.strip_prefix("group:") {
        let id = group.trim();
        return (!id.is_empty()).then(|| ("groups", id.to_string()));
    }
    let raw = recipient.strip_prefix("user:").unwrap_or(recipient).trim();
    let id: String = raw
        .chars()
        .filter(|character| character.is_alphanumeric() || *character == '_')
        .collect();
    (!id.is_empty()).then_some(("users", id))
}

pub fn send_url(recipient: &str) -> Option<String> {
    let (scope, id) = resolve_recipient(recipient)?;
    Some(format!(
        "{API_BASE}/v2/{scope}/{}/messages",
        utf8_percent_encode(&id, NON_ALPHANUMERIC)
    ))
}

pub fn build_send_body(content: &str, msg_seq: u32) -> Value {
    json!({
        "markdown": { "content": content },
        "msg_type": 2,
        "msg_seq": msg_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_and_gateway_responses_parse() {
        let cfg = QQConfig::from_json(r#"{"enabled":true,"app_id":"app","app_secret":"sec"}"#);
        assert!(cfg.is_configured());
        assert_eq!(auth_body(&cfg)["appId"], "app");
        let token = parse_access_token(&json!({"access_token":"tok","expires_in":"3600"})).unwrap();
        assert_eq!(token.expires_in, 3600);
        assert_eq!(
            gateway_url(&json!({"url":"wss://gateway.qq/ws"})).as_deref(),
            Some("wss://gateway.qq/ws")
        );
        assert!(gateway_url(&json!({"url":"https://wrong"})).is_none());
    }

    #[test]
    fn gateway_control_frames_decode() {
        assert_eq!(
            decode_gateway_frame(r#"{"op":10,"d":{"heartbeat_interval":30000}}"#).event,
            GatewayEvent::Hello {
                heartbeat_interval_ms: 30000
            }
        );
        assert_eq!(
            decode_gateway_frame(r#"{"op":1}"#).event,
            GatewayEvent::HeartbeatRequest
        );
        assert_eq!(
            decode_gateway_frame(r#"{"op":11}"#).event,
            GatewayEvent::HeartbeatAck
        );
        assert_eq!(
            decode_gateway_frame(r#"{"op":7}"#).event,
            GatewayEvent::Reconnect
        );
        assert_eq!(
            decode_gateway_frame(r#"{"op":9}"#).event,
            GatewayEvent::InvalidSession
        );
    }

    #[test]
    fn identify_resume_and_heartbeat_frames_match_gateway_contract() {
        let identify: Value = serde_json::from_str(&identify_frame("tok")).unwrap();
        assert_eq!(identify["op"], 2);
        assert_eq!(identify["d"]["token"], "QQBot tok");
        assert_eq!(identify["d"]["intents"], INTENTS);
        let resume: Value = serde_json::from_str(&resume_frame("tok", "sid", 42)).unwrap();
        assert_eq!(resume["op"], 6);
        assert_eq!(resume["d"]["seq"], 42);
        let heartbeat: Value = serde_json::from_str(&heartbeat_frame(Some(42))).unwrap();
        assert_eq!(heartbeat["d"], 42);
    }

    #[test]
    fn c2c_and_group_text_events_map_to_reply_targets() {
        let c2c = decode_gateway_frame(
            &json!({
                "op":0,"s":5,"t":"C2C_MESSAGE_CREATE","d":{
                    "id":"m1","content":" hello ","author":{"id":"legacy","user_openid":"user1"}
                }
            })
            .to_string(),
        );
        assert_eq!(c2c.sequence, Some(5));
        let GatewayEvent::Message(message) = c2c.event else {
            panic!("message")
        };
        assert_eq!(message.sender, "user1");
        assert_eq!(message.reply_target, "user:user1");
        assert_eq!(message.content, "hello");

        let group = decode_gateway_frame(&json!({
            "op":0,"t":"GROUP_AT_MESSAGE_CREATE","d":{
                "id":"m2","content":"group","group_openid":"g1","author":{"member_openid":"member1"}
            }
        }).to_string());
        let GatewayEvent::Message(message) = group.event else {
            panic!("message")
        };
        assert_eq!(message.sender, "member1");
        assert_eq!(message.reply_target, "group:g1");
    }

    #[test]
    fn recipient_and_send_body_match_v2_api() {
        assert_eq!(
            send_url("group:g1").as_deref(),
            Some("https://api.sgroup.qq.com/v2/groups/g1/messages")
        );
        assert_eq!(
            send_url("user:u_1").as_deref(),
            Some("https://api.sgroup.qq.com/v2/users/u%5F1/messages")
        );
        assert!(send_url("user:!!!").is_none());
        let body = build_send_body("answer", 7);
        assert_eq!(body["msg_type"], 2);
        assert_eq!(body["markdown"]["content"], "answer");
        assert_eq!(body["msg_seq"], 7);
    }
}
