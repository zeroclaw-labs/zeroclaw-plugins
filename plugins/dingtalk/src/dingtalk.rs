//! Pure DingTalk Stream Mode protocol logic. HTTP and WebSocket I/O stay in the
//! WASM component shim so frame handling is host-testable.

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use serde_json::{json, Value};

pub const CHANNEL: &str = "dingtalk";
pub const GATEWAY_OPEN_URL: &str = "https://api.dingtalk.com/v1.0/gateway/connections/open";
pub const BOT_CALLBACK_TOPIC: &str = "/v1.0/im/bot/messages/get";

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct DingTalkConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
}

fn default_enabled() -> bool {
    true
}

impl DingTalkConfig {
    pub fn from_json(input: &str) -> Self {
        serde_json::from_str(input).unwrap_or_default()
    }

    pub fn is_configured(&self) -> bool {
        self.enabled && !self.client_id.trim().is_empty() && !self.client_secret.trim().is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct GatewayResponse {
    pub endpoint: String,
    pub ticket: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    pub id: Option<String>,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameOutcome {
    pub response: Option<String>,
    pub inbound: Option<Inbound>,
    pub session_webhook: Option<SessionWebhook>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionWebhook {
    pub chat_id: String,
    pub sender_id: String,
    pub url: String,
}

pub fn registration_body(cfg: &DingTalkConfig) -> Value {
    json!({
        "clientId": cfg.client_id,
        "clientSecret": cfg.client_secret,
        "subscriptions": [{
            "type": "CALLBACK",
            "topic": BOT_CALLBACK_TOPIC,
        }],
    })
}

pub fn connection_url(gateway: &GatewayResponse) -> Option<String> {
    let endpoint = gateway.endpoint.trim();
    let ticket = gateway.ticket.trim();
    if endpoint.is_empty() || ticket.is_empty() {
        return None;
    }
    let separator = if endpoint.contains('?') { '&' } else { '?' };
    Some(format!(
        "{endpoint}{separator}ticket={}",
        utf8_percent_encode(ticket, NON_ALPHANUMERIC)
    ))
}

pub fn build_reply_body(content: &str, subject: Option<&str>) -> Value {
    json!({
        "msgtype": "markdown",
        "markdown": {
            "title": subject.filter(|title| !title.is_empty()).unwrap_or("ZeroClaw"),
            "text": content,
        }
    })
}

fn message_id(frame: &Value) -> Option<String> {
    frame
        .pointer("/headers/messageId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

fn response_frame(frame: &Value) -> String {
    json!({
        "code": 200,
        "headers": {
            "contentType": "application/json",
            "messageId": message_id(frame).unwrap_or_default(),
        },
        "message": "OK",
        "data": "",
    })
    .to_string()
}

fn stream_data(frame: &Value) -> Option<Value> {
    match frame.get("data") {
        Some(Value::String(raw)) => serde_json::from_str(raw).ok(),
        Some(Value::Object(_)) => frame.get("data").cloned(),
        _ => None,
    }
}

fn is_private_chat(data: &Value) -> bool {
    data.get("conversationType")
        .and_then(|value| {
            value
                .as_str()
                .map(|kind| kind == "1")
                .or_else(|| value.as_i64().map(|kind| kind == 1))
        })
        .unwrap_or(true)
}

fn chat_id(data: &Value, sender_id: &str) -> String {
    if is_private_chat(data) {
        sender_id.to_string()
    } else {
        data.get("conversationId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .unwrap_or(sender_id)
            .to_string()
    }
}

pub fn decode_frame(input: &str) -> FrameOutcome {
    let Ok(frame) = serde_json::from_str::<Value>(input) else {
        return FrameOutcome::default();
    };
    match frame.get("type").and_then(Value::as_str).unwrap_or("") {
        "SYSTEM" => FrameOutcome {
            response: Some(response_frame(&frame)),
            ..FrameOutcome::default()
        },
        "EVENT" | "CALLBACK" => {
            let mut outcome = FrameOutcome {
                response: Some(response_frame(&frame)),
                ..FrameOutcome::default()
            };
            let Some(data) = stream_data(&frame) else {
                return outcome;
            };
            let content = data
                .pointer("/text/content")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("");
            let sender_id = data
                .get("senderStaffId")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .unwrap_or("unknown");
            let target = chat_id(&data, sender_id);
            if let Some(url) = data
                .get("sessionWebhook")
                .and_then(Value::as_str)
                .filter(|url| !url.is_empty())
            {
                outcome.session_webhook = Some(SessionWebhook {
                    chat_id: target.clone(),
                    sender_id: sender_id.to_string(),
                    url: url.to_string(),
                });
            }
            if !content.is_empty() {
                outcome.inbound = Some(Inbound {
                    id: message_id(&frame),
                    sender: sender_id.to_string(),
                    reply_target: target,
                    content: content.to_string(),
                });
            }
            outcome
        }
        _ => FrameOutcome::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_and_registration_use_native_fields() {
        let cfg = DingTalkConfig::from_json(
            r#"{"enabled":true,"client_id":"app","client_secret":"secret","proxy_url":"http://ignored"}"#,
        );
        assert!(cfg.is_configured());
        let body = registration_body(&cfg);
        assert_eq!(body["clientId"], "app");
        assert_eq!(body["subscriptions"][0]["topic"], BOT_CALLBACK_TOPIC);
    }

    #[test]
    fn connection_url_encodes_ticket_and_preserves_query() {
        let gateway = GatewayResponse {
            endpoint: "wss://example/ws?x=1".into(),
            ticket: "a/b+c".into(),
        };
        assert_eq!(
            connection_url(&gateway).as_deref(),
            Some("wss://example/ws?x=1&ticket=a%2Fb%2Bc")
        );
    }

    #[test]
    fn system_frame_returns_pong() {
        let outcome = decode_frame(r#"{"type":"SYSTEM","headers":{"messageId":"m1"}}"#);
        let response: Value = serde_json::from_str(outcome.response.as_deref().unwrap()).unwrap();
        assert_eq!(response["code"], 200);
        assert_eq!(response["headers"]["messageId"], "m1");
        assert!(outcome.inbound.is_none());
    }

    #[test]
    fn callback_string_payload_maps_private_message_and_webhook() {
        let frame = json!({
            "type": "CALLBACK",
            "headers": { "messageId": "m2" },
            "data": json!({
                "conversationType": "1",
                "senderStaffId": "staff-1",
                "sessionWebhook": "https://oapi.dingtalk.com/robot/send?token=x",
                "text": { "content": " hello " }
            }).to_string()
        });
        let outcome = decode_frame(&frame.to_string());
        let inbound = outcome.inbound.unwrap();
        assert_eq!(inbound.id.as_deref(), Some("m2"));
        assert_eq!(inbound.sender, "staff-1");
        assert_eq!(inbound.reply_target, "staff-1");
        assert_eq!(inbound.content, "hello");
        let webhook = outcome.session_webhook.unwrap();
        assert_eq!(webhook.chat_id, "staff-1");
        assert_eq!(webhook.sender_id, "staff-1");
    }

    #[test]
    fn callback_object_payload_maps_group_chat() {
        let frame = json!({
            "type": "EVENT",
            "headers": { "messageId": "m3" },
            "data": {
                "conversationType": 2,
                "conversationId": "cid-group",
                "senderStaffId": "staff-2",
                "sessionWebhook": "https://example.invalid/session",
                "text": { "content": "group hello" }
            }
        });
        let outcome = decode_frame(&frame.to_string());
        assert_eq!(outcome.inbound.unwrap().reply_target, "cid-group");
        assert_eq!(outcome.session_webhook.unwrap().chat_id, "cid-group");
    }

    #[test]
    fn callback_acknowledges_empty_or_unsupported_messages() {
        let outcome = decode_frame(
            r#"{"type":"CALLBACK","headers":{"messageId":"m4"},"data":{"senderStaffId":"u"}}"#,
        );
        assert!(outcome.response.is_some());
        assert!(outcome.inbound.is_none());
    }

    #[test]
    fn reply_payload_defaults_title() {
        let body = build_reply_body("answer", None);
        assert_eq!(body["msgtype"], "markdown");
        assert_eq!(body["markdown"]["title"], "ZeroClaw");
        assert_eq!(body["markdown"]["text"], "answer");
    }
}
