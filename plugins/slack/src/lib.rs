//! Slack Events API channel. The plugin verifies the signing-secret HMAC and
//! replay window on each POST before answering a URL challenge or delivering
//! message events. Outbound text uses chat.postMessage.

pub mod slack;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::slack::{
        authenticate_webhook, build_send_body, chunk_text, decode_webhook, Inbound, SlackConfig,
        WebhookOutcome, CHANNEL, MAX_TEXT_CHARS,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    use zeroclaw::plugin::{config, secrets};

    fn public_config() -> Result<SlackConfig, String> {
        let public = config::get().map_err(|_| "slack: public configuration unavailable")?;
        serde_json::from_str(&public).map_err(|_| "slack: invalid public configuration".to_string())
    }

    fn optional_secret(key: &str) -> Result<Option<String>, String> {
        match secrets::get(key) {
            Ok(value) => Ok(Some(value)),
            Err(secrets::SecretError::NotFound) => Ok(None),
            Err(_) => Err(format!("slack: cannot read {key}")),
        }
    }

    fn send_config() -> Result<SlackConfig, String> {
        let mut cfg = public_config()?;
        cfg.bot_token = optional_secret("bot_token")?;
        Ok(cfg)
    }

    fn inbound_config() -> Result<SlackConfig, String> {
        let mut cfg = public_config()?;
        cfg.signing_secret = optional_secret("signing_secret")?;
        Ok(cfg)
    }

    const PLUGIN_NAME: &str = "slack";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    /// Current Unix time in seconds — the unit the signature replay-window check
    /// expects. `0` on a broken clock, which just makes every request read as
    /// stale (fail-closed).
    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Stamp a core [`Inbound`] with the WIT `inbound-message` fields.
    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: CHANNEL.to_string(),
            channel_alias: None,
            timestamp: inb.timestamp,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    /// Blocking `POST` of a `chat.postMessage` body with the bot token. Slack
    /// returns HTTP 200 even for logical failures, so both the status and the
    /// `ok` field are checked; the API `error` is surfaced to `send`.
    fn post_message(
        cfg: &SlackConfig,
        channel: &str,
        text: &str,
        thread_ts: Option<&str>,
    ) -> Result<(), String> {
        let body = build_send_body(channel, text, thread_ts);
        let resp = waki::Client::new()
            .post(&cfg.post_message_url())
            .header("Authorization", format!("Bearer {}", cfg.bot_token()))
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let value = resp.json::<Value>().map_err(|e| e.to_string())?;
        if !(200..300).contains(&status) {
            return Err(format!("slack chat.postMessage HTTP {status}"));
        }
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            let detail = value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            return Err(format!("slack chat.postMessage failed: {detail}"));
        }
        Ok(())
    }

    struct SlackChannel;

    impl PluginInfo for SlackChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for SlackChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure() -> Result<(), String> {
            public_config().map(|_| ())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = send_config()?;
            if cfg.bot_token().is_empty() {
                return Err("slack: no bot_token configured".to_string());
            }
            let thread = message.thread_ts.as_deref();
            let chunks = chunk_text(&message.content, MAX_TEXT_CHARS);
            for chunk in chunks {
                post_message(&cfg, &message.recipient, &chunk, thread)?;
            }
            Ok(())
        }

        /// Webhook channel: inbound arrives via `parse_webhook`, never polling.
        fn poll_message() -> Option<InboundMessage> {
            None
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::WEBHOOK_INGRESS
        }

        fn health_check() -> bool {
            send_config().is_ok_and(|cfg| !cfg.bot_token().is_empty())
                && inbound_config().is_ok_and(|cfg| !cfg.signing_secret().is_empty())
        }

        fn webhook_path() -> Option<String> {
            Some(PLUGIN_NAME.to_string())
        }

        fn parse_webhook(request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            let headers = request.headers;
            let body = request.body;
            let cfg = inbound_config().map_err(WebhookRejection::Unauthorized)?;
            if !authenticate_webhook(
                cfg.signing_secret(),
                &request.method,
                &headers,
                &body,
                now_secs(),
            )
            .map_err(WebhookRejection::Unauthorized)?
            {
                return Ok(WebhookResponse::Messages(Vec::new()));
            }
            match decode_webhook(&body).map_err(WebhookRejection::BadRequest)? {
                WebhookOutcome::Challenge(challenge) => Ok(WebhookResponse::Reply(challenge)),
                WebhookOutcome::Messages(msgs) => Ok(WebhookResponse::Messages(
                    msgs.into_iter().map(to_wit).collect(),
                )),
            }
        }

        // ── capability-gated stubs (documented WIT defaults) ──
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
    }

    export!(SlackChannel);
}
