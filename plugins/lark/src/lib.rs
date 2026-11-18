//! Lark/Feishu Open Platform channel. The plugin verifies the configured token
//! on plaintext challenges and events. URL verification returns a typed HTTP
//! reply; authenticated text events go to the channel's sender policy.
//! Outbound text uses an app-scoped tenant token obtained for the current send.

pub mod lark;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::Duration;

    use serde_json::Value;

    use crate::lark::{
        authenticate_webhook, build_send_body, build_token_request_body, decode_webhook,
        extract_tenant_token, is_invalid_token, parse_webhook_body, response_code,
        split_text_chunks, Inbound, LarkConfig, WebhookOutcome, LARK_TEXT_MAX_BYTES,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    use zeroclaw::plugin::{config, secrets};

    fn public_config() -> Result<LarkConfig, String> {
        let public = config::get().map_err(|_| "lark: public configuration unavailable")?;
        serde_json::from_str(&public).map_err(|_| "lark: invalid public configuration".to_string())
    }

    fn optional_secret(key: &str) -> Result<Option<String>, String> {
        match secrets::get(key) {
            Ok(value) => Ok(Some(value)),
            Err(secrets::SecretError::NotFound) => Ok(None),
            Err(_) => Err(format!("lark: cannot read {key}")),
        }
    }

    fn send_config() -> Result<LarkConfig, String> {
        let mut cfg = public_config()?;
        cfg.app_secret = optional_secret("app_secret")?.unwrap_or_default();
        Ok(cfg)
    }

    fn inbound_config() -> Result<LarkConfig, String> {
        let mut cfg = public_config()?;
        cfg.verification_token = optional_secret("verification_token")?;
        cfg.encrypt_key = optional_secret("encrypt_key")?;
        if cfg.verification_token().is_none() {
            return Err("lark: verification_token required for webhook ingress".into());
        }
        Ok(cfg)
    }

    const PLUGIN_NAME: &str = "lark";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    /// URL path segment the host mounts this channel's webhook under
    /// (`/plugin/lark`).
    const WEBHOOK_SEGMENT: &str = "lark";
    /// Connect-phase timeout for every API call. `waki` can only bound the
    /// connect (not the response body), which is enough to fail fast on a dead
    /// endpoint.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// `POST` a JSON body to a Lark endpoint with a `Bearer` token →
    /// `(status, parsed-body)`. The body is parsed even on error responses (Lark
    /// returns JSON `code`/`msg` errors) so the caller can inspect them.
    fn post_json(url: &str, token: &str, body: &Value) -> Result<(u16, Value), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json; charset=utf-8")
            .connect_timeout(CONNECT_TIMEOUT)
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status_code();
        let val = resp.json::<Value>().map_err(|e| e.to_string())?;
        Ok((status, val))
    }

    /// Exchange `app_id`/`app_secret` for a fresh `tenant_access_token`.
    fn fetch_tenant_token(cfg: &LarkConfig) -> Result<String, String> {
        let url = cfg.tenant_token_url();
        let body = build_token_request_body(cfg.app_id.trim(), cfg.app_secret.trim());
        let resp = waki::Client::new()
            .post(&url)
            .header("Content-Type", "application/json; charset=utf-8")
            .connect_timeout(CONNECT_TIMEOUT)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        let val = resp.json::<Value>().map_err(|e| e.to_string())?;
        extract_tenant_token(&val)
    }

    /// Send one already-chunked text message, refreshing the tenant token once
    /// on an expiry code.
    fn send_text_once(
        cfg: &LarkConfig,
        token: &mut String,
        recipient: &str,
        text: &str,
    ) -> Result<(), String> {
        let url = cfg.send_url();
        let body = build_send_body(recipient, text);

        let (status, resp) = post_json(&url, token, &body)?;
        let code = response_code(&resp);

        if status == 401 || is_invalid_token(code) {
            // Token expired mid-flight: drop it, fetch a fresh one, retry once.
            *token = fetch_tenant_token(cfg)?;
            let (status2, resp2) = post_json(&url, token, &body)?;
            let code2 = response_code(&resp2);
            if status2 >= 400 || code2 != 0 {
                return Err(format!(
                    "lark send failed after token refresh (status {status2}, code {code2}): {resp2}"
                ));
            }
            return Ok(());
        }

        if status >= 400 || code != 0 {
            return Err(format!(
                "lark send failed (status {status}, code {code}): {resp}"
            ));
        }
        Ok(())
    }

    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: inb.channel_alias,
            timestamp: inb.timestamp,
            thread_ts: inb.thread_ts,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct LarkChannel;

    impl PluginInfo for LarkChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for LarkChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure() -> Result<(), String> {
            public_config().map(|_| ())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = send_config()?;
            if !cfg.has_credentials() {
                return Err(
                    "lark: app_id/app_secret not configured — set them in this channel's config \
                     to send messages"
                        .to_string(),
                );
            }
            let recipient = message.recipient;
            // Lark text messages are plain (no Markdown rendering — the native
            // channel uses interactive cards for that; see README). Chunk long
            // turns into an ordered sequence of text messages.
            let chunks = split_text_chunks(&message.content, LARK_TEXT_MAX_BYTES);
            if chunks.is_empty() {
                return Ok(());
            }
            let mut token = fetch_tenant_token(&cfg)?;
            for chunk in &chunks {
                send_text_once(&cfg, &mut token, &recipient, chunk)?;
            }
            Ok(())
        }

        /// A webhook channel is push-only: the host feeds inbound events via
        /// `parse-webhook`, so there is nothing to poll.
        fn poll_message() -> Option<InboundMessage> {
            None
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::WEBHOOK_INGRESS
        }

        fn health_check() -> bool {
            let Ok(cfg) = send_config() else { return false };
            if !cfg.has_credentials() {
                return false;
            }
            // Reachable + credentials valid iff we can mint a tenant token.
            fetch_tenant_token(&cfg).is_ok()
        }

        fn webhook_path() -> Option<String> {
            Some(WEBHOOK_SEGMENT.to_string())
        }

        fn parse_webhook(request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            let body = request.body;
            let cfg = inbound_config().map_err(WebhookRejection::Unauthorized)?;
            let method = &request.method;
            let Some(payload) =
                parse_webhook_body(method, &body).map_err(WebhookRejection::BadRequest)?
            else {
                return Ok(WebhookResponse::Reply("ok".to_string()));
            };
            authenticate_webhook(&cfg, &payload).map_err(WebhookRejection::Unauthorized)?;

            match decode_webhook(&cfg, &payload) {
                WebhookOutcome::Reply(reply) => Ok(WebhookResponse::Reply(reply)),
                WebhookOutcome::Events(events) => Ok(WebhookResponse::Messages(
                    events.into_iter().map(to_wit).collect(),
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

    export!(LarkChannel);
}
