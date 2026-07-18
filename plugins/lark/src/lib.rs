//! A ZeroClaw WIT **channel** plugin: Lark / Feishu (webhook ingress).
//!
//! The host runs the network-facing listener: it serves `GET`/`POST` on
//! `/plugin/lark`, and hands each request to the plugin's exported
//! `parse-webhook` (with the request line surfaced via the reserved
//! `x-webhook-method` / `x-webhook-query` headers). The plugin owns the payload
//! shape and the authenticity check: it verifies the Lark **verification token**
//! over the body and returns a typed unauthorized or bad-request rejection so
//! the gateway replies 401 or 400 and enqueues nothing. The URL-verification
//! handshake is answered inline by
//! returning a single reserved `__webhook_reply__` message whose `content` the
//! host echoes back verbatim (Lark expects the `{"challenge": …}` JSON).
//!
//! Because a webhook channel does not poll, `poll-message` always returns
//! `none`. Outbound replies go through Lark's `im/v1/messages` API: the plugin
//! exchanges its `app_id`/`app_secret` for a short-lived `tenant_access_token`
//! (cached, refreshed on the `99991663` expiry code) and `POST`s a text message,
//! all via the host's `wasi:http` (`waki`) client — TLS is performed host-side.
//!
//! The pure Lark logic lives in [`lark`] (no wasm/http deps) and is covered by a
//! host `cargo test`; this file is the thin component shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod lark;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;
    use std::time::Duration;

    use serde_json::Value;

    use crate::lark::{
        authenticate_webhook, build_send_body, build_token_request_body, decode_webhook,
        extract_tenant_token, is_invalid_token, parse_webhook_body, response_code,
        split_text_chunks, Inbound, LarkConfig, WebhookOutcome, LARK_TEXT_MAX_BYTES,
        WEBHOOK_REPLY_CHANNEL,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "lark";
    const PLUGIN_VERSION: &str = "0.1.0";
    /// URL path segment the host mounts this channel's webhook under
    /// (`/plugin/lark`).
    const WEBHOOK_SEGMENT: &str = "lark";
    /// Reserved header names the host uses to pass the webhook request line.
    const HEADER_METHOD: &str = "x-webhook-method";
    const HEADER_QUERY: &str = "x-webhook-query";
    /// Connect-phase timeout for every API call. `waki` can only bound the
    /// connect (not the response body), which is enough to fail fast on a dead
    /// endpoint.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    thread_local! {
        static CONFIG: RefCell<LarkConfig> = RefCell::new(LarkConfig::default());
        /// Cached tenant access token; `None` == must be (re)fetched.
        static TENANT_TOKEN: RefCell<Option<String>> = const { RefCell::new(None) };
    }

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

    /// The cached tenant token, fetching + caching one on a miss.
    fn ensure_tenant_token(cfg: &LarkConfig) -> Result<String, String> {
        if let Some(tok) = TENANT_TOKEN.with(|t| t.borrow().clone()) {
            return Ok(tok);
        }
        let tok = fetch_tenant_token(cfg)?;
        TENANT_TOKEN.with(|t| *t.borrow_mut() = Some(tok.clone()));
        Ok(tok)
    }

    fn clear_tenant_token() {
        TENANT_TOKEN.with(|t| *t.borrow_mut() = None);
    }

    /// Send one already-chunked text message, refreshing the tenant token once
    /// on an expiry code.
    fn send_text_once(cfg: &LarkConfig, recipient: &str, text: &str) -> Result<(), String> {
        let url = cfg.send_url();
        let body = build_send_body(recipient, text);

        let mut token = ensure_tenant_token(cfg)?;
        let (status, resp) = post_json(&url, &token, &body)?;
        let code = response_code(&resp);

        if status == 401 || is_invalid_token(code) {
            // Token expired mid-flight: drop it, fetch a fresh one, retry once.
            clear_tenant_token();
            token = ensure_tenant_token(cfg)?;
            let (status2, resp2) = post_json(&url, &token, &body)?;
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

    /// Build the reserved `__webhook_reply__` inbound message the host echoes as
    /// the HTTP 200 response body (enqueuing nothing).
    fn reply_message(body: String) -> InboundMessage {
        InboundMessage {
            id: String::new(),
            sender: String::new(),
            reply_target: String::new(),
            content: body,
            channel: WEBHOOK_REPLY_CHANNEL.to_string(),
            channel_alias: None,
            timestamp: 0,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    /// Case-insensitive lookup of a lower-cased reserved header.
    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
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

        fn configure(config: String) -> Result<(), String> {
            let cfg = LarkConfig::from_json(&config);
            // A new config invalidates any cached tenant token (credentials or
            // endpoint may have changed).
            clear_tenant_token();
            CONFIG.with(|c| *c.borrow_mut() = cfg);
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
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
            for chunk in &chunks {
                send_text_once(&cfg, &recipient, chunk)?;
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
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if !cfg.has_credentials() {
                return false;
            }
            // Reachable + credentials valid iff we can mint a tenant token.
            match ensure_tenant_token(&cfg) {
                Ok(_) => true,
                Err(_) => {
                    clear_tenant_token();
                    false
                }
            }
        }

        fn webhook_path() -> Option<String> {
            Some(WEBHOOK_SEGMENT.to_string())
        }

        fn parse_webhook(
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            // The host passes the request line via reserved lower-cased headers.
            // Default to POST (Lark's event delivery method) when absent.
            let method = header(&headers, HEADER_METHOD).unwrap_or("POST");
            let _query = header(&headers, HEADER_QUERY).unwrap_or("");
            let Some(payload) =
                parse_webhook_body(method, &body).map_err(WebhookRejection::BadRequest)?
            else {
                return Ok(vec![reply_message("ok".to_string())]);
            };
            authenticate_webhook(&cfg, &payload).map_err(WebhookRejection::Unauthorized)?;

            match decode_webhook(&cfg, &payload) {
                WebhookOutcome::Reply(reply) => Ok(vec![reply_message(reply)]),
                WebhookOutcome::Events(events) => Ok(events.into_iter().map(to_wit).collect()),
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
