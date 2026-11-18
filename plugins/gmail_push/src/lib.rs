//! Gmail Pub/Sub channel. The host passes a typed request to the guest, which
//! checks the ingress bearer secret and fetches Gmail changes since the
//! binding's durable history cursor. The supervisor's first poll attempts
//! watch registration when configured. Outbound mail uses messages.send.

pub mod gmail_push;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::Cell;
    use std::time::{Duration, Instant};

    use serde_json::Value;

    use crate::gmail_push::{
        build_send_body, build_send_raw, build_watch_body, history_message_ids, history_url,
        message_to_inbound, message_url, parse_envelope, parse_notification, send_url,
        verify_bearer, watch_url, GmailMessage, GmailPushConfig, HistoryResponse, InboundFields,
        WEBHOOK_PATH,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    use crate::gmail_push::HistoryCursor;
    use zeroclaw::plugin::{config, logging, secrets, state};

    fn public_config() -> Result<GmailPushConfig, String> {
        let public = config::get().map_err(|_| "gmail_push: public configuration unavailable")?;
        serde_json::from_str(&public)
            .map_err(|_| "gmail_push: invalid public configuration".to_string())
    }

    fn optional_secret(key: &str) -> Result<Option<String>, String> {
        match secrets::get(key) {
            Ok(value) => Ok(Some(value)),
            Err(secrets::SecretError::NotFound) => Ok(None),
            Err(_) => Err(format!("gmail_push: cannot read {key}")),
        }
    }

    fn send_config() -> Result<GmailPushConfig, String> {
        let mut cfg = public_config()?;
        cfg.oauth_token = optional_secret("oauth_token")?.unwrap_or_default();
        Ok(cfg)
    }

    fn inbound_config() -> Result<GmailPushConfig, String> {
        let mut cfg = public_config()?;
        cfg.webhook_secret = optional_secret("webhook_secret")?.unwrap_or_default();
        cfg.oauth_token = optional_secret("oauth_token")?.unwrap_or_default();
        if cfg.webhook_secret().is_empty() {
            return Err("gmail_push: webhook_secret required for webhook ingress".into());
        }
        Ok(cfg)
    }

    const PLUGIN_NAME: &str = "gmail_push";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    thread_local! {
        // Only the supervisor's long-lived poll instance attempts watch registration.
        static NEXT_WATCH: Cell<Option<Instant>> = const { Cell::new(None) };
    }

    const HISTORY_KEY: &str = "gmail-history";

    fn read_cursor() -> Result<Option<(HistoryCursor, u64)>, String> {
        let entry =
            state::get(HISTORY_KEY).map_err(|_| "gmail_push: cannot read history cursor")?;
        entry
            .map(|entry| {
                let cursor = serde_json::from_slice(&entry.value)
                    .map_err(|_| "gmail_push: invalid history cursor")?;
                Ok((cursor, entry.revision))
            })
            .transpose()
    }

    fn save_cursor(cursor: HistoryCursor, revision: Option<u64>) -> Result<(), String> {
        let bytes =
            serde_json::to_vec(&cursor).map_err(|_| "gmail_push: cannot encode history cursor")?;
        state::put(HISTORY_KEY, &bytes, revision)
            .map(|_| ())
            .map_err(|_| "gmail_push: history cursor update failed; retry delivery".into())
    }

    fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    fn to_wit(inb: InboundFields) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: inb.timestamp,
            thread_ts: inb.thread_ts,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    fn get_bearer(url: &str, token: &str) -> Result<Value, String> {
        let response = waki::Client::new()
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .connect_timeout(CONNECT_TIMEOUT)
            .send()
            .map_err(|_| "gmail_push: Gmail GET transport failed")?;
        crate::gmail_push::check_api_status(response.status_code())?;
        response
            .json::<Value>()
            .map_err(|e| format!("gmail_push: bad JSON response: {e}"))
    }

    fn post_json_bearer(url: &str, token: &str, body: &Value) -> Result<(), String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .connect_timeout(CONNECT_TIMEOUT)
            .json(body)
            .send()
            .map_err(|_| "gmail_push: Gmail POST transport failed")?;
        crate::gmail_push::check_api_status(resp.status_code())
    }

    /// Fetch new message IDs from the History API since `start_id`, following
    /// pagination. Returns the IDs and the newest `historyId` observed.
    fn fetch_history(token: &str, start_id: u64) -> Result<(Vec<String>, u64), String> {
        let mut ids = Vec::new();
        let mut newest = start_id;
        let mut page_token: Option<String> = None;
        loop {
            let v = get_bearer(&history_url(start_id, page_token.as_deref()), token)?;
            let resp: HistoryResponse = serde_json::from_value(v)
                .map_err(|e| format!("gmail_push: bad history response: {e}"))?;
            ids.extend(history_message_ids(&resp));
            if resp.history_id > newest {
                newest = resp.history_id;
            }
            match resp.next_page_token {
                Some(pt) => page_token = Some(pt),
                None => break,
            }
        }
        Ok((ids, newest))
    }

    fn fetch_message(token: &str, id: &str) -> Result<GmailMessage, String> {
        let v = get_bearer(&message_url(id), token)?;
        serde_json::from_value(v).map_err(|e| format!("gmail_push: bad message response: {e}"))
    }

    struct GmailPushChannel;

    impl PluginInfo for GmailPushChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for GmailPushChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure() -> Result<(), String> {
            public_config().map(|_| ())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = send_config()?;
            let token = cfg.oauth_token();
            if token.is_empty() {
                return Err("gmail_push: missing oauth_token in config".to_string());
            }
            let subject = message.subject.as_deref().unwrap_or("ZeroClaw Message");
            let raw = build_send_raw(&message.recipient, subject, &message.content);
            post_json_bearer(&send_url(), token, &build_send_body(&raw))
        }

        /// A webhook channel never polls — inbound arrives via `parse_webhook`.
        fn poll_message() -> Option<InboundMessage> {
            if NEXT_WATCH.with(|next| next.get().is_none_or(|deadline| Instant::now() >= deadline))
            {
                // Gmail watches expire. While the supervisor is running, renew
                // daily and retry an unavailable API or credential after five minutes.
                let result = send_config().and_then(|cfg| {
                    if cfg.oauth_token().is_empty() || cfg.topic.trim().is_empty() {
                        return Ok(false);
                    }
                    let body = build_watch_body(cfg.topic.trim(), &cfg.label_filter);
                    post_json_bearer(&watch_url(), cfg.oauth_token(), &body).map(|_| true)
                });
                let delay = match result {
                    Ok(true) => Duration::from_secs(24 * 60 * 60),
                    Ok(false) => Duration::from_secs(5 * 60),
                    Err(error) => {
                        logging::log_record(
                            logging::LogLevel::Warn,
                            &logging::PluginEvent {
                                function_name: "gmail_push::poll_message".into(),
                                action: logging::PluginAction::Fail,
                                outcome: Some(logging::PluginOutcome::Failure),
                                duration_ms: None,
                                attrs: None,
                                message: error,
                            },
                        );
                        Duration::from_secs(5 * 60)
                    }
                };
                NEXT_WATCH.with(|next| next.set(Some(Instant::now() + delay)));
            }
            None
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::WEBHOOK_INGRESS
        }

        fn health_check() -> bool {
            send_config().is_ok_and(|cfg| !cfg.oauth_token().is_empty())
        }

        fn webhook_path() -> Option<String> {
            Some(WEBHOOK_PATH.to_string())
        }

        fn parse_webhook(request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            let headers = request.headers;
            let body = request.body;
            let method = &request.method;
            // Pub/Sub delivers via POST; ack a GET with nothing.
            if method.eq_ignore_ascii_case("GET") {
                return Ok(WebhookResponse::Messages(Vec::new()));
            }

            let cfg = inbound_config().map_err(WebhookRejection::Unauthorized)?;

            // ── Shared-secret auth ──
            let auth = header_get(&headers, "authorization").unwrap_or_default();
            if !verify_bearer(cfg.webhook_secret(), &auth) {
                return Err(WebhookRejection::Unauthorized(
                    "gmail_push: unauthorized (bad or missing Bearer secret)".to_string(),
                ));
            }

            // ── Decode the Pub/Sub notification ──
            let envelope = parse_envelope(&body).map_err(WebhookRejection::BadRequest)?;
            let notification =
                parse_notification(&envelope.message).map_err(WebhookRejection::BadRequest)?;

            let token = cfg.oauth_token();
            if token.is_empty() {
                return Err(WebhookRejection::BadRequest(
                    "gmail_push: missing oauth_token in config".to_string(),
                ));
            }

            // A webhook runs in a fresh guest, so keep the checkpoint in the
            // binding's durable state. Retain the previous start for a retry of
            // the same notification. Gmail message IDs let the host deduplicate.
            let tip = notification.history_id;
            let Some((cursor, revision)) = read_cursor().map_err(WebhookRejection::BadRequest)?
            else {
                save_cursor(HistoryCursor::seed(tip), None)
                    .map_err(WebhookRejection::BadRequest)?;
                return Ok(WebhookResponse::Messages(Vec::new()));
            };
            let Some(window) = cursor.window(tip) else {
                return Ok(WebhookResponse::Messages(Vec::new()));
            };
            let (ids, _) =
                fetch_history(token, window.start).map_err(WebhookRejection::BadRequest)?;
            let mut out = Vec::new();
            for id in ids {
                let msg = fetch_message(token, &id).map_err(WebhookRejection::BadRequest)?;
                if let Some(inb) = message_to_inbound(&msg) {
                    out.push(to_wit(inb));
                }
            }
            if let Some(next) = window.next {
                save_cursor(next, Some(revision)).map_err(WebhookRejection::BadRequest)?;
            }
            Ok(WebhookResponse::Messages(out))
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

    export!(GmailPushChannel);
}
