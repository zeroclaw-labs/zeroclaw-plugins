//! Gmail Pub/Sub channel. The host passes a typed request to the guest, which
//! authenticates the push and records the newest history ID. The long-lived
//! listener fetches mail and checkpoints after handing it to the host. The supervisor's first poll attempts
//! watch registration when configured. Outbound mail uses messages.send.

pub mod gmail_push;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::{Cell, RefCell};
    use std::time::{Duration, Instant};

    use serde_json::Value;

    use crate::gmail_push::{
        build_send_body, build_send_raw, build_watch_body, history_url, message_to_inbound,
        message_url, parse_envelope, parse_notification, send_url, verify_bearer, watch_url,
        GmailMessage, GmailPushConfig, HistoryResponse, InboundFields, WEBHOOK_PATH,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    use crate::gmail_push::{HistoryBatch, HistoryCursor};
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
        static BATCH: RefCell<Option<HistoryBatch>> = const { RefCell::new(None) };
        static NEXT_HISTORY: Cell<Option<Instant>> = const { Cell::new(None) };
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

    fn get_bearer(url: &str, token: &str) -> Result<waki::Response, String> {
        waki::Client::new()
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .connect_timeout(CONNECT_TIMEOUT)
            .send()
            .map_err(|e| format!("gmail_push GET failed: {e}"))
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

    fn load_batch(cursor: HistoryCursor, token: &str) -> Result<Option<HistoryBatch>, String> {
        let mut page_token = None;
        loop {
            let response =
                get_bearer(&history_url(cursor.delivered, page_token.as_deref()), token)?;
            if response.status_code() == 404 {
                return Err("gmail_push: Gmail history cursor expired; synchronize the mailbox and seed a fresh binding".into());
            }
            crate::gmail_push::check_api_status(response.status_code())?;
            let page: HistoryResponse = response
                .json()
                .map_err(|_| "gmail_push: invalid Gmail history page")?;
            if page.history.as_ref().is_none_or(Vec::is_empty) && page.next_page_token.is_some() {
                page_token = page.next_page_token;
                continue;
            }
            return page.next_batch(cursor);
        }
    }

    fn poll_mail() -> Result<Option<InboundMessage>, String> {
        // The host drains a successful poll result before it calls this guest
        // again. A dropped listener leaves the durable checkpoint behind it.
        if let Some(through) = BATCH.with(|b| {
            b.borrow()
                .as_ref()
                .filter(|b| b.message_ids.is_empty())
                .map(|b| b.through)
        }) {
            let (cursor, revision) = read_cursor()?.ok_or("gmail_push: missing delivery cursor")?;
            let confirmed = cursor.confirm(through);
            if confirmed != cursor {
                save_cursor(confirmed, Some(revision))?;
            }
            BATCH.with(|b| b.borrow_mut().take());
        }
        let pending = if BATCH.with(|b| b.borrow().is_none()) {
            let Some((cursor, _)) = read_cursor()? else {
                return Ok(None);
            };
            if cursor.delivered >= cursor.announced {
                return Ok(None);
            }
            Some(cursor)
        } else {
            None
        };
        let cfg = send_config()?;
        if cfg.oauth_token().is_empty() {
            return Err("gmail_push: missing oauth_token".into());
        }
        if let Some(cursor) = pending {
            let next = load_batch(cursor, cfg.oauth_token())?;
            BATCH.with(|b| *b.borrow_mut() = next);
        }
        let id = BATCH.with(|b| {
            b.borrow()
                .as_ref()
                .and_then(|b| b.message_ids.front().cloned())
        });
        let Some(id) = id else {
            return Ok(None);
        };
        let response = get_bearer(&message_url(&id), cfg.oauth_token())?;
        let message = if response.status_code() == 404 {
            // Deleted between the history listing and messages.get.
            None
        } else {
            crate::gmail_push::check_api_status(response.status_code())?;
            let mail: GmailMessage = response
                .json()
                .map_err(|_| "gmail_push: invalid Gmail message")?;
            message_to_inbound(&mail).map(to_wit)
        };
        BATCH.with(|b| {
            if let Some(batch) = b.borrow_mut().as_mut() {
                batch.message_ids.pop_front();
            }
        });
        Ok(message)
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

        /// Renew the Gmail watch and drain the durable notification watermark.
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
            if NEXT_HISTORY
                .with(|next| next.get().is_some_and(|deadline| Instant::now() < deadline))
            {
                return None;
            }
            match poll_mail() {
                Ok(message) => message,
                Err(error) => {
                    NEXT_HISTORY
                        .with(|next| next.set(Some(Instant::now() + Duration::from_secs(5))));
                    logging::log_record(
                        logging::LogLevel::Warn,
                        &logging::PluginEvent {
                            function_name: "gmail_push::poll_mail".into(),
                            action: logging::PluginAction::Fail,
                            outcome: Some(logging::PluginOutcome::Failure),
                            duration_ms: None,
                            attrs: None,
                            message: error,
                        },
                    );
                    None
                }
            }
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

            let tip = notification.history_id;
            match read_cursor().map_err(WebhookRejection::BadRequest)? {
                Some((cursor, revision)) if tip > cursor.announced => {
                    save_cursor(cursor.announce(tip), Some(revision))
                        .map_err(WebhookRejection::BadRequest)?;
                }
                None => {
                    save_cursor(HistoryCursor::seed(tip), None)
                        .map_err(WebhookRejection::BadRequest)?;
                }
                Some(_) => {}
            }
            Ok(WebhookResponse::Messages(Vec::new()))
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
