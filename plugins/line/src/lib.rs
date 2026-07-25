//! A ZeroClaw WIT **channel** plugin: LINE (webhook ingress).
//!
//! LINE delivers messages by POSTing signed webhooks, so this is a *webhook*
//! channel, not a poller: the host serves `/plugin/line`, hands the raw request
//! to `parse-webhook`, and the plugin verifies the `X-Line-Signature` HMAC
//! (secret from its own config) before decoding events into inbound messages —
//! the host stays crypto-agnostic. `poll-message` never yields (nothing to
//! poll). Replies go out via the Messaging API push endpoint over the host's
//! `wasi:http` (`waki`).
//!
//! The pure logic (config/signature/event/body) lives in [`line`] with no
//! wasm/http deps and is host-`cargo test`ed; this file is the component shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod line;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;

    use serde_json::Value;

    use crate::line::{
        build_push_body, chunk_text, parse_events, verify_signature, Inbound, LineConfig,
        MAX_MESSAGE_CHARS,
    };

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    const PLUGIN_NAME: &str = "line";
    const PLUGIN_VERSION: &str = "0.1.0";

    thread_local! {
        static CONFIG: RefCell<LineConfig> = RefCell::new(LineConfig::default());
    }

    fn post_json_bearer(url: &str, token: &str, body: &Value) -> Result<u16, String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        Ok(resp.status_code())
    }

    fn to_wit(inb: Inbound) -> InboundMessage {
        InboundMessage {
            id: inb.id,
            sender: inb.sender,
            reply_target: inb.reply_target,
            content: inb.content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: 0,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    struct LineChannel;

    impl PluginInfo for LineChannel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for LineChannel {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            CONFIG.with(|c| *c.borrow_mut() = LineConfig::from_json(&config));
            Ok(())
        }

        fn send(message: SendMessage) -> Result<(), String> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            if cfg.channel_access_token.is_empty() {
                return Err("line: no channel_access_token configured".to_string());
            }
            let url = format!("{}/v2/bot/message/push", cfg.api_base);
            for chunk in chunk_text(&message.content, MAX_MESSAGE_CHARS) {
                let body = build_push_body(&message.recipient, &chunk);
                let status = post_json_bearer(&url, &cfg.channel_access_token, &body)?;
                if !(200..300).contains(&status) {
                    return Err(format!("line push failed ({status})"));
                }
            }
            Ok(())
        }

        // Webhook channel: nothing to poll — inbound arrives via `parse-webhook`.
        fn poll_message() -> Option<InboundMessage> {
            None
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::WEBHOOK_INGRESS
        }

        fn health_check() -> bool {
            CONFIG.with(|c| {
                let cfg = c.borrow();
                !cfg.channel_access_token.is_empty() && !cfg.channel_secret.is_empty()
            })
        }

        fn webhook_path() -> Option<String> {
            Some("line".to_string())
        }

        fn parse_webhook(
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            let cfg = CONFIG.with(|c| c.borrow().clone());
            // Headers are lower-cased by the host. The plugin owns the check:
            // reject an absent/invalid signature so the gateway replies 401 and
            // enqueues nothing.
            let signature = headers
                .iter()
                .find(|(k, _)| k == "x-line-signature")
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            if !verify_signature(&cfg.channel_secret, &body, signature) {
                return Err(WebhookRejection::Unauthorized(
                    "bad line signature".to_string(),
                ));
            }
            serde_json::from_slice::<Value>(&body).map_err(|e| {
                WebhookRejection::BadRequest(format!("line: invalid JSON payload: {e}"))
            })?;
            Ok(parse_events(&body).into_iter().map(to_wit).collect())
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

    export!(LineChannel);
}
