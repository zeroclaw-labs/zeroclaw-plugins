pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::core::{parse_job, reply_key, Config};
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use serde_json::{json, Value};
    use std::cell::{Cell, RefCell};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use zeroclaw::plugin::{config, logging};

    thread_local! {
        // Only the in-flight message ID is guest state. Config is resolved on each operation.
        static PENDING: RefCell<Option<String>> = const { RefCell::new(None) };
        static HEALTHY: Cell<bool> = const { Cell::new(false) };
    }

    fn current() -> Result<Config, String> {
        Config::parse(&config::get().map_err(|_| "Iris configuration unavailable")?)
    }

    fn call(op: &str, data: &Value) -> Result<Value, String> {
        let response = waki::Client::new()
            .post(&format!("http://127.0.0.1:8765/channel/{op}"))
            .connect_timeout(Duration::from_secs(3))
            .json(data)
            .send()
            .map_err(|_| {
                "Iris bridge unavailable; check the bridge and explicit loopback egress grant"
            })?;
        if response.status_code() != 200 {
            return Err("Iris bridge rejected the operation".into());
        }
        let body: Value = response
            .json()
            .map_err(|_| "invalid Iris bridge response")?;
        if body.get("ok") != Some(&Value::Bool(true)) {
            return Err("Iris bridge operation failed".into());
        }
        Ok(body.get("result").cloned().unwrap_or(Value::Null))
    }

    fn receive() -> Result<Option<InboundMessage>, String> {
        let cfg = current()?;
        if PENDING.with(|pending| pending.borrow().is_some()) {
            return Ok(None);
        }
        let Some(job) = parse_job(call("receive", &json!({"active":[]}))?, &cfg)? else {
            return Ok(None);
        };
        if job.interrupted {
            call(
                "send",
                &json!({"key":format!("recovery:{}", job.id),
                "text":"My previous task was interrupted. I did not repeat it automatically. Send a new message to continue."}),
            )?;
            call("finish", &json!({"id":job.id}))?;
            return Ok(None);
        }
        call("seen", &json!({"id":job.id}))?;
        PENDING.with(|pending| *pending.borrow_mut() = Some(job.id.clone()));
        Ok(Some(InboundMessage {
            id: job.id,
            sender: job.owner.clone(),
            reply_target: job.owner,
            content: job.text,
            channel: "iris".into(),
            channel_alias: None,
            timestamp: (job.created * 1000.0) as u64,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: vec![],
            subject: None,
        }))
    }

    struct Iris;
    impl PluginInfo for Iris {
        fn plugin_name() -> String {
            "iris-chat".into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }

    impl Channel for Iris {
        fn name() -> String {
            "Iris Chat".into()
        }
        fn configure() -> Result<(), String> {
            let cfg = current()?;
            let health = call("health", &json!({}))?;
            cfg.recipient(
                health
                    .get("owner")
                    .and_then(Value::as_str)
                    .ok_or("Iris bridge has no paired contact")?,
            )?;
            if health.get("ready") != Some(&Value::Bool(true)) {
                return Err("Iris bridge is not ready".into());
            }
            HEALTHY.with(|healthy| healthy.set(true));
            Ok(())
        }
        fn send(message: SendMessage) -> Result<(), String> {
            current()?.recipient(&message.recipient)?;
            if !message.attachments.is_empty() {
                return Err("Iris supports text replies only".into());
            }
            if message.content.trim().is_empty() {
                return Err("Iris reply is empty".into());
            }
            let pending = PENDING.with(|value| value.borrow().clone());
            let anchor = match &pending {
                Some(id) => id.clone(),
                None => format!(
                    "outbound:{}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| "invalid system clock")?
                        .as_nanos()
                ),
            };
            call(
                "send",
                &json!({"key":reply_key(&anchor, &message.content),"text":message.content}),
            )?;
            if let Some(id) = pending {
                call("finish", &json!({"id":id}))?;
                PENDING.with(|value| *value.borrow_mut() = None);
            }
            call("typing", &json!({"active":false}))?;
            Ok(())
        }
        fn poll_message() -> Option<InboundMessage> {
            match receive() {
                Ok(message) => {
                    HEALTHY.with(|healthy| healthy.set(true));
                    message
                }
                Err(_) => {
                    if HEALTHY.with(|healthy| healthy.replace(false)) {
                        logging::log_record(logging::LogLevel::Warn, &logging::PluginEvent {
                            function_name: "iris_chat::poll_message".into(), action: logging::PluginAction::Fail,
                            outcome: Some(logging::PluginOutcome::Failure), duration_ms: None, attrs: None,
                            message: "Iris receive failed; check paired contact, local bridge, and egress permissions. No task is replayed.".into(),
                        });
                    }
                    None
                }
            }
        }
        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::START_TYPING
                | ChannelCapabilities::STOP_TYPING
        }
        fn health_check() -> bool {
            current().is_ok() && HEALTHY.with(Cell::get)
        }
        fn start_typing(recipient: String) -> Result<(), String> {
            current()?.recipient(&recipient)?;
            call("typing", &json!({"active":true})).map(|_| ())
        }
        fn stop_typing(recipient: String) -> Result<(), String> {
            current()?.recipient(&recipient)?;
            call("typing", &json!({"active":false})).map(|_| ())
        }
        fn self_handle() -> Option<String> {
            None
        }
        fn self_addressed_mention() -> Option<String> {
            None
        }
        fn drop_self_message(_: InboundMessage) -> bool {
            false
        }
        fn supports_draft_updates() -> bool {
            false
        }
        fn send_draft(_: SendMessage) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn update_draft(_: String, _: String, _: String) -> Result<(), String> {
            Ok(())
        }
        fn update_draft_progress(_: String, _: String, _: String) -> Result<(), String> {
            Ok(())
        }
        fn finalize_draft(_: String, _: String, _: String) -> Result<(), String> {
            Ok(())
        }
        fn cancel_draft(_: String, _: String) -> Result<(), String> {
            Ok(())
        }
        fn supports_multi_message_streaming() -> bool {
            false
        }
        fn multi_message_delay_ms() -> u64 {
            800
        }
        fn add_reaction(_: String, _: String, _: String) -> Result<(), String> {
            Ok(())
        }
        fn remove_reaction(_: String, _: String, _: String) -> Result<(), String> {
            Ok(())
        }
        fn pin_message(_: String, _: String) -> Result<(), String> {
            Ok(())
        }
        fn unpin_message(_: String, _: String) -> Result<(), String> {
            Ok(())
        }
        fn redact_message(_: String, _: String, _: Option<String>) -> Result<(), String> {
            Ok(())
        }
        fn request_approval(
            _: String,
            _: ApprovalRequest,
        ) -> Result<Option<ApprovalResponse>, String> {
            Ok(None)
        }
        fn request_choice(_: String, _: Vec<String>, _: u64) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn supports_free_form_ask() -> bool {
            false
        }
        fn webhook_path() -> Option<String> {
            None
        }
        fn parse_webhook(_: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            Err(WebhookRejection::BadRequest("unsupported".into()))
        }
    }
    export!(Iris);
}
