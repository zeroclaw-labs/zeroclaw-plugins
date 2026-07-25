//! A ZeroClaw WIT **channel** plugin: Solana as an inbound message stream.
//!
//! Zeroclaw already treats Telegram, Discord, Matrix, WhatsApp, IRC, Nostr,
//! Bluesky, email, MQTT and 20+ other platforms as first-class inbound
//! channels. This plugin adds one more: **Solana**. It polls a
//! configured on-chain address, extracts every SPL Memo the address was
//! mentioned in and every SOL/SPL transfer credited to it, and hands each
//! event to the agent through the same `channel-plugin` WIT contract every
//! other channel uses.
//!
//! Custody tier
//! ------------
//! **T0 (read-only).** This channel holds no keys and signs nothing. Sending
//! is the job of the companion `solana-outbox` **tool** plugin (T1: builds an
//! unsigned versioned transaction, human/multisig signs). Splitting the pair
//! keeps the WASM component that touches the network sandboxed to reads only
//! — the operator's spend authority never crosses the plugin boundary. The
//! `send` export on this channel therefore returns an error naming the
//! outbox plugin, and the channel-capabilities bitmask advertises no
//! outbound features.
//!
//! Pure logic lives in [`core`] with no wasm/http dependency. The wasm
//! component is the thin shim wiring HTTP + WIT to that logic — the same
//! layout the reference `redact-text` and `telegram` plugins use.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::cell::RefCell;
    use std::collections::VecDeque;

    use serde_json::{json, Value};

    use crate::core::{extract_inbounds, parse_signatures_response, Config, Inbound};

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaInbox;

    const PLUGIN_NAME: &str = "solana-inbox";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    thread_local! {
        static CONFIG: RefCell<Option<Config>> = const { RefCell::new(None) };
        /// Cursor: the newest signature we have already delivered. On the
        /// next `getSignaturesForAddress` call we ask the RPC to return
        /// everything strictly newer than this one via the `until` param,
        /// which is bounded, monotonic, and survives the plugin sleeping.
        static CURSOR: RefCell<Option<String>> = const { RefCell::new(None) };
        /// Local buffer of already-decoded inbound events. One transaction
        /// can produce multiple events (memo + transfer); we drain the
        /// buffer one item per `poll_message` call so the runtime never
        /// blocks longer than one RPC round-trip.
        static BUFFER: RefCell<VecDeque<Inbound>> = const { RefCell::new(VecDeque::new()) };
    }

    impl PluginInfo for SolanaInbox {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for SolanaInbox {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            let cfg = Config::from_json(&config)?;
            CONFIG.with(|c| *c.borrow_mut() = Some(cfg));
            emit(PluginAction::Register, PluginOutcome::Success, "configured");
            Ok(())
        }

        fn send(_message: SendMessage) -> Result<(), String> {
            // The whole point of the split-plugin design: this channel is
            // read-only. Attempting to `send()` here would either need a
            // signing key (blowing the T0 tier and the plugin's sandbox
            // safety story) or would silently no-op (worse — it would
            // look like the agent replied when nothing happened on chain).
            // Both are worse than an explicit error routing the agent at
            // the companion tool plugin.
            Err(
                "solana-inbox is read-only; build outbound replies with the `solana-outbox` \
                 tool plugin and sign them via a channel plugin the operator trusts (Telegram \
                 approval, Squads multisig, etc.)"
                    .to_string(),
            )
        }

        fn poll_message() -> Option<InboundMessage> {
            if let Some(next) = BUFFER.with(|b| b.borrow_mut().pop_front()) {
                return Some(to_wit(next));
            }

            let cfg = CONFIG.with(|c| c.borrow().clone())?;

            if let Err(e) = refill_from_rpc(&cfg) {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    &format!("poll refill failed: {e}"),
                );
                return None;
            }

            BUFFER.with(|b| b.borrow_mut().pop_front()).map(to_wit)
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            // Only `HEALTH_CHECK` is advertised. Every other flag is left
            // off deliberately: no `SELF_HANDLE` (an inbox has no
            // handle), no draft/typing/reaction/approval features (all
            // are outbound). The runtime resolves each unset flag to the
            // WIT-documented Rust trait default and never calls the
            // corresponding stub below.
            ChannelCapabilities::HEALTH_CHECK
        }

        fn health_check() -> bool {
            let Some(cfg) = CONFIG.with(|c| c.borrow().clone()) else {
                return false;
            };
            rpc_health(&cfg).unwrap_or_default()
        }

        // ── capability-gated stubs (documented WIT defaults) ──
        // Everything below returns the trait default the WIT header
        // documents; the runtime never calls these because the
        // corresponding capability flag isn't in `get_channel_capabilities`.

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
            false
        }
        fn webhook_path() -> Option<String> {
            None
        }
        fn parse_webhook(
            _headers: Vec<(String, String)>,
            _body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, WebhookRejection> {
            Err(WebhookRejection::BadRequest(
                "solana-inbox does not serve webhooks".to_string(),
            ))
        }
    }

    fn refill_from_rpc(cfg: &Config) -> Result<(), String> {
        let cursor = CURSOR.with(|c| c.borrow().clone());
        let sigs_resp = rpc_get_signatures(cfg, cursor.as_deref())?;
        let sigs = parse_signatures_response(&sigs_resp);
        if sigs.is_empty() {
            return Ok(());
        }

        // Advance the cursor to the newest signature we saw *before* we
        // start fetching individual transactions. Even if one of those
        // fetches fails, we won't re-emit the same events on the next
        // poll — the RPC will hand us newer ones only.
        if let Some(newest) = sigs.last() {
            CURSOR.with(|c| *c.borrow_mut() = Some(newest.signature.clone()));
        }

        for sig_entry in sigs {
            let tx_resp = match rpc_get_transaction(cfg, &sig_entry.signature) {
                Ok(v) => v,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        &format!("getTransaction {} failed: {e}", &sig_entry.signature),
                    );
                    continue;
                }
            };
            let events = extract_inbounds(
                &tx_resp,
                &sig_entry.signature,
                &cfg.watched_address,
                cfg.include_transfers,
                sig_entry.block_time_secs,
            );
            for ev in events {
                BUFFER.with(|b| b.borrow_mut().push_back(ev));
            }
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
            channel_alias: None,
            timestamp: inb.timestamp_ms,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    // ── RPC helpers ────────────────────────────────────────────────────

    fn post_rpc(url: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .map_err(|e| e.to_string())
    }

    fn rpc_get_signatures(cfg: &Config, until: Option<&str>) -> Result<Value, String> {
        let mut params_options = serde_json::Map::new();
        params_options.insert("limit".to_string(), json!(cfg.max_sigs_per_poll));
        params_options.insert("commitment".to_string(), json!(cfg.commitment));
        if let Some(u) = until {
            params_options.insert("until".to_string(), json!(u));
        }
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [cfg.watched_address, Value::Object(params_options)],
        });
        post_rpc(&cfg.rpc_url, &body)
    }

    fn rpc_get_transaction(cfg: &Config, signature: &str) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "encoding": "jsonParsed",
                    "commitment": cfg.commitment,
                    "maxSupportedTransactionVersion": 0
                }
            ],
        });
        post_rpc(&cfg.rpc_url, &body)
    }

    fn rpc_health(cfg: &Config) -> Result<bool, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "getHealth"
        });
        let resp = post_rpc(&cfg.rpc_url, &body)?;
        // "ok" means healthy; anything else (including RPC errors returned
        // as `{ error: ... }`) is "unhealthy".
        Ok(resp.get("result").and_then(|r| r.as_str()) == Some("ok"))
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_inbox::channel".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaInbox);
}
