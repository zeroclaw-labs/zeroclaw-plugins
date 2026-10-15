//! Matrix text-only component. Policy and credentials are resolved per call.
pub mod matrix;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/current",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::matrix::{self, Inbound, MatrixConfig, Session, CHANNEL, MAX_BODY, MAX_TEXT};
    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage, WebhookRejection, WebhookRequest, WebhookResponse,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use serde_json::Value;
    use std::cell::RefCell;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use zeroclaw::plugin::logging::{self, LogLevel, PluginAction, PluginEvent, PluginOutcome};
    use zeroclaw::plugin::{config, secrets};

    struct Runtime {
        session: Session,
        transaction: u64,
        retry_at: Option<Instant>,
        retry_secs: u64,
    }
    thread_local! {
        static INSTANCE: RefCell<Option<Runtime>> = const { RefCell::new(None) };
    }
    fn with_state<T>(f: impl FnOnce(&mut Runtime) -> T) -> Result<T, String> {
        INSTANCE
            .with(|cell| cell.borrow_mut().as_mut().map(f))
            .ok_or_else(|| "matrix: fresh configure required".into())
    }

    // Adapted locally from Discord's wasi:http shim. Nonblocking streams and
    // timer pollables enforce one aggregate deadline, including body writes.
    mod http {
        use crate::matrix::split_http_url;
        use std::time::{Duration, Instant};
        use wasip2::clocks::monotonic_clock;
        use wasip2::http::{
            outgoing_handler,
            types::{
                Fields, IncomingBody, Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme,
            },
        };
        use wasip2::io::{
            poll::{self, Pollable},
            streams::StreamError,
        };

        pub struct Budget {
            deadline: Instant,
            bytes_left: usize,
        }
        impl Budget {
            pub fn new(seconds: u64) -> Self {
                Self {
                    deadline: Instant::now() + Duration::from_secs(seconds),
                    bytes_left: 1024 * 1024,
                }
            }
            fn remaining(&self) -> Result<Duration, String> {
                self.deadline
                    .checked_duration_since(Instant::now())
                    .filter(|d| !d.is_zero())
                    .ok_or_else(|| "matrix: HTTP deadline exceeded".into())
            }
            fn charge(&mut self, bytes: usize) -> Result<(), String> {
                self.bytes_left = self
                    .bytes_left
                    .checked_sub(bytes)
                    .ok_or("matrix: HTTP byte budget exceeded")?;
                Ok(())
            }
            fn wait(&self, ready: &Pollable) -> Result<(), String> {
                let nanos = u64::try_from(self.remaining()?.as_nanos()).unwrap_or(u64::MAX);
                let timer = monotonic_clock::subscribe_duration(nanos);
                let _ = poll::poll(&[ready, &timer]);
                self.remaining().map(|_| ())
            }
        }

        pub fn request(
            method: Method,
            url: &str,
            token: &str,
            body: Option<&[u8]>,
            max_body: usize,
            budget: &mut Budget,
        ) -> Result<(u16, Vec<u8>), String> {
            budget.remaining()?;
            let target = split_http_url(url).ok_or("matrix: invalid HTTP target")?;
            let headers = Fields::from_list(&[
                (
                    "authorization".into(),
                    format!("Bearer {token}").into_bytes(),
                ),
                ("accept".into(), b"application/json".to_vec()),
                ("content-type".into(), b"application/json".to_vec()),
            ])
            .map_err(|_| "matrix: invalid HTTP headers")?;
            let request = OutgoingRequest::new(headers);
            let scheme = if target.https {
                Scheme::Https
            } else {
                Scheme::Http
            };
            request
                .set_method(&method)
                .and_then(|()| request.set_scheme(Some(&scheme)))
                .and_then(|()| request.set_authority(Some(target.authority)))
                .and_then(|()| request.set_path_with_query(Some(target.path_with_query)))
                .map_err(|()| "matrix: HTTP target refused")?;
            let options = RequestOptions::new();
            let timeout = |secs| {
                u64::try_from(
                    budget
                        .remaining()
                        .unwrap_or_default()
                        .min(Duration::from_secs(secs))
                        .as_nanos(),
                )
                .unwrap_or(u64::MAX)
            };
            options
                .set_connect_timeout(Some(timeout(2)))
                .map_err(|_| "matrix: HTTP timeout refused")?;
            options
                .set_first_byte_timeout(Some(timeout(3)))
                .map_err(|_| "matrix: HTTP timeout refused")?;
            options
                .set_between_bytes_timeout(Some(timeout(1)))
                .map_err(|_| "matrix: HTTP timeout refused")?;
            let outgoing = request
                .body()
                .map_err(|()| "matrix: HTTP body unavailable")?;
            let future = outgoing_handler::handle(request, Some(options))
                .map_err(|_| "matrix: HTTP transport refused")?;
            if let Some(bytes) = body {
                budget.charge(bytes.len())?;
                let stream = outgoing
                    .write()
                    .map_err(|()| "matrix: HTTP output unavailable")?;
                let mut offset = 0;
                while offset < bytes.len() {
                    budget.remaining()?;
                    let quota = stream
                        .check_write()
                        .map_err(|_| "matrix: HTTP write failed")?;
                    let size = (bytes.len() - offset).min(4096).min(quota as usize);
                    if size == 0 {
                        budget.wait(&stream.subscribe())?;
                        continue;
                    }
                    stream
                        .write(&bytes[offset..offset + size])
                        .map_err(|_| "matrix: HTTP write failed")?;
                    offset += size;
                }
                stream.flush().map_err(|_| "matrix: HTTP flush failed")?;
                loop {
                    budget.remaining()?;
                    if stream
                        .check_write()
                        .map_err(|_| "matrix: HTTP flush failed")?
                        > 0
                    {
                        break;
                    }
                    budget.wait(&stream.subscribe())?;
                }
            }
            OutgoingBody::finish(outgoing, None).map_err(|_| "matrix: HTTP finish failed")?;
            let response = loop {
                budget.remaining()?;
                if let Some(result) = future.get() {
                    break result;
                }
                budget.wait(&future.subscribe())?;
            }
            .map_err(|()| "matrix: HTTP response already taken")?
            .map_err(|_| "matrix: HTTP transport failed")?;
            let status = response.status();
            let incoming = response
                .consume()
                .map_err(|()| "matrix: HTTP response unavailable")?;
            let stream = incoming
                .stream()
                .map_err(|()| "matrix: HTTP input unavailable")?;
            let mut bytes = Vec::new();
            loop {
                budget.remaining()?;
                match stream.read((max_body + 1 - bytes.len()).min(8192) as u64) {
                    Ok(chunk) if chunk.is_empty() => budget.wait(&stream.subscribe())?,
                    Ok(chunk) => {
                        budget.charge(chunk.len())?;
                        bytes.extend_from_slice(&chunk);
                        if bytes.len() > max_body {
                            return Err("matrix: HTTP response too large".into());
                        }
                    }
                    Err(StreamError::Closed) => break,
                    Err(_) => return Err("matrix: HTTP response incomplete".into()),
                }
            }
            // Child stream must be dropped before its parent body.
            drop(stream);
            let completion = IncomingBody::finish(incoming);
            loop {
                budget.remaining()?;
                if let Some(result) = completion.get() {
                    let trailers = result
                        .map_err(|()| "matrix: HTTP completion already taken")?
                        .map_err(|_| "matrix: HTTP response incomplete")?;
                    drop(trailers);
                    break;
                }
                budget.wait(&completion.subscribe())?;
            }
            Ok((status, bytes))
        }
    }
    use http::Budget;
    use wasip2::http::types::Method;

    fn public_config() -> Result<MatrixConfig, String> {
        MatrixConfig::from_public_json(&config::get().map_err(|_| "matrix: config unavailable")?)
    }
    fn token() -> Result<String, String> {
        let token = secrets::get("access_token").map_err(|_| "matrix: access_token unavailable")?;
        if token.is_empty() || token.len() > 8192 || token.chars().any(char::is_control) {
            return Err("matrix: invalid access_token".into());
        }
        Ok(token)
    }
    fn json_get(
        url: &str,
        token: &str,
        max_body: usize,
        budget: &mut Budget,
    ) -> Result<Value, String> {
        let (status, bytes) = http::request(Method::Get, url, token, None, max_body, budget)?;
        if status != 200 {
            return Err(format!("matrix: HTTP GET status {status}"));
        }
        serde_json::from_slice(&bytes).map_err(|_| "matrix: invalid response JSON".into())
    }
    fn identity(cfg: &MatrixConfig, token: &str, budget: &mut Budget) -> Result<String, String> {
        let value = json_get(
            &matrix::whoami_url(cfg.homeserver()),
            token,
            16 * 1024,
            budget,
        )?;
        matrix::parse_whoami(&value).ok_or_else(|| "matrix: invalid authenticated identity".into())
    }
    fn current() -> Result<(MatrixConfig, String), String> {
        let cfg = public_config()?;
        with_state(|state| {
            let id = state.session.self_id.clone();
            state.session.check_binding(&cfg, &id)
        })??;
        Ok((cfg, token()?))
    }
    fn authenticate(cfg: &MatrixConfig, token: &str, budget: &mut Budget) -> Result<(), String> {
        let id = identity(cfg, token, budget)?;
        with_state(|state| state.session.check_binding(cfg, &id))?
    }
    fn report_failure(function: &str, error: &str) {
        // All callers supply closed local classes or numeric HTTP statuses.
        logging::log_record(
            LogLevel::Warn,
            &PluginEvent {
                function_name: format!("matrix::{function}"),
                action: PluginAction::Fail,
                outcome: Some(PluginOutcome::Failure),
                duration_ms: None,
                attrs: None,
                message: error.to_string(),
            },
        );
    }
    fn to_wit(message: Inbound) -> InboundMessage {
        InboundMessage {
            id: message.id,
            sender: message.sender,
            reply_target: message.reply_target,
            content: message.content,
            channel: CHANNEL.into(),
            channel_alias: None,
            timestamp: message.timestamp,
            thread_ts: message.thread_ts,
            interruption_scope_id: message.interruption_scope_id,
            attachments: Vec::new(),
            subject: None,
        }
    }
    fn poll() -> Result<Option<InboundMessage>, String> {
        let mut budget = Budget::new(25);
        let (cfg, token) = current()?;
        if with_state(|state| state.retry_at.is_some_and(|at| Instant::now() < at))? {
            return Ok(None);
        }
        authenticate(&cfg, &token, &mut budget)?;
        if let Some(message) = with_state(|state| state.session.next(&cfg))? {
            return Ok(Some(to_wit(message)));
        }
        let since = with_state(|state| state.session.since.clone())?;
        let value = json_get(
            &matrix::sync_url(cfg.homeserver(), since.as_deref()),
            &token,
            MAX_BODY,
            &mut budget,
        )?;
        with_state(|state| {
            state.session.ingest(&value, &cfg)?;
            state.retry_at = None;
            state.retry_secs = 1;
            Ok(state.session.next(&cfg).map(to_wit))
        })?
    }

    struct MatrixChannel;
    impl PluginInfo for MatrixChannel {
        fn plugin_name() -> String {
            CHANNEL.into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }
    impl Channel for MatrixChannel {
        fn name() -> String {
            CHANNEL.into()
        }
        fn configure() -> Result<(), String> {
            INSTANCE.with(|cell| *cell.borrow_mut() = None);
            let mut budget = Budget::new(7);
            let cfg = public_config()?;
            let id = identity(&cfg, &token()?, &mut budget)?;
            let mut session = Session::new(&cfg, id.clone());
            session.check_binding(&cfg, &id)?;
            let transaction = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1);
            INSTANCE.with(|cell| {
                *cell.borrow_mut() = Some(Runtime {
                    session,
                    transaction,
                    retry_at: None,
                    retry_secs: 1,
                })
            });
            Ok(())
        }
        fn send(message: SendMessage) -> Result<(), String> {
            let mut budget = Budget::new(25);
            if !message.attachments.is_empty() {
                return Err("matrix: attachments unsupported".into());
            }
            if message.content.len() > MAX_TEXT {
                return Err("matrix: message too large".into());
            }
            let (cfg, token) = current()?;
            authenticate(&cfg, &token, &mut budget)?;
            let room = if matrix::matrix_id(&message.recipient, '!') {
                message.recipient
            } else if matrix::matrix_id(&message.recipient, '#') {
                let value = json_get(
                    &matrix::room_alias_url(cfg.homeserver(), &message.recipient),
                    &token,
                    16 * 1024,
                    &mut budget,
                )?;
                matrix::parse_room_id(&value).ok_or("matrix: invalid alias resolution")?
            } else {
                return Err("matrix: invalid recipient".into());
            };
            let body = matrix::build_send_body(
                &message.content,
                message.thread_ts.as_deref(),
                cfg.reply_in_thread,
            )
            .to_string();
            if body.len() > MAX_TEXT {
                return Err("matrix: send body too large".into());
            }
            let transaction = with_state(|state| {
                let id = state.transaction;
                state.transaction = id.wrapping_add(1);
                id
            })?;
            // No cached room permission. The GET and PUT are necessarily non-atomic.
            let (status, bytes) = http::request(
                Method::Get,
                &matrix::encryption_url(cfg.homeserver(), &room),
                &token,
                None,
                16 * 1024,
                &mut budget,
            )?;
            matrix::require_unencrypted(status, &bytes)?;
            let (status, _) = http::request(
                Method::Put,
                &matrix::send_url(cfg.homeserver(), &room, transaction),
                &token,
                Some(body.as_bytes()),
                16 * 1024,
                &mut budget,
            )?;
            if status != 200 {
                return Err(format!("matrix: HTTP PUT status {status}"));
            }
            Ok(())
        }
        fn poll_message() -> Option<InboundMessage> {
            match poll() {
                Ok(message) => message,
                Err(error) => {
                    let report = with_state(|state| {
                        state.session.sync_failed = true;
                        if state.retry_at.is_some_and(|at| Instant::now() < at) {
                            return false;
                        }
                        state.retry_at =
                            Some(Instant::now() + Duration::from_secs(state.retry_secs));
                        state.retry_secs = (state.retry_secs * 2).min(30);
                        true
                    })
                    .unwrap_or(true);
                    if report {
                        report_failure("poll", &error);
                    }
                    None
                }
            }
        }
        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
                | ChannelCapabilities::SELF_HANDLE
                | ChannelCapabilities::SELF_ADDRESSED_MENTION
        }
        fn health_check() -> bool {
            let result = (|| {
                let mut budget = Budget::new(7);
                let (cfg, token) = current()?;
                authenticate(&cfg, &token, &mut budget)?;
                with_state(|state| state.session.healthy())
            })();
            match result {
                Ok(healthy) => healthy,
                Err(error) => {
                    report_failure("health", &error);
                    false
                }
            }
        }
        // Static host metadata is read outside config/secrets service frames.
        fn self_handle() -> Option<String> {
            with_state(|s| s.session.self_id.clone()).ok()
        }
        fn self_addressed_mention() -> Option<String> {
            Self::self_handle()
        }
        fn drop_self_message(_message: InboundMessage) -> bool {
            false
        }
        fn start_typing(_r: String) -> Result<(), String> {
            Ok(())
        }
        fn stop_typing(_r: String) -> Result<(), String> {
            Ok(())
        }
        fn supports_draft_updates() -> bool {
            false
        }
        fn send_draft(_m: SendMessage) -> Result<Option<String>, String> {
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
        fn redact_message(_c: String, _m: String, _r: Option<String>) -> Result<(), String> {
            Ok(())
        }
        fn request_approval(
            _r: String,
            _a: ApprovalRequest,
        ) -> Result<Option<ApprovalResponse>, String> {
            Ok(None)
        }
        fn request_choice(_q: String, _c: Vec<String>, _t: u64) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn supports_free_form_ask() -> bool {
            true
        }
        fn webhook_path() -> Option<String> {
            None
        }
        fn parse_webhook(_request: WebhookRequest) -> Result<WebhookResponse, WebhookRejection> {
            Err(WebhookRejection::BadRequest(
                "matrix does not serve webhooks".into(),
            ))
        }
    }
    export!(MatrixChannel);
}
