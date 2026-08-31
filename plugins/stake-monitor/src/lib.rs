//! ZeroClaw WIT tool plugin: `stake_monitor`.
//!
//! Read-only status for the operator's own stake accounts: delegation state,
//! validator health from vote lag through formal delinquency, epoch progress,
//! and last-epoch rewards, shaped for chat. The pure core lives in [`stake`]
//! with no wasm dependency, so it compiles and tests on the host with a plain
//! `cargo test`; the wasm component reuses the same logic through the shim
//! below.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod stake;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::Duration;

    use crate::stake::{
        self, derive_status, render_payload, Config, Entry, StakeStatus, ValidatorStatus,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct StakeMonitor;

    const TOOL_NAME: &str = "stake_monitor";

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        #[serde(default)]
        account: Option<String>,
        /// The host merges this plugin's validated config object into the
        /// call arguments under the reserved `__config` key, after deleting
        /// any model-supplied value of that name. It is captured as a raw
        /// `Value` so a config-shaped problem is reported as a config error
        /// rather than collapsing the whole argument parse into "invalid
        /// arguments".
        #[serde(rename = "__config", default)]
        config: serde_json::Value,
    }

    impl PluginInfo for StakeMonitor {
        fn plugin_name() -> String {
            env!("CARGO_PKG_NAME").to_string()
        }

        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Tool for StakeMonitor {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Read-only status for the operator's own Solana stake accounts: delegation \
             state, stake amount, validator health (vote lag and delinquency), epoch \
             progress, and last-epoch reward. Accounts come from the plugin config \
             allowlist; arbitrary addresses are refused."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "account": {
                        "type": "string",
                        "description": "Optional stake account label or pubkey from the configured allowlist. Omit for all configured accounts."
                    }
                },
                "required": []
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return fail(format!("invalid arguments: {e}")),
            };

            let cfg = match Config::from_json(&parsed.config) {
                Ok(c) => c,
                Err(e) => return fail(format!("config error: {e}")),
            };

            let accounts = match cfg.resolve_account(parsed.account.as_deref()) {
                Ok(a) => a,
                Err(e) => return fail(e),
            };

            let timeout = Duration::from_secs(cfg.timeout_secs);
            let rpc = |body: &str| post_json(&cfg.rpc_url, body, timeout);

            // One head-slot reading for the whole run: every vote lag below is
            // measured against this slot, so a long multi-account report can
            // under-report the lag of its later accounts by however far the
            // chain moved in the meantime.
            let epoch =
                match rpc(&stake::epoch_info_body()).and_then(|b| stake::parse_epoch_info(&b)) {
                    Ok(e) => e,
                    Err(e) => return fail(format!("epoch info failed: {e}")),
                };

            let mut issues: Vec<String> = Vec::new();
            let mut entries: Vec<Entry> = Vec::new();

            for account in &accounts {
                let state = match rpc(&stake::stake_account_body(&account.pubkey))
                    .and_then(|b| stake::parse_stake_account(&b))
                {
                    Ok(s) => s,
                    Err(e) => {
                        issues.push(format!("{}: {e}", account.label));
                        continue;
                    }
                };
                let status = derive_status(state.delegation.as_ref(), epoch.epoch);
                let validator = match &state.delegation {
                    Some(d) => match rpc(&stake::vote_account_body(&d.voter))
                        .and_then(|b| stake::parse_vote_status(&b, &d.voter))
                    {
                        Ok(v) => Some(v),
                        Err(e) => {
                            issues.push(format!("{} validator: {e}", account.label));
                            Some(ValidatorStatus::Unknown)
                        }
                    },
                    None => None,
                };
                entries.push(Entry {
                    label: account.label.clone(),
                    state,
                    status,
                    validator,
                    // Unread until the batched reward call below answers for
                    // this row; a run that never gets that far leaves it here.
                    reward: None,
                });
            }

            if entries.is_empty() {
                return fail(stake::render_total_failure(&issues));
            }

            // Rewards land one epoch behind, so ask for the previous one.
            if epoch.epoch > 0 {
                let pubkeys: Vec<String> = accounts
                    .iter()
                    .filter(|a| entries.iter().any(|e| e.label == a.label))
                    .map(|a| a.pubkey.clone())
                    .collect();
                match rpc(&stake::inflation_reward_body(&pubkeys, epoch.epoch - 1))
                    .and_then(|b| stake::parse_inflation_rewards(&b, pubkeys.len()))
                {
                    Ok(rewards) => {
                        // The outer `Some` records that the read happened at
                        // all; the inner option is the epoch's own answer. Rows
                        // left at `None` above are the ones no reply covered,
                        // and they render as unknown rather than as zero.
                        for (entry, reward) in entries.iter_mut().zip(rewards) {
                            entry.reward = Some(reward);
                        }
                    }
                    Err(e) => issues.push(format!("rewards: {e}")),
                }
            }

            // Rows and failed reads are capped together: the char cap covers
            // the whole delivered payload, not just the part above the
            // data-issues line.
            let report = render_payload(&entries, &epoch, &cfg, &issues);

            let delinquent = entries
                .iter()
                .filter(|e| matches!(e.validator, Some(ValidatorStatus::Delinquent { .. })))
                .count();
            let behind = entries
                .iter()
                .filter(|e| {
                    e.validator
                        .as_ref()
                        .is_some_and(|v| v.is_behind(epoch.absolute_slot, cfg.vote_lag_warn_slots))
                })
                .count();
            let deactivating = entries
                .iter()
                .filter(|e| e.status == StakeStatus::Deactivating)
                .count();
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                &format!(
                    "reported {} account(s), {delinquent} delinquent validator(s), {behind} behind, {deactivating} deactivating",
                    entries.len()
                ),
            );

            Ok(ToolResult {
                success: true,
                output: report,
                error: None,
            })
        }
    }

    /// Turns a raw wasi-http failure into something an operator can act on.
    ///
    /// Plugins reach the network through `wasmtime-wasi-http`, whose bundled
    /// request path trusts the webpki root set rather than the machine's own
    /// certificate store. Antivirus HTTPS inspection (Avast, AVG, Kaspersky,
    /// ESET) and corporate TLS-inspecting proxies present a certificate signed
    /// by a CA they install into the OS store, which that root set does not
    /// contain, so every outbound call fails. The bare code says nothing, and
    /// the same machine's browser reaches the endpoint fine, which makes the
    /// plugin look broken when the cause is entirely outside it.
    fn explain_request_error(e: impl std::fmt::Display) -> String {
        let raw = e.to_string();
        if raw.contains("TlsProtocolError") {
            return format!(
                "{raw} (TLS refused: likely antivirus HTTPS inspection or a TLS-inspecting proxy, whose CA this runtime does not trust)"
            );
        }
        raw
    }

    fn post_json(url: &str, body: &str, timeout: Duration) -> Result<String, String> {
        let response = waki::Client::new()
            .post(url)
            .connect_timeout(timeout)
            .header("Content-Type", "application/json")
            .body(body.as_bytes().to_vec())
            .send()
            .map_err(|e| format!("request failed: {}", explain_request_error(e)))?;
        let status = response.status_code();
        let bytes = response
            .body()
            .map_err(|e| format!("response read failed: {e}"))?;
        if status != 200 {
            return Err(format!("HTTP {status}"));
        }
        String::from_utf8(bytes).map_err(|_| "response is not UTF-8".to_string())
    }

    fn fail(message: String) -> Result<ToolResult, String> {
        // The same 900-character bound the report path carries. Several failure
        // messages interpolate a value the caller supplied, so without this the
        // failure path is the wider door into the agent's context.
        let message = crate::stake::cap_failure(message);
        emit(PluginAction::Fail, PluginOutcome::Failure, &message);
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "stake_monitor::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(StakeMonitor);
}
