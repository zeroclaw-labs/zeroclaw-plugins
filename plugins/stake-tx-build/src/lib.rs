//! ZeroClaw WIT tool plugin: `stake_tx_build`.
//!
//! Builds an unsigned legacy Solana transaction that delegates or
//! deactivates one of the operator's allowlisted stake accounts, returned
//! as base64 with a human summary for the approval gate. The genesis hash the
//! endpoint reports is checked against the pinned cluster before anything is
//! built, which catches an honest endpoint on the wrong chain. The
//! plugin holds no keys and cannot sign or submit; a human wallet does both.
//! The pure core lives in [`txbuild`] with no wasm dependency, so it compiles
//! and tests on the host with a plain `cargo test`; the wasm component reuses
//! the same logic through the shim below.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod txbuild;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::Duration;

    use crate::txbuild::{self, build_transaction, parse_action, validate_vote, Config};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct StakeTxBuild;

    const TOOL_NAME: &str = "stake_tx_build";

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        action: String,
        stake_account: String,
        #[serde(default)]
        vote_account: Option<String>,
        /// The host merges this plugin's validated config object into the
        /// call arguments under the reserved `__config` key, after deleting
        /// any model-supplied value of that name. It is captured as a raw
        /// `Value` so a config-shaped problem is reported as a config error
        /// rather than collapsing the whole argument parse into "invalid
        /// arguments".
        #[serde(rename = "__config", default)]
        config: serde_json::Value,
    }

    impl PluginInfo for StakeTxBuild {
        fn plugin_name() -> String {
            env!("CARGO_PKG_NAME").to_string()
        }

        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Tool for StakeTxBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Builds an UNSIGNED Solana stake transaction (delegate or deactivate) for a \
             stake account from the configured allowlist, returned as base64 for the \
             operator to review and sign in their own wallet. Delegation targets come \
             from a second operator allowlist. This component holds no key material and \
             cannot sign or submit anything."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["delegate", "deactivate"],
                        "description": "Transaction to build: delegate stake to a vote account, or deactivate the stake."
                    },
                    "stake_account": {
                        "type": "string",
                        "description": "Stake account label or pubkey from the configured allowlist."
                    },
                    "vote_account": {
                        "type": "string",
                        "description": "Delegation target vote account pubkey; required for delegate and must be in the configured allowed_vote_accounts allowlist. Omit for deactivate."
                    }
                },
                "required": ["action", "stake_account"]
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

            let action = match parse_action(&parsed.action) {
                Ok(a) => a,
                Err(e) => return fail(e),
            };

            let stake = match cfg.resolve_stake(&parsed.stake_account) {
                Ok(s) => s,
                Err(e) => return fail(e),
            };

            let vote = match validate_vote(&cfg, action, parsed.vote_account.as_deref()) {
                Ok(v) => v,
                Err(e) => return fail(e),
            };

            let timeout = Duration::from_secs(cfg.timeout_secs);

            // Cluster identity gate: one getGenesisHash read per invocation,
            // before any transaction bytes exist. An endpoint reporting a
            // genesis other than the pinned cluster aborts the call here,
            // which catches an honest endpoint on the wrong chain. An
            // endpoint that echoes the expected hash still passes; the limits
            // are spelled out in the README threat model.
            let genesis = match post_json(&cfg.rpc_url, &txbuild::genesis_hash_body(), timeout)
                .and_then(|b| txbuild::parse_genesis_hash(&b))
            {
                Ok(g) => g,
                Err(e) => return fail(format!("cluster check failed: {e}")),
            };
            if let Err(e) = txbuild::verify_cluster(cfg.cluster, &genesis) {
                return fail(e);
            }

            // Durable path: the blockhash slot is filled from the nonce
            // account state instead of the recent blockhash queue.
            let blockhash = match &cfg.nonce {
                Some(nonce) => {
                    match post_json(
                        &cfg.rpc_url,
                        &txbuild::nonce_account_body(&nonce.account),
                        timeout,
                    )
                    .and_then(|b| txbuild::parse_nonce_blockhash(&b, &nonce.authority))
                    {
                        Ok(h) => h,
                        Err(e) => return fail(format!("nonce account read failed: {e}")),
                    }
                }
                None => {
                    match post_json(&cfg.rpc_url, &txbuild::latest_blockhash_body(), timeout)
                        .and_then(|b| txbuild::parse_latest_blockhash(&b))
                    {
                        Ok(h) => h,
                        Err(e) => return fail(format!("blockhash fetch failed: {e}")),
                    }
                }
            };

            // Delegation-target standing. The allowlist is what enforces which
            // validators are acceptable, and it is static: a validator added
            // months ago can have stopped voting since. This read tells the
            // operator that before they sign, and it deliberately does not
            // refuse. A failed read is reported as unread rather than swallowed,
            // so a network problem never reads as a clean bill of health.
            let standing = vote.as_deref().map(|v| {
                match post_json(&cfg.rpc_url, &txbuild::vote_account_body(v), timeout)
                    .and_then(|b| txbuild::parse_voter_standing(&b, v))
                {
                    Ok(s) => s,
                    Err(_) => txbuild::VoterStanding::Unread,
                }
            });

            // The mirror of the check above, on the other action. A deactivate
            // against a stake that already has one recorded is rejected by the
            // Stake program with AlreadyDeactivated, and without this read the
            // operator finds that out only after signing and paying the fee.
            // Reproduced on devnet during the acceptance run.
            let stake_standing = match action {
                txbuild::Action::Deactivate => Some(
                    match post_json(
                        &cfg.rpc_url,
                        &txbuild::stake_account_body(&stake.pubkey),
                        timeout,
                    )
                    .and_then(|b| txbuild::parse_stake_standing(&b))
                    {
                        Ok(s) => s,
                        Err(_) => txbuild::StakeStanding::Unread,
                    },
                ),
                txbuild::Action::Delegate => None,
            };

            let built = match build_transaction(
                &cfg,
                action,
                stake,
                vote.as_deref(),
                blockhash,
                standing,
                stake_standing,
            ) {
                Ok(b) => b,
                Err(e) => return fail(format!("transaction build failed: {e}")),
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                &format!(
                    "built unsigned {} transaction for `{}`",
                    action.as_str(),
                    stake.label
                ),
            );

            Ok(ToolResult {
                success: true,
                output: built.output(),
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
                function_name: "stake_tx_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(StakeTxBuild);
}
