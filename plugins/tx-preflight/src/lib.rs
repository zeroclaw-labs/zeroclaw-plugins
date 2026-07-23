//! `tx-preflight`: show a human what a transaction will actually do, before
//! they approve it.
//!
//! Custody tier: **T1**. Holds no key, signs nothing, submits nothing. It
//! reads chain state and returns a verdict.
//!
//! The problem it exists for: an agent that builds a transaction and asks for
//! approval hands the human a description the language model wrote. Poison the
//! model and the approval card reads "refund the customer 25 USDC" while the
//! bytes underneath move 2,140 and install a delegate. Cupel simulates the
//! transaction against the operator's own RPC and reports the observed effect,
//! so the human approves arithmetic rather than prose.

pub mod args;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use cupel_core::{preflight, Envelope, Transport};

    use crate::args::{parse_args, settings_from_config};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TxPreflight;

    const PLUGIN_NAME: &str = "tx-preflight";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    /// `wasi:http` through the host, granted by the `http_client` permission.
    /// TLS terminates host-side; the component never sees a certificate.
    struct WakiTransport;

    impl Transport for WakiTransport {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let response = waki::Client::new()
                .post(url)
                .headers([("Content-Type", "application/json")])
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("request failed: {e}"))?;

            let status = response.status_code();
            let bytes = response
                .body()
                .map_err(|e| format!("could not read response: {e}"))?;

            if !(200..300).contains(&status) {
                return Err(format!("RPC returned {status}"));
            }

            String::from_utf8(bytes).map_err(|e| format!("response was not UTF-8: {e}"))
        }
    }

    impl PluginInfo for TxPreflight {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TxPreflight {
        fn name() -> String {
            "solana_tx_preflight".to_string()
        }

        fn description() -> String {
            // The relay instruction is deliberate. execute() returns to the
            // model, and the model decides what the human sees; a paraphrased
            // FAIL is the one hole this plugin cannot close by itself.
            "Simulate a Solana transaction and report what it will actually do: net amounts \
             moved, authorities granted, accounts closed, and whether it stays inside the \
             operator's configured limits. Call this before asking a human to approve or sign \
             any transaction. Relay the returned block to the user verbatim and never \
             summarise, reword, or shorten it."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "transaction": {
                        "type": "string",
                        "description": "The transaction to check, base64-encoded. Signed or unsigned."
                    }
                },
                "required": ["transaction"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let (request, config) = match parse_args(&args) {
                Ok(parsed) => parsed,
                Err(e) => return Ok(refuse(&e)),
            };

            let settings = match settings_from_config(&config) {
                Ok(s) => s,
                Err(e) => return Ok(refuse(&e)),
            };

            // A misconfigured envelope is not a reason to pass everything.
            let envelope = match Envelope::from_config(&config) {
                Ok(e) => e,
                Err(e) => return Ok(refuse(&e)),
            };

            let report = preflight(
                &WakiTransport,
                &settings.rpc_url,
                &request.transaction,
                &envelope,
                settings.owner,
            );

            let signable = report.is_signable();

            emit(
                if signable {
                    PluginAction::Approve
                } else {
                    PluginAction::Reject
                },
                if signable {
                    PluginOutcome::Success
                } else {
                    PluginOutcome::Failure
                },
                if signable {
                    "transaction is inside the envelope"
                } else {
                    "transaction refused"
                },
            );

            // A FAIL verdict is a *successful* verification with a negative
            // result. Reporting it as a tool failure makes the host discard
            // `output` and surface only the first line, throwing away the one
            // thing the human needs to read. The verdict word carries the
            // decision; the tool call itself succeeded either way.
            Ok(ToolResult {
                success: true,
                output: report.render(),
                error: None,
            })
        }
    }

    /// Anything we could not check is reported in the same shape as anything we
    /// checked and rejected: a rendered block, delivered intact.
    fn refuse(reason: &str) -> ToolResult {
        emit(
            PluginAction::Reject,
            PluginOutcome::Failure,
            "could not verify",
        );
        ToolResult {
            success: true,
            output: cupel_core::Report::unverifiable(reason).render(),
            error: None,
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "tx_preflight::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(TxPreflight);
}
