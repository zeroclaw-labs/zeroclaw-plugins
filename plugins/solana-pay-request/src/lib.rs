//! solana-pay-request — ZeroClaw tool plugin (custody tier T1, Build).
//!
//! Turns "charge table 4 for 25 USDC" into a Solana Pay `solana:` URL the payer
//! scans and signs from their own wallet. The plugin holds no key, builds no
//! transaction, and touches neither the network nor config — so its manifest
//! declares zero permissions. All logic is in [`pay`], tested on the host.

pub mod pay;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::pay::{build, RequestInput};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct Component;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        recipient: String,
        /// String or number; both are accepted and normalized.
        #[serde(default)]
        amount: Option<serde_json::Value>,
        #[serde(default, alias = "mint", alias = "spl_token", alias = "spl-token")]
        spl_token: Option<String>,
        #[serde(default)]
        reference: Option<String>,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        memo: Option<String>,
    }

    fn value_to_amount(v: Option<serde_json::Value>) -> Option<String> {
        match v {
            Some(serde_json::Value::String(s)) => Some(s),
            Some(serde_json::Value::Number(n)) => Some(n.to_string()),
            _ => None,
        }
    }

    impl PluginInfo for Component {
        fn plugin_name() -> String {
            "solana-pay-request".to_string()
        }
        fn plugin_version() -> String {
            "0.1.0".to_string()
        }
    }

    impl Tool for Component {
        fn name() -> String {
            "solana_pay_request".to_string()
        }

        fn description() -> String {
            "Create a Solana Pay payment request (a `solana:` URL / QR code) so \
             someone can pay the user. Use when the user wants to charge, invoice, \
             or request a payment — e.g. 'charge table 4 for 25 USDC'. Returns a \
             scannable URL the payer approves from their OWN wallet. This tool \
             holds no keys and moves no funds; it only builds the request."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "description": "Wallet address that will RECEIVE the payment (base58)."},
                    "amount": {"type": "string", "description": "Amount in display units, e.g. \"25\" or \"0.5\". Omit to let the payer choose."},
                    "spl_token": {"type": "string", "description": "SPL token mint to charge in (e.g. USDC mint). Omit for native SOL."},
                    "memo": {"type": "string", "description": "Optional memo recorded with the payment, e.g. an invoice id."},
                    "reference": {"type": "string", "description": "Optional reference public key for reconciliation / payment-watch matching."},
                    "label": {"type": "string", "description": "Optional merchant/source label shown in the payer's wallet."},
                    "message": {"type": "string", "description": "Optional human description of the transfer."}
                },
                "required": ["recipient"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };

            let input = RequestInput {
                recipient: parsed.recipient,
                amount: value_to_amount(parsed.amount),
                spl_token: parsed.spl_token,
                references: parsed.reference.into_iter().collect(),
                label: parsed.label,
                message: parsed.message,
                memo: parsed.memo,
            };

            match build(&input) {
                Ok(req) => {
                    let url = req.to_url();
                    let output = format!(
                        "{}\nSolana Pay URL (encode as QR for the payer to scan):\n{}",
                        req.summary(),
                        url
                    );
                    log(
                        LogLevel::Info,
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "built solana pay request",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => Ok(fail(e.to_string())),
            }
        }
    }

    fn fail(msg: String) -> ToolResult {
        log(
            LogLevel::Warn,
            PluginAction::Validate,
            Some(PluginOutcome::Failure),
            &msg,
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg),
        }
    }

    fn log(level: LogLevel, action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            level,
            &PluginEvent {
                function_name: "solana_pay_request::tool::execute".into(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.into(),
            },
        );
    }

    export!(Component);
}
