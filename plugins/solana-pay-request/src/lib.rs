//! ZeroClaw WIT tool plugin: `solana-pay-request`.
//!
//! Menghasilkan tautan permintaan transaksi Solana Pay dan tautan gambar QR Code instan.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod pay;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::pay::{generate_solana_pay_url, PayRequest};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    const PLUGIN_NAME: &str = "solana-pay-request";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_pay_request";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        recipient: String,
        amount: Option<f64>,
        #[serde(rename = "spl_token")]
        spl_token: Option<String>,
        label: Option<String>,
        message: Option<String>,
        memo: Option<String>,
        #[serde(rename = "__config", default)]
        _config: HashMap<String, String>,
    }

    impl PluginInfo for SolanaPayRequest {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaPayRequest {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Menghasilkan tautan pembayaran standar Solana Pay dan QR Code gambar secara instan. \
             Menerima alamat dompet penerima (recipient), jumlah (amount), dan jenis token SPL opsional (seperti USDC)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Alamat dompet penerima Solana (Base58)."
                    },
                    "amount": {
                        "type": "number",
                        "description": "Jumlah nominal token yang ditagih (opsional)."
                    },
                    "spl_token": {
                        "type": "string",
                        "description": "Alamat Mint Token SPL opsional jika menagih koin selain SOL (misalnya USDC/USDG) (opsional)."
                    },
                    "label": {
                        "type": "string",
                        "description": "Nama pedagang atau toko untuk ditampilkan di dompet pembayar (opsional)."
                    },
                    "message": {
                        "type": "string",
                        "description": "Deskripsi atau pesan catatan tagihan untuk pembeli (opsional)."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Memo teks publik untuk disertakan dalam catatan transaksi on-chain (opsional)."
                    }
                },
                "required": ["recipient"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "argumen masukan tidak valid",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("argumen masukan tidak valid: {e}")),
                    });
                }
            };

            emit(
                PluginAction::Start,
                PluginOutcome::Success,
                &format!("Memulai pembuatan tautan Solana Pay ke {}", parsed.recipient),
            );

            let req = PayRequest {
                recipient: parsed.recipient,
                amount: parsed.amount,
                spl_token: parsed.spl_token,
                label: parsed.label,
                message: parsed.message,
                memo: parsed.memo,
            };

            match generate_solana_pay_url(&req) {
                Ok(res) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "Tautan dan QR Code Solana Pay berhasil dibuat",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: res.message,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        &format!("Gagal merancang tautan: {e}"),
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Gagal merancang tautan pembayaran: {e}")),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_pay_request::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPayRequest);
}