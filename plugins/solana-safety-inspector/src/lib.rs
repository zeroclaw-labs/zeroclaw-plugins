//! ZeroClaw WIT tool plugin: `solana-safety-inspector`.
//!
//! Memeriksa keamanan token Solana (SPL Token) langsung ke jaringan blockchain (on-chain).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod inspector;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::inspector::parse_rpc_response;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaSafetyInspector;

    const PLUGIN_NAME: &str = "solana-safety-inspector";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_safety_inspector";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolanaSafetyInspector {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaSafetyInspector {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Memeriksa keamanan dasar suatu token Solana (SPL Token) di blockchain secara waktu nyata. \
             Berguna untuk mendeteksi apakah mint authority sudah dimatikan dan freeze authority dinonaktifkan."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Alamat kontrak token Solana (Mint Address) yang ingin diperiksa keamanannya."
                    }
                },
                "required": ["mint"]
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

            // Baca RPC URL dari konfigurasi, atau gunakan RPC publik utama Solana jika tidak dikonfigurasi
            let rpc_url = parsed
                .config
                .get("rpc_url")
                .map(|s| s.as_str())
                .unwrap_or("https://api.mainnet-beta.solana.com");

            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                &format!("Memulai pemeriksaan token {} menggunakan RPC {}", parsed.mint, rpc_url),
            );

            // Menyiapkan format payload standar Solana JSON-RPC getAccountInfo
            let req_body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [
                    parsed.mint,
                    { "encoding": "jsonParsed" }
                ]
            });

            // Melakukan HTTP POST menggunakan waki (WASI Outbound HTTP Client)
            let client = waki::Client::new();
            let mut req = client.post(rpc_url)
                .header("Content-Type", "application/json")
                .connect_timeout(std::time::Duration::from_secs(10));

            let resp = match req.json(&req_body).send() {
                Ok(r) => r,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        &format!("Koneksi HTTP ke Solana RPC gagal: {e}"),
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Gagal menghubungi blockchain Solana: {e}")),
                    });
                }
            };

            let status = resp.status_code();
            if !(200..300).contains(&status) {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    &format!("RPC merespon dengan status HTTP tidak sukses: {status}"),
                );
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Solana RPC mengembalikan kode kesalahan HTTP {status}")),
                });
            }

            // Membaca respon dalam format JSON secara aman menggunakan waki
            let json_val: serde_json::Value = match resp.json() {
                Ok(v) => v,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "Gagal mengurai respon JSON dari RPC",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Gagal membaca data JSON dari RPC: {e}")),
                    });
                }
            };

            let text_body = json_val.to_string();

            // Membedah data respon menggunakan logika murni di modul inspector kita
            match parse_rpc_response(&parsed.mint, &text_body) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "Pemeriksaan keamanan token selesai dengan sukses",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report.message,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        &format!("Gagal menganalisis struktur data token: {e}"),
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Gagal menganalisis data token: {e}")),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_safety_inspector::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaSafetyInspector);
}