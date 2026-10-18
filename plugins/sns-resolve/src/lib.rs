//! ZeroClaw WIT tool plugin: `sns-resolve`.
//!
//! Resolves `.sol` / `.abc` SNS domains and validates raw Solana base58
//! addresses.  Returns the canonical 32-byte public key and input type
//! metadata.  T0 custody tier — read-only RPC calls, zero secrets.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod resolve;

// Inline base58 (needed by the WASM shim for PDA encoding)
mod base58_inline {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    static REVERSE: [u8; 128] = {
        let mut table = [0xFFu8; 128];
        let mut i = 0;
        while i < 58 { table[ALPHABET[i] as usize] = i as u8; i += 1; }
        table
    };

    #[allow(dead_code)]
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let bytes = s.as_bytes();
        let leading_ones = bytes.iter().take_while(|&&b| b == b'1').count();
        let mut buf = vec![0u8; (bytes.len() * 733 / 1000) + 2];
        let mut buf_len = 0;
        for &ch in bytes.iter().skip(leading_ones) {
            if ch > 127 { return None; }
            let digit = REVERSE[ch as usize];
            if digit == 0xFF { return None; }
            let mut carry = digit as u32;
            for idx in 0.. {
                if idx >= buf_len { buf_len = idx + 1; while buf.len() <= idx { buf.push(0); } }
                carry += (buf[idx] as u32) * 58;
                buf[idx] = (carry % 256) as u8;
                carry /= 256;
                if carry == 0 && idx + 1 >= buf_len { break; }
            }
        }
        let mut result = vec![0u8; leading_ones];
        for &byte in buf[..buf_len].iter().rev() { result.push(byte); }
        Some(result)
    }

    pub fn encode(bytes: &[u8]) -> String {
        let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
        let mut buf = vec![0u8; (bytes.len() * 138 / 100) + 2];
        let mut buf_len = 0;
        for &byte in bytes.iter().skip(leading_zeros) {
            let mut carry = byte as u32;
            for idx in 0.. {
                if idx >= buf_len { buf_len = idx + 1; while buf.len() <= idx { buf.push(0); } }
                carry += (buf[idx] as u32) << 8;
                buf[idx] = (carry % 58) as u8;
                carry /= 58;
                if carry == 0 && idx + 1 >= buf_len { break; }
            }
        }
        let mut result = String::with_capacity(leading_zeros + buf_len);
        for _ in 0..leading_zeros { result.push('1'); }
        for &digit in buf[..buf_len].iter().rev() { result.push(ALPHABET[digit as usize] as char); }
        result
    }
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-bindgen-v0"],
    });

    use std::collections::HashMap;

    use crate::resolve::{self, DomainQuery, InputType, ResolveResult};
    use crate::base58_inline;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SnsResolve;

    const PLUGIN_NAME: &str = "sns-resolve";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "sns_resolve";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        domain: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SnsResolve {
        fn plugin_name() -> String { PLUGIN_NAME.to_string() }
        fn plugin_version() -> String { PLUGIN_VERSION.to_string() }
    }

    impl Tool for SnsResolve {
        fn name() -> String { TOOL_NAME.to_string() }

        fn description() -> String {
            "Resolve .sol and .abc SNS domains to Solana public keys. Also validates \
             raw base58 addresses. Never hallucinate an address again — use this tool \
             before any transfer.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "A .sol domain (e.g. 'bonfida.sol'), .abc domain, or raw base58 pubkey."}
                },
                "required": ["domain"]
            }).to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    log_fail(&format!("invalid arguments: {e}"));
                    return Ok(ToolResult { success: false, output: String::new(), error: Some(format!("invalid arguments: {e}")) });
                }
            };

            let input_type = resolve::detect(&parsed.domain);
            let result = match input_type {
                InputType::Pubkey => {
                    let decoded = match crate::base58_inline::decode(&parsed.domain) {
                        Some(v) if v.len() == 32 => v,
                        _ => return Ok(ToolResult { success: false, output: String::new(),
                            error: Some(format!("invalid base58 pubkey: {}", parsed.domain)) }),
                    };
                    ResolveResult { address: parsed.domain.trim().to_string(), input_type, input: parsed.domain.clone(), domain: None, is_raw: true }
                }
                InputType::SolDomain | InputType::AnsDomain => {
                    let query = match resolve::build_query(&parsed.domain) {
                        Ok(q) => q,
                        Err(e) => return Ok(ToolResult { success: false, output: String::new(), error: Some(e) }),
                    };
                    let rpc_url = parsed.config.get("rpc_url").cloned().unwrap_or_else(|| "https://api.mainnet-beta.solana.com".into());
                    let api_key = parsed.config.get("rpc_api_key").cloned();
                    match fetch_name_registry(&rpc_url, api_key.as_deref(), &query) {
                        Ok(Some(owner)) => ResolveResult { address: owner, input_type, input: parsed.domain.clone(), domain: Some(query.domain), is_raw: false },
                        Ok(None) => return Ok(ToolResult { success: false, output: String::new(), error: Some(format!("domain not registered: {}", parsed.domain)) }),
                        Err(e) => return Ok(ToolResult { success: false, output: String::new(), error: Some(format!("RPC error: {e}")) }),
                    }
                }
                InputType::Unknown => {
                    return Ok(ToolResult { success: false, output: String::new(),
                        error: Some(format!("unrecognized input: {}. Expected .sol, .abc, or base58 pubkey.", parsed.domain)) });
                }
            };

            log_record(LogLevel::Info, &PluginEvent {
                function_name: "sns_resolve::execute".into(),
                action: PluginAction::Complete, outcome: Some(PluginOutcome::Success),
                duration_ms: None,
                attrs: Some(serde_json::json!({"type": format!("{:?}", result.input_type)}).to_string()),
                message: format!("Resolved {} → {}", result.input, &result.address[..result.address.len().min(16)]),
            });

            Ok(ToolResult {
                success: true,
                output: serde_json::json!({
                    "address": result.address, "input": result.input,
                    "type": format!("{:?}", result.input_type).to_lowercase(),
                    "is_raw": result.is_raw,
                }).to_string(),
                error: None,
            })
        }
    }

    // -- RPC helpers --------------------------------------------------------

    fn fetch_name_registry(rpc_url: &str, api_key: Option<&str>, query: &DomainQuery) -> Result<Option<String>, String> {
        let (pda, _) = resolve::find_name_pda(query);
        let pda_b58 = base58_inline::encode(&pda);

        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":[pda_b58,{"encoding":"base64"}]});
        let resp: serde_json::Value = rpc_post(rpc_url, api_key, &body)?;
        let val = resp.get("result").and_then(|r| r.get("value"));
        if val.is_none() || val.and_then(|v| v.as_object()).map(|o| o.is_empty()).unwrap_or(true) {
            return Ok(None);
        }

        let data_str = val.unwrap().get("data").and_then(|d| d.as_array())
            .and_then(|a| a.first()).and_then(|s| s.as_str())
            .ok_or_else(|| "no data field".to_string())?;

        let raw = base64_decode(data_str)?;
        if raw.len() < 64 { return Err(format!("name registry too short: {} bytes", raw.len())); }
        let owner = base58_inline::encode(&raw[32..64]);
        Ok(Some(owner))
    }

    fn rpc_post(url: &str, api_key: Option<&str>, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
        let auth_val;
        if let Some(key) = api_key { auth_val = format!("Bearer {key}"); headers.push(("Authorization", &auth_val)); }
        waki::Client::new().post(url).headers(headers).json(body).send()
            .map_err(|e| e.to_string())?.json().map_err(|e| e.to_string())
    }

    fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| e.to_string())
    }

    fn log_fail(msg: &str) {
        log_record(LogLevel::Error, &PluginEvent {
            function_name: "sns_resolve::execute".into(),
            action: PluginAction::Fail, outcome: Some(PluginOutcome::Failure),
            duration_ms: None, attrs: None, message: msg.to_string(),
        });
    }

    export!(SnsResolve);
}
