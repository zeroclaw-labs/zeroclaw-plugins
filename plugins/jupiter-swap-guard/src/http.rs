//! The network boundary, behind traits so the whole pipeline is host-testable.
//!
//! `SwapApi` and `Rpc` are the only I/O the plugin performs. The pure pipeline
//! (`crate::pipeline`) takes them as `&dyn`, so its tests drive the full
//! quote → gate → compile flow with mocks fed the real captured fixtures — no
//! network, no wasm. The `waki` implementations below are the thin wasm-only
//! adapters that actually call the host's `wasi:http` (TLS is performed host-side;
//! granted by the `http_client` permission).

#![forbid(unsafe_code)]

/// Jupiter swap API: quote and swap-instructions. Both return the raw JSON body.
pub trait SwapApi {
    fn quote(&self, base_url: &str, query: &str) -> Result<String, String>;
    fn swap_instructions(&self, base_url: &str, body: &str) -> Result<String, String>;
}

/// The minimal Solana JSON-RPC surface the plugin needs. `get_account_base64`
/// returns the account's base64 data (None if the account does not exist);
/// `get_account_owner` returns the owning program (base58) — used to resolve a
/// mint's real token program from a TRUSTED source rather than the aggregator.
pub trait Rpc {
    fn get_account_base64(&self, url: &str, pubkey_b58: &str) -> Result<Option<String>, String>;
    fn get_account_owner(&self, url: &str, pubkey_b58: &str) -> Result<String, String>;
    fn get_genesis_hash(&self, url: &str) -> Result<String, String>;
    fn get_latest_blockhash(&self, url: &str) -> Result<String, String>;
}

#[cfg(target_family = "wasm")]
mod waki_impl {
    use super::{Rpc, SwapApi};
    use std::time::Duration;
    use waki::Client;

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// waki-backed Jupiter client.
    pub struct WakiSwapApi;
    /// waki-backed Solana JSON-RPC client.
    pub struct WakiRpc;

    fn body_string(resp: waki::Response) -> Result<String, String> {
        let status = resp.status_code();
        let bytes = resp.body().map_err(|e| e.to_string())?;
        let text = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        if !(200..300).contains(&status) {
            return Err(format!("HTTP {status}: {}", truncate(&text, 200)));
        }
        Ok(text)
    }

    fn truncate(s: &str, n: usize) -> String {
        s.chars().take(n).collect()
    }

    impl SwapApi for WakiSwapApi {
        fn quote(&self, base_url: &str, query: &str) -> Result<String, String> {
            let url = format!("{base_url}/quote?{query}");
            let resp = Client::new()
                .get(&url)
                .connect_timeout(CONNECT_TIMEOUT)
                .send()
                .map_err(|e| e.to_string())?;
            body_string(resp)
        }

        fn swap_instructions(&self, base_url: &str, body: &str) -> Result<String, String> {
            let url = format!("{base_url}/swap-instructions");
            let resp = Client::new()
                .post(&url)
                .header("Content-Type", "application/json")
                .connect_timeout(CONNECT_TIMEOUT)
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| e.to_string())?;
            body_string(resp)
        }
    }

    fn rpc_call(url: &str, method: &str, params: &str) -> Result<serde_json::Value, String> {
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
        let resp = Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .connect_timeout(CONNECT_TIMEOUT)
            .body(body.into_bytes())
            .send()
            .map_err(|e| e.to_string())?;
        let text = body_string(resp)?;
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("rpc response not JSON: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("rpc error: {err}"));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| "rpc response missing result".to_string())
    }

    impl Rpc for WakiRpc {
        fn get_account_base64(
            &self,
            url: &str,
            pubkey_b58: &str,
        ) -> Result<Option<String>, String> {
            let params = format!(r#"["{pubkey_b58}",{{"encoding":"base64"}}]"#);
            let result = rpc_call(url, "getAccountInfo", &params)?;
            let value = &result["value"];
            if value.is_null() {
                return Ok(None);
            }
            value["data"][0]
                .as_str()
                .map(|s| Some(s.to_string()))
                .ok_or_else(|| "account data not base64".to_string())
        }

        fn get_account_owner(&self, url: &str, pubkey_b58: &str) -> Result<String, String> {
            let params = format!(r#"["{pubkey_b58}",{{"encoding":"base64"}}]"#);
            let result = rpc_call(url, "getAccountInfo", &params)?;
            result["value"]["owner"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "account has no owner (does it exist?)".to_string())
        }

        fn get_genesis_hash(&self, url: &str) -> Result<String, String> {
            let result = rpc_call(url, "getGenesisHash", "[]")?;
            result
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "genesis hash not a string".to_string())
        }

        fn get_latest_blockhash(&self, url: &str) -> Result<String, String> {
            let params = r#"[{"commitment":"finalized"}]"#;
            let result = rpc_call(url, "getLatestBlockhash", params)?;
            result["value"]["blockhash"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "blockhash missing".to_string())
        }
    }
}

#[cfg(target_family = "wasm")]
pub use waki_impl::{WakiRpc, WakiSwapApi};
