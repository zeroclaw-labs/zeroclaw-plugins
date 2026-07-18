
pub fn rpc_post(url: &str, body: &str) -> Result<String, String> {
    #[cfg(target_family = "wasm")]
    {
        use waki::Client;
        let resp = Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.as_bytes())
            .send()
            .map_err(|e| format!("http error: {e}"))?;
        let bytes = resp.body().map_err(|e| format!("body error: {e}"))?;
        String::from_utf8(bytes).map_err(|e| format!("utf8 error: {e}"))
    }
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = url;
        let _ = body;
        Err("rpc_post not available outside wasm - use mocks in tests".to_string())
    }
}

pub fn get_account_info(rpc_url: &str, pubkey: &str) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["{}",{{"encoding":"jsonParsed"}}]}}"#,
        pubkey
    );
    rpc_post(rpc_url, &body)
}

pub fn get_largest_accounts(rpc_url: &str, mint: &str) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getTokenLargestAccounts","params":["{}"]}}"#,
        mint
    );
    rpc_post(rpc_url, &body)
}

pub fn das_get_asset(das_url: &str, mint: &str) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getAsset","params":{{"id":"{}"}}}}"#,
        mint
    );
    rpc_post(das_url, &body)
}
