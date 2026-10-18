
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

pub fn get_signatures(rpc_url: &str, address: &str, limit: u8) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress","params":["{}",{{"limit":{}}}]}}"#,
        address, limit
    );
    rpc_post(rpc_url, &body)
}

pub fn get_transaction(rpc_url: &str, sig: &str) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["{}",{{"encoding":"jsonParsed","maxSupportedTransactionVersion":0}}]}}"#,
        sig
    );
    rpc_post(rpc_url, &body)
}
