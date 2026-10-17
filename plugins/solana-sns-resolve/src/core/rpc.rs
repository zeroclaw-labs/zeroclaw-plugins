
pub fn http_get(url: &str) -> Result<String, String> {
    #[cfg(target_family = "wasm")]
    {
        use waki::Client;
        let resp = Client::new()
            .get(url)
            .send()
            .map_err(|e| format!("http error: {e}"))?;
        let bytes = resp.body().map_err(|e| format!("body error: {e}"))?;
        String::from_utf8(bytes).map_err(|e| format!("utf8 error: {e}"))
    }
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = url;
        Err("http_get not available outside wasm - use mocks in tests".to_string())
    }
}
