use governance_watch::governance_watch::{watch, HttpClient, WatchArgs, WatchConfig};
use serde_json::Value;

struct CountingHttp {
    calls: usize,
}

impl HttpClient for CountingHttp {
    fn get_json(&mut self, _url: &str) -> Result<Value, String> {
        self.calls += 1;
        Ok(Value::Null)
    }
}

#[test]
fn public_api_rejects_invalid_realm_before_http() {
    let mut http = CountingHttp { calls: 0 };
    let args = WatchArgs {
        realm: "not-a-solana-public-key".to_string(),
        states: Vec::new(),
        limit: None,
        since_unix: None,
    };

    let result = watch(&mut http, &args, &WatchConfig::default());

    assert!(result.unwrap_err().contains("base58"));
    assert_eq!(http.calls, 0);
}
