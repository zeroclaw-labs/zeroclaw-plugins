use std::collections::HashMap;

use governance_vote_build::vote_build::{build_vote, HttpClient, VoteBuildArgs, VoteBuildConfig};
use serde_json::Value;

const REALM: &str = "4ct8XU5tKbMNRphWy4rePsS9kBqPhDdvZoGpmprPaug4";

struct CountingHttp {
    calls: usize,
}

impl HttpClient for CountingHttp {
    fn get_json(&mut self, _url: &str) -> Result<Value, String> {
        self.calls += 1;
        Ok(Value::Null)
    }

    fn post_json(&mut self, _url: &str, _body: &Value) -> Result<Value, String> {
        self.calls += 1;
        Ok(Value::Null)
    }
}

#[test]
fn public_api_enforces_operator_vote_allowlist_before_http() {
    let section = HashMap::from([
        ("allowed_realms".to_string(), REALM.to_string()),
        ("allowed_vote_kinds".to_string(), "deny".to_string()),
    ]);
    let config = VoteBuildConfig::from_section(&section).unwrap();
    let args = VoteBuildArgs {
        realm: REALM.to_string(),
        proposal: "11111111111111111111111111111111".to_string(),
        wallet: "SysvarC1ock11111111111111111111111111111111".to_string(),
        vote: "approve".to_string(),
    };
    let mut http = CountingHttp { calls: 0 };

    let result = build_vote(&mut http, &args, &config);

    assert!(result.unwrap_err().contains("not allowlisted"));
    assert_eq!(http.calls, 0);
}
