use wallet_narrate::core::{activities_from_rpc, summarize};

#[test]
fn host_fixture_is_bounded_and_redacted() {
    let value = serde_json::json!([{"signature":"1234567890abcdef","slot":9,"err":null}]);
    let items = activities_from_rpc(&value).unwrap();
    assert!(summarize(&items, 100)[0].contains("123456…cdef"));
}
