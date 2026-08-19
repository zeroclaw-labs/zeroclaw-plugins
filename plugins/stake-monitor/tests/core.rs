use stake_monitor::core::{assess, state_from_rpc};

#[test]
fn host_fixture_reports_activation() {
    let value = serde_json::json!({"value":{"data":{"parsed":{"info":{"stake":{
        "delegation":{"stake":1000},"activeLamports":700,"activatingLamports":300
    }}}}}});
    let state = state_from_rpc(&value).unwrap();
    assert_eq!(assess(&state).status, "activating");
}
