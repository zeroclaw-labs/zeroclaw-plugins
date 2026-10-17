use token_risk_check::core::{assess, signals_from_mint_account};

#[test]
fn host_fixture_flags_enabled_authorities() {
    let value = serde_json::json!({
        "value": { "data": { "parsed": { "info": {
            "mintAuthority": "Auth", "freezeAuthority": null,
            "supply": "1000", "decimals": 6
        }}}}
    });
    let report = assess(&signals_from_mint_account(&value).unwrap());
    assert!(report.flags.contains(&"mint_authority_enabled"));
}
