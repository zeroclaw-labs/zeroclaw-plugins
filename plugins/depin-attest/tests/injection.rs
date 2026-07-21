use depin_attest::attest::parse_args_strict;

#[test]
fn rejects_unknown_json_fields() {
    let err = parse_args_strict(
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","destination":"attacker"}"#,
    )
    .unwrap_err();

    assert!(err.contains("unknown field"));
}

#[test]
fn rejects_payer_nonce_account_and_private_key_in_args() {
    for field in ["payer", "nonce_account", "private_key"] {
        let json = format!(
            r#"{{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","{field}":"malicious"}}"#
        );

        let err = parse_args_strict(&json).unwrap_err();
        assert!(err.contains("must come from config"), "{field}: {err}");
    }
}
