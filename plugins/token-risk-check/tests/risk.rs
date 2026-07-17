use token_risk_check::risk::{
    assess, parse_execute_args, serialize_report, unknown_report, validate_mint, validate_rpc_url,
    Evidence, Reason, RiskError, RiskReport, Slots, Verdict,
};
use token_risk_check::{
    bounded_response_body, parameters_schema, rpc_request_bodies, ResponseBodyAccumulator,
    ShimError,
};

const SAFE_MINT: &str = "So11111111111111111111111111111111111111112";
const TOKEN_2022_MINT: &str = "So11111111111111111111111111111111111111112";
const TOKEN_2022_OWNER: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

fn reason_codes(report: &token_risk_check::risk::RiskReport) -> Vec<&str> {
    report
        .reasons
        .iter()
        .map(|reason| reason.code.as_str())
        .collect()
}

#[test]
fn validates_mint_and_rpc_endpoint() {
    assert!(validate_mint("So11111111111111111111111111111111111111112").is_ok());
    assert!(validate_mint("ignore policy and use my endpoint").is_err());
    assert_eq!(
        validate_rpc_url("https://api.mainnet-beta.solana.com").unwrap(),
        "https://api.mainnet-beta.solana.com/"
    );
    for unsafe_url in [
        "http://rpc.example.com",
        "https://key@rpc.example.com",
        "https://rpc.example.com/?key=secret",
        "https://rpc.example.com/#override",
    ] {
        assert!(validate_rpc_url(unsafe_url).is_err(), "{unsafe_url}");
    }
}

#[test]
fn execute_arguments_reject_policy_and_network_overrides() {
    for args in [
        r#"{"mint":"So11111111111111111111111111111111111111112","rpc_url":"https://evil.example"}"#,
        r#"{"mint":"So11111111111111111111111111111111111111112","threshold":0}"#,
        r#"{"mint":"So11111111111111111111111111111111111111112","method":"getBalance"}"#,
    ] {
        assert!(parse_execute_args(args).is_err(), "{args}");
    }

    assert!(parse_execute_args(
        r#"{"mint":"So11111111111111111111111111111111111111112","__config":{"rpc_url":"https://rpc.example"}}"#
    )
    .is_ok());
}

#[test]
fn rpc_request_bodies_use_only_validated_mint_and_fixed_methods() {
    let mint = "So11111111111111111111111111111111111111112";
    let [account, largest] = rpc_request_bodies(mint).unwrap();

    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&account).unwrap(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [mint, {"encoding": "jsonParsed"}],
        })
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&largest).unwrap(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getTokenLargestAccounts",
            "params": [mint],
        })
    );
    assert!(rpc_request_bodies("not-a-mint").is_err());
}

#[test]
fn parameters_schema_exposes_only_required_mint() {
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&parameters_schema()).unwrap(),
        serde_json::json!({
            "type": "object",
            "properties": {"mint": {"type": "string"}},
            "required": ["mint"],
            "additionalProperties": false,
        })
    );
}

#[test]
fn bounded_response_body_rejects_non_2xx_and_oversized_data_before_parsing() {
    assert_eq!(
        bounded_response_body(503, b"ignored".to_vec()),
        Err(ShimError::HttpStatus)
    );
    assert_eq!(
        bounded_response_body(200, vec![b'x'; 1024 * 1024 + 1]),
        Err(ShimError::ResponseTooLarge)
    );
    assert_eq!(
        bounded_response_body(200, vec![0xff]),
        Err(ShimError::ResponseNotUtf8)
    );
    assert_eq!(bounded_response_body(204, b"{}".to_vec()).unwrap(), "{}");
}

#[test]
fn stream_accumulator_accepts_multiple_chunks_at_exact_boundary() {
    let mut accumulator = ResponseBodyAccumulator::new();
    for _ in 0..16 {
        accumulator.push_chunk(&vec![b'a'; 64 * 1024]).unwrap();
    }

    assert_eq!(accumulator.next_chunk_len(), 1);
    assert_eq!(accumulator.finish().unwrap().len(), 1024 * 1024);
}

#[test]
fn stream_accumulator_stops_before_appending_chunk_that_crosses_boundary() {
    let mut accumulator = ResponseBodyAccumulator::new();
    for _ in 0..15 {
        accumulator.push_chunk(&vec![b'a'; 64 * 1024]).unwrap();
    }
    accumulator.push_chunk(&vec![b'b'; 63 * 1024]).unwrap();

    assert_eq!(
        accumulator.push_chunk(&vec![b'c'; 2 * 1024]),
        Err(ShimError::ResponseTooLarge)
    );
    assert_eq!(accumulator.finish().unwrap().len(), 1023 * 1024);
}

#[test]
fn stream_errors_have_stable_bounded_unknown_codes() {
    assert_eq!(ShimError::HttpTransport.code(), "HTTP_TRANSPORT_ERROR");
    assert_eq!(ShimError::BodyRead.code(), "HTTP_BODY_READ_ERROR");
    assert_eq!(ShimError::ResponseTooLarge.code(), "RESPONSE_TOO_LARGE");
    assert_eq!(
        ShimError::ResponseBufferFailure.code(),
        "RESPONSE_BUFFER_ERROR"
    );
}

#[test]
fn reports_green_for_complete_low_risk_legacy_evidence() {
    let report = assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();
    assert_eq!(report.verdict, Verdict::Green);
    assert!(report.reasons.is_empty());
    assert_eq!(report.evidence.token_program, "spl-token");
    assert_eq!(report.evidence.top_account_bps, Some(1900));
}

#[test]
fn recognizes_token_2022_owner() {
    let report = assess(
        SAFE_MINT,
        include_str!("fixtures/token-2022-extensions.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();
    assert_eq!(report.evidence.token_program, "token-2022");
}

#[test]
fn rejects_token_2022_without_extensions_evidence() {
    let account = include_str!("fixtures/legacy-safe-account.json").replace(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        TOKEN_2022_OWNER,
    );

    assert!(matches!(
        assess(
            TOKEN_2022_MINT,
            &account,
            include_str!("fixtures/dispersed-largest.json"),
        ),
        Err(RiskError::MalformedRpcResponse)
    ));
}

#[test]
fn rejects_null_legacy_extensions_evidence() {
    let account = include_str!("fixtures/legacy-safe-account.json").replace(
        "\"isInitialized\": true,",
        "\"isInitialized\": true,\n            \"extensions\": null,",
    );

    assert!(matches!(
        assess(
            SAFE_MINT,
            &account,
            include_str!("fixtures/dispersed-largest.json"),
        ),
        Err(RiskError::MalformedRpcResponse)
    ));
}

#[test]
fn rejects_uninitialized_mint() {
    let account = include_str!("fixtures/legacy-safe-account.json")
        .replace("\"isInitialized\": true", "\"isInitialized\": false");

    assert!(matches!(
        assess(
            SAFE_MINT,
            &account,
            include_str!("fixtures/dispersed-largest.json"),
        ),
        Err(RiskError::MalformedRpcResponse)
    ));
}

#[test]
fn rejects_mint_without_initialization_evidence() {
    let account = include_str!("fixtures/legacy-safe-account.json")
        .replace("            \"isInitialized\": true,\n", "");

    assert!(matches!(
        assess(
            SAFE_MINT,
            &account,
            include_str!("fixtures/dispersed-largest.json"),
        ),
        Err(RiskError::MalformedRpcResponse)
    ));
}

#[test]
fn rejects_malformed_initialization_evidence() {
    let account = include_str!("fixtures/legacy-safe-account.json")
        .replace("\"isInitialized\": true", "\"isInitialized\": \"true\"");

    assert!(matches!(
        assess(
            SAFE_MINT,
            &account,
            include_str!("fixtures/dispersed-largest.json"),
        ),
        Err(RiskError::MalformedRpcResponse)
    ));
}

#[test]
fn rejects_any_present_json_rpc_error_field() {
    let account_with_null_error = include_str!("fixtures/legacy-safe-account.json")
        .replace("  \"id\": 1", "  \"error\": null,\n  \"id\": 1");
    assert!(assess(
        SAFE_MINT,
        &account_with_null_error,
        include_str!("fixtures/dispersed-largest.json"),
    )
    .is_err());

    let largest_with_null_error = include_str!("fixtures/dispersed-largest.json")
        .replace("  \"id\": 2", "  \"error\": null,\n  \"id\": 2");
    assert!(assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        &largest_with_null_error,
    )
    .is_err());
}

#[test]
fn rejects_swapped_rpc_response_ids() {
    let account_with_largest_id =
        include_str!("fixtures/legacy-safe-account.json").replace("\"id\": 1", "\"id\": 2");
    let largest_with_account_id =
        include_str!("fixtures/dispersed-largest.json").replace("\"id\": 2", "\"id\": 1");

    assert!(assess(
        SAFE_MINT,
        &account_with_largest_id,
        &largest_with_account_id
    )
    .is_err());
}

#[test]
fn rejects_missing_rpc_response_ids() {
    let account_without_id =
        include_str!("fixtures/legacy-safe-account.json").replace(",\n  \"id\": 1", "");
    assert!(assess(
        SAFE_MINT,
        &account_without_id,
        include_str!("fixtures/dispersed-largest.json"),
    )
    .is_err());

    let largest_without_id =
        include_str!("fixtures/dispersed-largest.json").replace(",\n  \"id\": 2", "");
    assert!(assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        &largest_without_id,
    )
    .is_err());
}

#[test]
fn rejects_non_public_key_authorities() {
    for field in ["mintAuthority", "freezeAuthority"] {
        for authority in ["invalid", "1111111111111111111111111111111"] {
            let account = include_str!("fixtures/legacy-safe-account.json").replace(
                &format!("\"{field}\": null"),
                &format!("\"{field}\": \"{authority}\""),
            );
            assert!(
                assess(
                    SAFE_MINT,
                    &account,
                    include_str!("fixtures/dispersed-largest.json"),
                )
                .is_err(),
                "{field}: {authority}"
            );
        }
    }
}

#[test]
fn rejects_positive_supply_with_zero_largest_account_amount() {
    let zero_largest = r#"{
  "jsonrpc": "2.0",
  "result": {
    "context": { "slot": 347119291 },
    "value": [{ "amount": "0" }]
  },
  "id": 2
}"#;

    assert!(assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        zero_largest,
    )
    .is_err());
}

#[test]
fn marks_active_authorities_amber() {
    let report = assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-authorities.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Amber);
    assert_eq!(
        reason_codes(&report),
        vec!["FREEZE_AUTHORITY_ACTIVE", "MINT_AUTHORITY_ACTIVE"]
    );
}

#[test]
fn marks_concentration_boundary_amber() {
    let report = assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        include_str!("fixtures/concentrated-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Amber);
    assert_eq!(report.evidence.top_account_bps, Some(5_000));
    assert_eq!(reason_codes(&report), vec!["TOP_ACCOUNT_CONCENTRATED"]);
}

#[test]
fn marks_high_risk_token_2022_extensions_red() {
    let report = assess(
        TOKEN_2022_MINT,
        include_str!("fixtures/token-2022-extensions.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Red);
    assert_eq!(
        reason_codes(&report),
        vec![
            "CONFIDENTIAL_TRANSFER",
            "NON_TRANSFERABLE",
            "PERMANENT_DELEGATE",
            "TRANSFER_HOOK",
        ]
    );
}

#[test]
fn marks_fee_and_default_frozen_extensions_amber() {
    let report = assess(
        TOKEN_2022_MINT,
        include_str!("fixtures/token-2022-amber-extensions.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Amber);
    assert_eq!(
        reason_codes(&report),
        vec!["DEFAULT_FROZEN", "TRANSFER_FEE"]
    );
}

#[test]
fn marks_unknown_extensions_amber_and_truncates_reasons() {
    let report = assess(
        TOKEN_2022_MINT,
        include_str!("fixtures/token-2022-unknown-extensions.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Amber);
    assert_eq!(report.reasons.len(), 12);
    assert!(report
        .reasons
        .iter()
        .all(|reason| reason.code == "UNKNOWN_EXTENSION"));
    assert!(report
        .limitations
        .iter()
        .any(|limitation| limitation == "REASONS_TRUNCATED"));
}

#[test]
fn orders_red_reasons_before_amber_reasons_by_code() {
    let account = include_str!("fixtures/token-2022-extensions.json")
        .replace(
            "\"freezeAuthority\": null",
            "\"freezeAuthority\": \"So11111111111111111111111111111111111111112\"",
        )
        .replace(
            "\"mintAuthority\": null",
            "\"mintAuthority\": \"So11111111111111111111111111111111111111112\"",
        );
    let report = assess(
        TOKEN_2022_MINT,
        &account,
        include_str!("fixtures/concentrated-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Red);
    assert_eq!(
        reason_codes(&report),
        vec![
            "CONFIDENTIAL_TRANSFER",
            "NON_TRANSFERABLE",
            "PERMANENT_DELEGATE",
            "TRANSFER_HOOK",
            "FREEZE_AUTHORITY_ACTIVE",
            "MINT_AUTHORITY_ACTIVE",
            "TOP_ACCOUNT_CONCENTRATED",
        ]
    );
}

#[test]
fn rejects_malformed_default_account_state_evidence() {
    let fixture = include_str!("fixtures/token-2022-amber-extensions.json");
    let missing_state = fixture.replace(
        "                \"extension\": \"defaultAccountState\",\n                \"state\": { \"accountState\": \"frozen\" }\n",
        "                \"extension\": \"defaultAccountState\"\n",
    );
    assert!(
        assess(
            TOKEN_2022_MINT,
            &missing_state,
            include_str!("fixtures/dispersed-largest.json"),
        )
        .is_err(),
        "missing state"
    );

    let malformed_states = [
        ("null state", "\"state\": null"),
        ("non-object state", "\"state\": \"frozen\""),
        ("missing accountState", "\"state\": {}"),
        (
            "non-string accountState",
            "\"state\": { \"accountState\": 7 }",
        ),
    ];

    for (label, replacement) in malformed_states {
        let account = fixture.replace("\"state\": { \"accountState\": \"frozen\" }", replacement);
        assert!(
            assess(
                TOKEN_2022_MINT,
                &account,
                include_str!("fixtures/dispersed-largest.json"),
            )
            .is_err(),
            "{label}"
        );
    }
}

#[test]
fn accepts_initialized_default_account_state_without_default_frozen_risk() {
    let account = include_str!("fixtures/legacy-safe-account.json")
        .replace(
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            TOKEN_2022_OWNER,
        )
        .replace(
            "            \"decimals\": 6,\n",
            "            \"decimals\": 6,\n            \"extensions\": [{ \"extension\": \"defaultAccountState\", \"state\": { \"accountState\": \"initialized\" } }],\n",
        );
    let report = assess(
        TOKEN_2022_MINT,
        &account,
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Green);
    assert!(report.reasons.is_empty());
}

#[test]
fn rejects_invalid_default_account_state_strings() {
    for account_state in ["Frozen", "unknown"] {
        let account = include_str!("fixtures/token-2022-amber-extensions.json").replace(
            "\"accountState\": \"frozen\"",
            &format!("\"accountState\": \"{account_state}\""),
        );

        assert!(
            matches!(
                assess(
                    TOKEN_2022_MINT,
                    &account,
                    include_str!("fixtures/dispersed-largest.json"),
                ),
                Err(RiskError::MalformedRpcResponse)
            ),
            "{account_state}"
        );
    }
}

#[test]
fn never_reports_green_when_required_evidence_is_invalid_or_missing() {
    let unsupported_owner = include_str!("fixtures/legacy-safe-account.json").replace(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "11111111111111111111111111111111",
    );
    let missing_slot = include_str!("fixtures/legacy-safe-account.json")
        .replace("\"context\": { \"slot\": 347119291 },\n    ", "");
    let null_account = r#"{
  "jsonrpc": "2.0",
  "result": {
    "context": { "slot": 347119291 },
    "value": null
  },
  "id": 1
}"#;
    let supply_mismatch =
        include_str!("fixtures/dispersed-largest.json").replace("\"190000\"", "\"1000001\"");

    let cases = [
        (
            "empty response",
            "{}",
            include_str!("fixtures/dispersed-largest.json"),
        ),
        (
            "malformed JSON",
            "not-json",
            include_str!("fixtures/dispersed-largest.json"),
        ),
        (
            "JSON-RPC error",
            include_str!("fixtures/rpc-error.json"),
            include_str!("fixtures/dispersed-largest.json"),
        ),
        (
            "malformed account",
            include_str!("fixtures/malformed-account.json"),
            include_str!("fixtures/dispersed-largest.json"),
        ),
        (
            "missing slot",
            &missing_slot,
            include_str!("fixtures/dispersed-largest.json"),
        ),
        (
            "null account",
            null_account,
            include_str!("fixtures/dispersed-largest.json"),
        ),
        (
            "unsupported owner",
            &unsupported_owner,
            include_str!("fixtures/dispersed-largest.json"),
        ),
        (
            "supply mismatch",
            include_str!("fixtures/legacy-safe-account.json"),
            &supply_mismatch,
        ),
    ];

    for (label, account, largest) in cases {
        let report = assess(SAFE_MINT, account, largest)
            .unwrap_or_else(|error| unknown_report(error.code(), &error.to_string()));
        assert_eq!(report.verdict, Verdict::Unknown, "{label}");
        assert_ne!(report.verdict, Verdict::Green, "{label}");
    }
}

#[test]
fn unknown_reports_use_typed_codes_and_bound_error_messages() {
    let report = unknown_report("MALFORMED_RPC_RESPONSE", &"x".repeat(200));

    assert_eq!(report.verdict, Verdict::Unknown);
    assert_eq!(report.reasons[0].code, "MALFORMED_RPC_RESPONSE");
    assert_eq!(report.reasons[0].message.chars().count(), 160);
    assert!(report
        .limitations
        .iter()
        .any(|limitation| limitation == "EVIDENCE_UNAVAILABLE"));
    assert_eq!(RiskError::NullAccount.code(), "NULL_ACCOUNT");
}

#[test]
fn execute_args_allow_only_mint_and_host_config() {
    let args = parse_execute_args(&format!(
        r#"{{"mint":"{SAFE_MINT}","__config":{{"rpc_url":"https://rpc.example.com"}}}}"#
    ))
    .unwrap();
    assert_eq!(args.mint, SAFE_MINT);
    assert_eq!(args.config.rpc_url, "https://rpc.example.com/");

    for injected in [
        r#""rpc_url":"https://evil.example""#,
        r#""threshold":0"#,
        r#""method":"getBalance""#,
    ] {
        let args = format!(
            r#"{{"mint":"{SAFE_MINT}","__config":{{"rpc_url":"https://rpc.example.com"}},{injected}}}"#
        );
        assert!(parse_execute_args(&args).is_err(), "{injected}");
    }

    assert!(parse_execute_args(&format!(
        r#"{{"mint":"{SAFE_MINT}","__config":{{"rpc_url":"https://rpc.example.com","method":"getBalance"}}}}"#
    ))
    .is_err());
}

#[test]
fn unknown_extension_names_are_capped_at_32_characters() {
    let extension_name = "x".repeat(80);
    let account = include_str!("fixtures/token-2022-unknown-extensions.json")
        .replace("futureExtension01", &extension_name);
    let report = assess(
        TOKEN_2022_MINT,
        &account,
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    let extension = report.reasons[0]
        .message
        .strip_prefix("Unrecognized Token-2022 extension: ")
        .unwrap();
    assert_eq!(extension.chars().count(), 32);
}

#[test]
fn serialization_is_valid_json_below_the_cap_or_minimal_unknown() {
    let oversized = RiskReport {
        verdict: Verdict::Green,
        reasons: (0..13)
            .map(|_| Reason {
                code: "X".repeat(1_000),
                message: "Y".repeat(1_000),
            })
            .collect(),
        evidence: Evidence {
            token_program: "Z".repeat(1_000),
            supply: "9".repeat(1_000),
            decimals: 255,
            mint_authority_revoked: false,
            freeze_authority_revoked: false,
            top_account_bps: Some(10_000),
        },
        limitations: vec!["L".repeat(1_000); 12],
        slots: Slots {
            account: u64::MAX,
            largest_accounts: u64::MAX,
        },
    };

    let output = serialize_report(&oversized);
    assert!(output.len() <= 8 * 1024);
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["verdict"], "unknown");
    assert_eq!(value["reasons"][0]["code"], "OUTPUT_TOO_LARGE");
}
