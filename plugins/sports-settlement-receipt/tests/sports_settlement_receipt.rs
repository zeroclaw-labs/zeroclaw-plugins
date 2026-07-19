use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use sports_settlement_receipt::core::{
    build_attestation_plan, build_validate_stat_instruction, compile_market,
    derive_daily_scores_pda, encode_pubkey, hash_canonical_json, parameters_schema,
    parse_execute_args, parse_stat_validation_response, stat_validation_url, unknown_report,
    MarketInput, MatchSelection, PluginConfig, TotalGoalsSide, COMPUTE_BUDGET_PROGRAM_ID,
    COMPUTE_UNIT_LIMIT, MEMO_PROGRAM_ID, PROGRAM_ID, VALIDATE_STAT_DISCRIMINATOR,
};
use sports_settlement_receipt::quorum::{
    classify_quorum, inspect_provider, quorum_request_bodies, verify_attestation_response,
    ProviderState, QuorumVerdict,
};

const VALID_PROOF: &str = include_str!("fixtures/proof-valid.json");
const DEVNET_REFERENCE: &str = include_str!("fixtures/devnet-validation-proof.json");
const FIXTURE_ID: u64 = 18_179_550;
const SEQUENCE: u64 = 1_315;
const SLOT: u64 = 476_311_319;

fn signature() -> String {
    bs58::encode([7u8; 64]).into_string()
}

fn valid_args() -> String {
    json!({
        "fixture_id": FIXTURE_ID,
        "sequence": SEQUENCE,
        "market": {"kind": "match_winner", "selection": "home"},
        "attestation_signature": signature()
    })
    .to_string()
}

fn proof() -> sports_settlement_receipt::core::ParsedProof {
    parse_stat_validation_response(VALID_PROOF, FIXTURE_ID).expect("valid proof fixture")
}

fn home_market() -> sports_settlement_receipt::core::CompiledMarket {
    compile_market(&MarketInput::MatchWinner {
        selection: MatchSelection::Home,
    })
    .expect("valid market")
}

#[test]
fn schema_is_closed_and_prompt_injection_is_rejected() {
    let schema: Value = serde_json::from_str(&parameters_schema()).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema["properties"].get("attestation_signature").is_some());
    for forbidden in [
        "__config",
        "rpc_url",
        "method",
        "transaction",
        "private_key",
    ] {
        assert!(schema["properties"].get(forbidden).is_none());
        let mut value: Value = serde_json::from_str(&valid_args()).unwrap();
        value[forbidden] = json!("sendTransaction");
        assert_eq!(
            parse_execute_args(&value.to_string()).unwrap_err().code(),
            "INVALID_EXECUTE_ARGS"
        );
    }
    let mut threshold: Value = serde_json::from_str(&valid_args()).unwrap();
    threshold["market"]["threshold"] = json!(-999);
    assert_eq!(
        parse_execute_args(&threshold.to_string())
            .unwrap_err()
            .code(),
        "INVALID_EXECUTE_ARGS"
    );
}

#[test]
fn arguments_config_and_targets_are_fail_closed() {
    let parsed = parse_execute_args(&valid_args()).unwrap();
    assert_eq!(parsed.fixture_id, FIXTURE_ID);
    let mut config = HashMap::from([
        ("txline_api_token".into(), "token".into()),
        ("txline_session_jwt".into(), "jwt".into()),
        ("rpc_url_1".into(), "https://rpc-one.example/v1/key".into()),
        ("rpc_url_2".into(), "https://rpc-two.example".into()),
        ("rpc_url_3".into(), "https://rpc-three.example".into()),
    ]);
    let parsed_config = PluginConfig::from_section(&config).unwrap();
    assert_eq!(parsed_config.rpc_urls.len(), 3);
    config.insert("rpc_url_2".into(), "https://rpc-one.example/other".into());
    assert_eq!(
        PluginConfig::from_section(&config).unwrap_err().code(),
        "DUPLICATE_RPC_PROVIDER"
    );
    config.insert("rpc_url_2".into(), "http://rpc-two.example".into());
    assert_eq!(
        PluginConfig::from_section(&config).unwrap_err().code(),
        "INVALID_RPC_URL"
    );
    assert_eq!(
        stat_validation_url("https://txline-dev.txodds.com", FIXTURE_ID, SEQUENCE).unwrap(),
        "https://txline-dev.txodds.com/api/scores/stat-validation?fixtureId=18179550&seq=1315&statKey=1&statKey2=2"
    );
}

#[test]
fn proof_market_pda_and_borsh_plan_are_deterministic() {
    let proof = proof();
    assert_eq!((proof.stat_a.value, proof.stat_b.value), (3, 2));
    assert_eq!((proof.stat_a.period, proof.stat_b.period), (100, 100));
    let market = home_market();
    assert_eq!(market.compact, "stat[1]-stat[2]>0");
    let plan = build_attestation_plan(&proof, &market).unwrap();
    assert!(plan.predicate_result);
    assert_eq!(
        plan.daily_scores_pda,
        "69SexUQvQ9uNpyx6bgDLVoQ5uKkbn3uRxZXCJ5KVZ7QL"
    );
    let instruction = build_validate_stat_instruction(&proof, &market).unwrap();
    assert_eq!(&instruction[..8], &VALIDATE_STAT_DISCRIMINATOR);
    assert_eq!(instruction, plan.instruction);
    let (pda, _) = derive_daily_scores_pda(proof.update_stats.min_timestamp).unwrap();
    assert_eq!(encode_pubkey(&pda), plan.daily_scores_pda);

    let over = compile_market(&MarketInput::TotalGoals {
        side: TotalGoalsSide::Over,
        line_x2: 5,
    })
    .unwrap();
    assert_eq!(over.compact, "stat[1]+stat[2]>2");
}

#[test]
fn proof_rejects_wrong_fixture_and_non_final_period() {
    assert_eq!(
        parse_stat_validation_response(VALID_PROOF, FIXTURE_ID + 1)
            .unwrap_err()
            .code(),
        "PROOF_FIXTURE_MISMATCH"
    );
    let mut value: Value = serde_json::from_str(VALID_PROOF).unwrap();
    value["statToProve"]["period"] = json!(99);
    assert_eq!(
        parse_stat_validation_response(&value.to_string(), FIXTURE_ID)
            .unwrap_err()
            .code(),
        "PERIOD_NOT_FINAL"
    );
}

#[test]
fn rpc_methods_are_fixed_and_finalized() {
    let [status, transaction] = quorum_request_bodies(&signature()).unwrap();
    let status: Value = serde_json::from_str(&status).unwrap();
    let transaction: Value = serde_json::from_str(&transaction).unwrap();
    assert_eq!(status["method"], "getSignatureStatuses");
    assert_eq!(status["params"][1]["searchTransactionHistory"], true);
    assert_eq!(transaction["method"], "getTransaction");
    assert_eq!(transaction["params"][1]["commitment"], "finalized");
    assert_eq!(transaction["params"][1]["encoding"], "base64");
}

#[test]
fn exact_finalized_attestation_reaches_two_provider_quorum() {
    let plan = build_attestation_plan(&proof(), &home_market()).unwrap();
    let (status, transaction) = synthetic_rpc(&plan, None);
    let binding =
        verify_attestation_response(&transaction, &signature(), FIXTURE_ID, SEQUENCE, &plan)
            .unwrap();
    assert_eq!(binding.finalized_slot, SLOT);
    assert_eq!(binding.memo_receipt_sha256, "ab".repeat(32));
    assert!(binding.predicate_result);

    let first = inspect_provider(1, &signature(), Ok(&status), Ok(&transaction));
    let second = inspect_provider(2, &signature(), Ok(&status), Ok(&transaction));
    assert_eq!(first.state, ProviderState::Complete);
    let decision = classify_quorum(vec![first, second]);
    assert_eq!(decision.verdict, QuorumVerdict::Consistent);
    assert_eq!(decision.complete, 2);
}

#[test]
fn any_attestation_or_provider_disagreement_stays_unknown() {
    let plan = build_attestation_plan(&proof(), &home_market()).unwrap();
    let (status, valid) = synthetic_rpc(&plan, None);
    let (_, bad_memo) = synthetic_rpc(&plan, Some("fixture=999"));
    assert_eq!(
        verify_attestation_response(&bad_memo, &signature(), FIXTURE_ID, SEQUENCE, &plan)
            .unwrap_err()
            .code(),
        "ATTESTATION_MEMO_MISMATCH"
    );
    let good = inspect_provider(1, &signature(), Ok(&status), Ok(&valid));
    let bad = inspect_provider(2, &signature(), Ok(&status), Ok(&bad_memo))
        .binding_diverged("ATTESTATION_MEMO_MISMATCH");
    let decision = classify_quorum(vec![good, bad]);
    assert_eq!(decision.verdict, QuorumVerdict::Diverged);

    let unknown: Value = serde_json::from_str(&unknown_report(
        &decision.code,
        Some(FIXTURE_ID),
        Some(SEQUENCE),
    ))
    .unwrap();
    assert_eq!(unknown["verdict"], "unknown");
    assert_eq!(unknown["settlement_ready"], false);
}

#[test]
fn canonical_hash_is_stable() {
    let first = json!({"z": 1, "a": {"b": 2, "a": 1}});
    let second = json!({"a": {"a": 1, "b": 2}, "z": 1});
    assert_eq!(
        hash_canonical_json(&first).unwrap(),
        hash_canonical_json(&second).unwrap()
    );
}

#[test]
fn public_devnet_reference_matches_the_fresh_proof_plan() {
    let reference: Value = serde_json::from_str(DEVNET_REFERENCE).unwrap();
    let proof = proof();
    let plan = build_attestation_plan(&proof, &home_market()).unwrap();
    assert_eq!(reference["fixtureId"], FIXTURE_ID);
    assert_eq!(reference["scoreSequence"], SEQUENCE);
    assert_eq!(reference["proofPayloadHash"], proof.payload_sha256);
    assert_eq!(reference["dailyScoresPda"], plan.daily_scores_pda);
    assert_eq!(reference["predicate"], plan.predicate_compact);
    assert_eq!(reference["predicateResult"], plan.predicate_result);
    assert_eq!(reference["slot"], SLOT);
    parse_execute_args(
        &json!({
            "fixture_id": FIXTURE_ID,
            "sequence": SEQUENCE,
            "market": {"kind": "match_winner", "selection": "home"},
            "attestation_signature": reference["signature"]
        })
        .to_string(),
    )
    .unwrap();
}

fn synthetic_rpc(
    plan: &sports_settlement_receipt::core::AttestationPlan,
    memo_override: Option<&str>,
) -> (String, String) {
    let signature_bytes = [7u8; 64];
    let payer = [9u8; 32];
    let accounts = [
        payer,
        plan.daily_scores_pda_bytes,
        decode_key(PROGRAM_ID),
        decode_key(COMPUTE_BUDGET_PROGRAM_ID),
        decode_key(MEMO_PROGRAM_ID),
    ];
    let receipt = "ab".repeat(32);
    let normal_memo = format!(
        "SettleTrace v1 | fixture={FIXTURE_ID} | seq={SEQUENCE} | receiptHash={receipt} | predicate={}",
        plan.predicate_compact
    );
    let memo = memo_override
        .map(|replacement| normal_memo.replace(&format!("fixture={FIXTURE_ID}"), replacement))
        .unwrap_or(normal_memo);

    let mut message = vec![1, 0, 4];
    shortvec(&mut message, accounts.len());
    for account in accounts {
        message.extend_from_slice(&account);
    }
    message.extend_from_slice(&[3u8; 32]);
    shortvec(&mut message, 3);
    let mut compute_data = vec![2];
    compute_data.extend_from_slice(&COMPUTE_UNIT_LIMIT.to_le_bytes());
    instruction(&mut message, 3, &[], &compute_data);
    instruction(&mut message, 4, &[0], memo.as_bytes());
    instruction(&mut message, 2, &[1], &plan.instruction);

    let mut transaction = vec![1];
    transaction.extend_from_slice(&signature_bytes);
    transaction.extend_from_slice(&message);
    let encoded = BASE64_STANDARD.encode(transaction);
    let predicate = BASE64_STANDARD.encode([u8::from(plan.predicate_result)]);
    let status = json!({
        "jsonrpc": "2.0", "id": 11,
        "result": {"context": {"slot": SLOT + 1}, "value": [{
            "slot": SLOT, "confirmations": null, "err": null,
            "confirmationStatus": "finalized"
        }]}
    })
    .to_string();
    let transaction = json!({
        "jsonrpc": "2.0", "id": 12,
        "result": {
            "slot": SLOT,
            "transaction": [encoded, "base64"],
            "meta": {"err": null, "returnData": {
                "programId": PROGRAM_ID, "data": [predicate, "base64"]
            }}
        }
    })
    .to_string();
    (status, transaction)
}

fn decode_key(value: &str) -> [u8; 32] {
    bs58::decode(value).into_vec().unwrap().try_into().unwrap()
}

fn instruction(out: &mut Vec<u8>, program: u8, accounts: &[u8], data: &[u8]) {
    out.push(program);
    shortvec(out, accounts.len());
    out.extend_from_slice(accounts);
    shortvec(out, data.len());
    out.extend_from_slice(data);
}

fn shortvec(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}
