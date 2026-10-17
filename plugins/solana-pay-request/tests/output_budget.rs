use serde_json::{json, Value};
use solana_pay_request::pay_request::{
    execute_component_input, RequestOutput, MAX_TOOL_OUTPUT_BYTES,
};

const RECIPIENT: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

fn execute(value: Value) -> solana_pay_request::pay_request::ToolResponse {
    execute_component_input(&serde_json::to_string(&value).expect("fixture"))
}

#[test]
fn happy_path_output_stays_well_below_the_context_ceiling() {
    let result = execute(json!({
        "recipient": RECIPIENT,
        "amount": "25",
        "invoice_id": "412",
        "label": "Table Four",
        "message": "Lunch",
        "memo": "Order 412"
    }));
    assert!(result.success);
    assert!(result.output.len() < MAX_TOOL_OUTPUT_BYTES);
    assert!(result.output.len() < 1_000);
}

#[test]
fn largest_successful_ascii_fields_remain_bounded_and_have_no_qr_art() {
    let result = execute(json!({
        "recipient": RECIPIENT,
        "amount": "1",
        "invoice_id": "i".repeat(128),
        "label": "l".repeat(128),
        "message": "m".repeat(256),
        "memo": "o".repeat(256)
    }));
    assert!(result.success, "{:?}", result.error);
    assert!(result.output.len() < MAX_TOOL_OUTPUT_BYTES);
    let output: RequestOutput = serde_json::from_str(&result.output).expect("output");
    assert_eq!(output.url, output.qr_payload);
    assert!(!result.output.contains("████"));
    assert!(!result.output.contains("▄▀"));
}

#[test]
fn worst_case_percent_expansion_refuses_instead_of_overrunning_output() {
    let result = execute(json!({
        "recipient": RECIPIENT,
        "amount": "1",
        "invoice_id": "412",
        "label": "é".repeat(64),
        "message": "é".repeat(128),
        "memo": "é".repeat(128)
    }));
    assert!(!result.success);
    assert!(result.output.is_empty());
}
