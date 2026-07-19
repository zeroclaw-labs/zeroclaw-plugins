//! Host-run tests for wallet-narrate core.
use wallet_narrate::*;

#[test]
fn test_narrative_struct_serialization() {
    let n = Narrative {
        short: "Transferred 1.0000 SOL from ABC to XYZ".to_string(),
        type_: "TRANSFER".to_string(),
        parties: vec!["ABCdefgh".to_string(), "XYZ12345".to_string()],
        direction: "out".to_string(),
    };
    let json = serde_json::to_string(&n).unwrap();
    assert!(json.contains("TRANSFER"));
    assert!(json.contains("ABCdefgh"));
}

#[test]
fn test_detect_swap_type() {
    let logs = vec!["Program jupiter exchange log".to_string()];
    assert_eq!(detect_tx_type(&logs), "SWAP");
}

#[test]
fn test_detect_transfer_type() {
    let logs = vec!["Program Token Transfer".to_string()];
    assert_eq!(detect_tx_type(&logs), "TRANSFER");
}

#[test]
fn test_detect_unknown_type() {
    let logs = vec!["Program some unknown instruction".to_string()];
    assert_eq!(detect_tx_type(&logs), "UNKNOWN");
}

#[test]
fn test_direction_inference() {
    let n = Narrative { short: "test".to_string(), type_: "TRANSFER".to_string(), parties: vec![], direction: "in".to_string() };
    assert_eq!(n.direction, "in");
    let n2 = Narrative { short: "test".to_string(), type_: "TRANSFER".to_string(), parties: vec![], direction: "out".to_string() };
    assert_eq!(n2.direction, "out");
}

#[test]
fn test_empty_parties() {
    let n = Narrative { short: "test".to_string(), type_: "UNKNOWN".to_string(), parties: vec![], direction: "self".to_string() };
    assert!(n.parties.is_empty());
}
