use settlement_proof_narrate::narrate::{detect_prompt_injection, narrate, ProofInput};

#[test]
fn injection() {
    assert!(detect_prompt_injection("jailbreak now"));
}

#[test]
fn narrates_valid_en() {
    let n = narrate(&ProofInput {
        fixture_id: Some("18209181".into()),
        outcome: Some("home".into()),
        valid: Some(true),
        merkle_root: Some("abcdef0123456789".into()),
        program_id: None,
        locale: Some("en".into()),
    });
    assert!(n.text.contains("VALID"));
    assert_eq!(n.custody_tier, "T0");
}

#[test]
fn narrates_invalid_fr() {
    let n = narrate(&ProofInput {
        fixture_id: Some("1".into()),
        outcome: Some("draw".into()),
        valid: Some(false),
        merkle_root: None,
        program_id: None,
        locale: Some("fr".into()),
    });
    assert!(n.text.contains("INVALIDE"));
}
