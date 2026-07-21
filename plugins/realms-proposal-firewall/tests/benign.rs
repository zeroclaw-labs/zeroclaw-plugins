include!("policy.rs");

/// A routine treasury payment that satisfies every configured policy must not
/// be escalated. The tool is only useful if an approved payment reads as an
/// approved payment, with its exact effect still reported as evidence.
#[test]
fn approved_treasury_payment_is_not_escalated() {
    let (snapshot, config) = snapshot(&[100], key(7));
    let report = analyze_snapshot(&snapshot, &config);

    assert!(report.complete, "{report:#?}");
    assert_eq!(report.verdict, Verdict::Low, "{report:#?}");
    assert!(codes(&report).is_empty(), "{report:#?}");

    // The absence of findings is not the absence of disclosure: the analyzed
    // option, its transaction, and the decoded instruction are still reported.
    let json = report.to_json();
    assert!(json.contains("\"transaction_count\":\"1\""), "{json}");
    assert!(json.contains("\"instruction_count\":\"1\""), "{json}");
    assert!(json.contains("\"unknown_instructions\":[]"), "{json}");
}

/// The same payment above the operator's large-outflow ratio is reported, so a
/// quiet verdict is a policy result rather than a blind spot.
#[test]
fn the_same_payment_escalates_once_it_crosses_the_configured_ratio() {
    let (snapshot, config) = snapshot(&[2_600], key(7));
    let report = analyze_snapshot(&snapshot, &config);

    assert!(report.complete, "{report:#?}");
    assert_eq!(
        codes(&report),
        vec!["LARGE_TREASURY_OUTFLOW"],
        "{report:#?}"
    );
}
