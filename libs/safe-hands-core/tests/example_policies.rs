use safe_hands_core::policy::Policy;
use std::path::Path;

#[test]
fn every_shipped_policy_parses_through_the_real_schema() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("safe-hands-core lives under repository/libs");

    for filename in ["merchant.json", "treasury.json"] {
        let path = repository.join("examples").join("policies").join(filename);
        let document = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
        Policy::from_json(&document).unwrap_or_else(|error| {
            panic!(
                "{} is not a valid Safe Hands policy: {error}",
                path.display()
            )
        });
    }
}
