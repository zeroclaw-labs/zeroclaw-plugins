//! The policies we ship to operators must parse through the real schema.
//!
//! These files live in the repository, not in this crate, so the test reaches
//! outside `CARGO_MANIFEST_DIR`. That is fine in the repository and wrong
//! anywhere else: vendored or copied on its own, the crate would fail a test
//! for a reason that has nothing to do with the crate. `cargo mutants` found
//! this by building the crate in a temporary directory, where the examples do
//! not exist and the test panicked before a single mutant could be scored.
//!
//! So absence of the examples is a skip, not a failure — and a skip that says
//! so out loud, because a silently-passing test that checks nothing is worse
//! than the failure it replaces.

use safe_hands_core::policy::Policy;
use std::path::Path;

#[test]
fn every_shipped_policy_parses_through_the_real_schema() {
    let Some(repository) = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
    else {
        println!("skipped: cannot resolve the repository root from CARGO_MANIFEST_DIR");
        return;
    };

    let policies = repository.join("examples").join("policies");
    if !policies.is_dir() {
        println!(
            "skipped: {} is not present — this crate is being built outside the repository",
            policies.display()
        );
        return;
    }

    let mut checked = 0;
    for filename in ["merchant.json", "treasury.json"] {
        let path = policies.join(filename);
        let document = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
        Policy::from_json(&document).unwrap_or_else(|error| {
            panic!(
                "{} is not a valid Safe Hands policy: {error}",
                path.display()
            )
        });
        checked += 1;
    }

    assert_eq!(
        checked, 2,
        "both shipped policies must be checked when the examples are present"
    );
}
