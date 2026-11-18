//! The package has two names and they are not interchangeable.
//!
//! `manifest.toml` carries the package id an operator installs and configures
//! (`nonce-status`). The component exports a tool name the model calls
//! (`nonce_status`). The host resolves config by package id and dispatches calls by
//! exported tool name, so a rename on either side silently breaks the other half:
//! config would land on a package nobody dispatches to, or the model would call a
//! tool with no config. Nothing else in the tree pins the pair, so this does.
//!
//! Liveness is the other half of the boundary. A component that instantiates is
//! not necessarily a component the host will call: it also has to export this
//! exact name. The demo rig proves the call end to end; this test proves the name
//! the rig depends on has not drifted.

use std::fs;

const PACKAGE_ID: &str = "nonce-status";
const EXPORTED_TOOL: &str = "nonce_status";

#[test]
fn the_manifest_declares_the_package_id() {
    let manifest = fs::read_to_string("manifest.toml").expect("manifest.toml");
    let declared = manifest
        .lines()
        .find_map(|l| l.strip_prefix("name = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect("manifest declares a name");
    assert_eq!(declared, PACKAGE_ID, "the installed package id moved");
}

#[test]
fn the_component_exports_the_tool_name_the_host_dispatches() {
    let lib = fs::read_to_string("src/lib.rs").expect("src/lib.rs");
    let quoted = format!("\"{EXPORTED_TOOL}\"");
    assert!(
        lib.contains(&quoted),
        "src/lib.rs no longer exports {EXPORTED_TOOL}; the host would dispatch nothing"
    );
}

#[test]
fn the_two_names_correspond_by_the_documented_transform() {
    // The only sanctioned difference is the separator: hyphens in the package id,
    // underscores in the exported tool name.
    assert_eq!(PACKAGE_ID.replace('-', "_"), EXPORTED_TOOL);
}
