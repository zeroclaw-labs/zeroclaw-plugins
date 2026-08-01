//! The vendored `solana-core` copy must stay byte-identical across every
//! plugin that carries one.
//!
//! Each plugin here is a standalone crate: the repository's validation
//! snapshots `plugins/<name>` plus `wit/v0` and builds in that directory
//! alone, so a path dependency reaching outside the plugin cannot resolve.
//! The core is therefore vendored into each plugin rather than shared through
//! `libs/`.
//!
//! Vendoring invites drift, so this pins it. The digest below covers the
//! core's Rust sources and its manifest. Every plugin carrying the core
//! asserts the same constant, so editing one copy and not the others turns
//! that plugin red. Update the core with `vendor-core.sh` (which re-copies
//! from a single source), then update this constant in all copies together.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// sha256 over the vendored core's `src/*.rs`, `tests/*.rs` and `Cargo.toml`.
/// Identical in every plugin that vendors the core.
const VENDORED_CORE_DIGEST: &str =
    "cadae0d0f9becba8d9849ec593c8f1f277dbecc95a6cdde06525d151bd694c40";

/// Hash the vendored tree the same way in every plugin: files in a fixed
/// order, each contributing its relative path and its bytes, both
/// NUL-terminated so a rename cannot collide with a content change.
fn digest_vendored_core(root: &Path) -> String {
    let mut files: Vec<PathBuf> = Vec::new();

    for dir in ["src", "tests"] {
        let entries = fs::read_dir(root.join(dir))
            .unwrap_or_else(|e| panic!("cannot read {}/{dir}: {e}", root.display()));
        for entry in entries {
            let path = entry.expect("cannot read directory entry").path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.push(root.join("Cargo.toml"));

    // Sort by the path relative to the core root, so the order does not depend
    // on where the plugin happens to sit on disk.
    let rel = |p: &Path| {
        p.strip_prefix(root)
            .expect("vendored file outside core root")
            .to_string_lossy()
            .replace('\\', "/")
    };
    files.sort_by_key(|p| rel(p));

    let mut hasher = Sha256::new();
    for path in &files {
        hasher.update(rel(path).as_bytes());
        hasher.update([0u8]);
        hasher.update(
            fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display())),
        );
        hasher.update([0u8]);
    }
    format!("{:x}", hasher.finalize())
}

#[test]
fn vendored_core_matches_the_pinned_digest() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("solana-core");
    let actual = digest_vendored_core(&root);

    assert_eq!(
        actual, VENDORED_CORE_DIGEST,
        "the vendored solana-core in this plugin no longer matches the pinned \
         digest.\n\nIf you edited the core, re-run vendor-core.sh so every \
         plugin gets the same bytes, then set VENDORED_CORE_DIGEST to {actual} \
         in each plugin's tests/vendored_core.rs."
    );
}
