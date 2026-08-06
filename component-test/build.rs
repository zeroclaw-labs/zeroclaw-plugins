//! Generate a feature-gate-free copy of `wit/v0` for host bindings.
//!
//! The contract marks every item `@unstable(feature = plugins-wit-v0)`. The
//! guest-side `wit_bindgen::generate!` macro takes a `features` option to
//! switch those on; wasmtime's host-side `bindgen!` has no equivalent, so the
//! gated items would be invisible and the generated bindings empty.
//!
//! Rather than keep a hand-edited second copy that silently drifts from the
//! real contract, this regenerates one on every build by stripping only the
//! gate attributes. Nothing else is altered: if `wit/v0` changes, this copy
//! changes with it, and a contract change that breaks the harness will break
//! the build rather than pass unnoticed.

use std::fs;
use std::path::Path;

fn main() {
    let source = Path::new("../wit/v0");
    let generated = Path::new("wit-generated");

    println!("cargo:rerun-if-changed=../wit/v0");

    fs::create_dir_all(generated).expect("create wit-generated");

    for entry in fs::read_dir(source).expect("read ../wit/v0") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("wit") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read wit file");
        let stripped: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("@unstable("))
            .collect::<Vec<_>>()
            .join("\n");
        let name = path.file_name().expect("wit filename");
        fs::write(generated.join(name), stripped).expect("write generated wit");
    }
}
