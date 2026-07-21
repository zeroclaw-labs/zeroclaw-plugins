//! Developer-only, host-run helper for reproducible read-only live checks.
//! Reads one RugCheck report JSON from stdin and prints the same pure-core
//! verdict used by the wasm component when Helius is not configured.

use std::io::Read;

fn main() {
    let mint = std::env::args()
        .nth(1)
        .expect("usage: assess-rugcheck <mint> < report.json");
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read stdin");
    let report: serde_json::Value = serde_json::from_str(&input).expect("valid RugCheck JSON");
    println!(
        "{}",
        token_risk_check::risk::format(&token_risk_check::risk::assess(&report, None), &mint)
    );
}
