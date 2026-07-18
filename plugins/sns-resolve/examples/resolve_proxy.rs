//! Developer-only helper: pipe one SNS SDK proxy JSON response to stdin.
use std::io::Read;

fn main() {
    let domain = std::env::args()
        .nth(1)
        .expect("usage: resolve-proxy <domain> < response.json");
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read stdin");
    let response: serde_json::Value = serde_json::from_str(&input).expect("valid SNS proxy JSON");
    match sns_resolve::resolve::parse_proxy_response(&response) {
        Ok(wallet) => println!("{}", sns_resolve::resolve::format(&domain, &wallet)),
        Err(error) => println!("SNS resolution failed: {error}"),
    }
}
