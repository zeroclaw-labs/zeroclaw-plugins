//! Run one tool call from a JSON argument: `run '{"op":"pubkey_decode",...}'`.
fn main() {
    let arg = std::env::args().nth(1).expect("usage: run '<json args>'");
    let (out, ok) = solana_verify::handler::run(&arg);
    let pretty = serde_json::from_str::<serde_json::Value>(&out)
        .map(|v| serde_json::to_string_pretty(&v).unwrap())
        .unwrap_or(out);
    println!("{pretty}");
    std::process::exit(if ok { 0 } else { 1 });
}
