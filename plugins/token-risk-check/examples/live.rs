//! Host-side harness: run the exact core pipeline on saved RPC responses.
//! Usage: cargo run --example live -- <mint> <account.json> <supply.json> <largest.json>
//! (Fetch the files with curl; keeps `cargo test` network-free per the rules.)

use token_risk_check::{risk, rpc, spl};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, mint, acc, sup, lar] = &args[..] else {
        eprintln!("usage: live <mint> <account.json> <supply.json> <largest.json>");
        std::process::exit(2);
    };
    let read = |p: &String| std::fs::read_to_string(p).expect("read fixture");

    let (owner, data) = rpc::parse_account_info(&read(acc))
        .expect("account parse")
        .expect("mint exists");
    let info = spl::parse_mint(&data).expect("mint layout");
    let (supply, _) = rpc::parse_token_supply(&read(sup)).expect("supply parse");
    let largest = rpc::parse_largest_amounts(&read(lar)).unwrap_or_else(|e| {
        eprintln!("[holder data unavailable: {e}]");
        Vec::new()
    });
    let report = risk::analyze(&info, &owner, supply, &largest).expect("analyze");
    println!("{}", risk::render(mint, &report));
    println!("--- extensions: {:?}", info.extensions);
}
