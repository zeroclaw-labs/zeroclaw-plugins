//! Run one tool call from a JSON argument: `run '{"op":"pubkey_decode",...}'`.
//!
//! Pure-compute ops (merkle_verify, ed25519_verify, pubkey_*) need nothing else.
//! The live `merkle_verify_onchain` op reads an anchored root from chain; on the host
//! there is no `wasi:http`, so pass a second argument pointing at a pre-fetched
//! `getAccountInfo` response file — exactly what `demo.sh` curls from a live RPC. The
//! example then runs the REAL `handler::run` against that real chain data, so the judge
//! sees the exact verdict the wasm component produces, with no mocking of the logic.
//!
//! Usage: run '<json args>' [getAccountInfo.json]
use serde_json::Value;
use solana_verify::handler;

fn main() {
    let arg = std::env::args().nth(1).expect("usage: run '<json args>' [getAccountInfo.json]");

    // Optional file-backed fetcher: return the pre-fetched getAccountInfo response so the
    // live op runs on real chain data with no host HTTP. Pure ops never call it.
    let acct_file = std::env::args().nth(2);
    let acct: Value = acct_file
        .as_ref()
        .map(|p| {
            serde_json::from_str(&std::fs::read_to_string(p).expect("read account json"))
                .expect("parse account json")
        })
        .unwrap_or(Value::Null);
    let fetch = move |_url: &str, method: &str, _params: Value| -> Result<Value, String> {
        match method {
            "getAccountInfo" if !acct.is_null() => Ok(acct.clone()),
            "getAccountInfo" => Err("no pre-fetched account file (pass it as the 2nd argument)".into()),
            other => Err(format!("unexpected method {other}")),
        }
    };

    let (out, ok) = handler::run(&arg, &fetch);
    let pretty = serde_json::from_str::<Value>(&out)
        .map(|v| serde_json::to_string_pretty(&v).unwrap())
        .unwrap_or(out);
    println!("{pretty}");
    std::process::exit(if ok { 0 } else { 1 });
}
