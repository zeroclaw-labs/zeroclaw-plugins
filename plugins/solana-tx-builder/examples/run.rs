//! Run one tool call from a JSON argument: `run '{"op":"system_transfer",...}'`.
//! Used by the top-level compose-demo to chain this plugin after the risk scan.
//!
//! Pure construction ops (derive_pda, derive_ata, system_transfer, spl_transfer) need
//! nothing else. The live `prepare_transfer` op reads a recent blockhash and the
//! recipient's account; on the host there is no `wasi:http`, so pass pre-fetched RPC
//! responses as extra arguments — exactly what a demo curls from a live RPC. The example
//! then runs the REAL `handler::run` against that real chain data, no mocking of the logic.
//!
//! Usage: run '<json args>' [getLatestBlockhash.json] [getAccountInfo.json]
use serde_json::Value;
use solana_tx_builder::handler;

fn main() {
    let arg = std::env::args().nth(1).expect("usage: run '<json args>' [blockhash.json] [account.json]");
    let read = |n: usize| -> Value {
        std::env::args()
            .nth(n)
            .map(|p| {
                serde_json::from_str(&std::fs::read_to_string(&p).expect("read json file"))
                    .expect("parse json file")
            })
            .unwrap_or(Value::Null)
    };
    let blockhash = read(2);
    let account = read(3);
    let fetch = move |_url: &str, method: &str, _params: Value| -> Result<Value, String> {
        match method {
            "getLatestBlockhash" if !blockhash.is_null() => Ok(blockhash.clone()),
            "getAccountInfo" if !account.is_null() => Ok(account.clone()),
            m @ ("getLatestBlockhash" | "getAccountInfo") =>
                Err(format!("no pre-fetched response for {m} (pass it as an argument)")),
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
