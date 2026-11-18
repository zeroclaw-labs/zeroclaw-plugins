//! Demo driver for the `spl-transfer-build` component.
//!
//! Reads one tool-call JSON (exactly what the host passes to the component's
//! `execute`) on stdin, runs the component's own `builder::run` on the host
//! target, and prints the component's output plus the number of RPC round
//! trips it made. This is the same source the wasm export calls; the only
//! substitution is the transport, which the component reaches through the
//! `Lookups` trait either way.
//!
//! It cannot sign and it cannot send: `builder::run` returns unsigned bytes
//! and there is no keypair anywhere in this binary.

#[path = "../../common/transport.rs"]
mod transport;

use spl_transfer_build::builder::{run, Lookups};

struct Transport(transport::Curl);

impl Lookups for Transport {
    fn rpc(&mut self, body: &str) -> Result<String, String> {
        self.0.post(body)
    }
}

fn main() {
    let args = transport::args_from_stdin();
    let mut t = Transport(transport::Curl::from_env());
    match run(&args, &mut t) {
        Ok(out) => {
            let mut v: serde_json::Value = serde_json::from_str(&out).expect("component json");
            // Report the decoded size too: a reader can check the byte count
            // against the base64 without trusting this line.
            if let Some(b64) = v["unsigned_transaction_base64"].as_str() {
                let bytes = solana_core_wasi::encoding::base64_decode(b64)
                    .map(|b| b.len())
                    .unwrap_or(0);
                v["unsigned_transaction_bytes"] = serde_json::json!(bytes);
            }
            transport::emit(true, v, t.0.calls);
        }
        Err(e) => transport::emit(false, serde_json::json!(e.to_string()), t.0.calls),
    }
}
