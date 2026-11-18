//! Demo driver for the `payment-watch` component.
//!
//! Reads one tool-call JSON on stdin, runs the component's own `watcher::run`
//! on the host target, prints its verdict line and the RPC call count. Read
//! only: two bounded lookups, no keys, nothing to sign.

#[path = "../../common/transport.rs"]
mod transport;

use payment_watch::watcher::{run, Lookups};

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
            let v: serde_json::Value = serde_json::from_str(&out).expect("component json");
            transport::emit(true, v, t.0.calls);
        }
        Err(e) => transport::emit(false, serde_json::json!(e.to_string()), t.0.calls),
    }
}
