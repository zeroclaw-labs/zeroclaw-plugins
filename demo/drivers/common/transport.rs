//! JSON-RPC transport for the demo drivers.
//!
//! On wasm each component POSTs through `waki` (the host performs TLS). The
//! drivers are host binaries, so they shell out to `curl` instead: same
//! request bytes, same response bytes, no extra crate in the dependency
//! graph. The component core cannot tell the difference; it only sees the
//! `Lookups` trait.
//!
//! Configuration is environment-only, so a scenario file never carries an
//! endpoint the component did not get from operator config:
//!   ZC_RPC_URL     endpoint curl posts to (required)
//!   ZC_CACERT      CA file for the local fake's self-signed certificate
//!   ZC_TRANSCRIPT  append every request and response here as JSON lines
//!   ZC_TIMEOUT     per-call timeout in seconds, default 20

use std::io::Write;
use std::process::{Command, Stdio};

pub struct Curl {
    url: String,
    cacert: Option<String>,
    transcript: Option<String>,
    timeout: String,
    /// Number of RPC round trips this run made. A refusal that never reaches
    /// the network leaves this at 0, which is the claim worth printing.
    pub calls: u32,
}

impl Curl {
    pub fn from_env() -> Self {
        Self {
            url: std::env::var("ZC_RPC_URL").expect("ZC_RPC_URL is required"),
            cacert: std::env::var("ZC_CACERT").ok().filter(|s| !s.is_empty()),
            transcript: std::env::var("ZC_TRANSCRIPT").ok().filter(|s| !s.is_empty()),
            timeout: std::env::var("ZC_TIMEOUT").unwrap_or_else(|_| "20".to_string()),
            calls: 0,
        }
    }

    pub fn post(&mut self, body: &str) -> Result<String, String> {
        self.calls += 1;
        let mut cmd = Command::new("curl");
        cmd.arg("-sS")
            .arg("-m")
            .arg(&self.timeout)
            .arg("-X")
            .arg("POST")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("--data-binary")
            .arg("@-");
        if let Some(ca) = &self.cacert {
            cmd.arg("--cacert").arg(ca);
        }
        cmd.arg(&self.url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| format!("curl spawn: {e}"))?;
        child
            .stdin
            .as_mut()
            .ok_or("curl stdin")?
            .write_all(body.as_bytes())
            .map_err(|e| format!("curl write: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("curl wait: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        self.record(body, &stdout, &stderr, out.status.code());
        if !out.status.success() {
            return Err(format!(
                "curl exit {}: {}",
                out.status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }
        Ok(stdout)
    }

    fn record(&self, body: &str, stdout: &str, stderr: &str, code: Option<i32>) {
        let Some(path) = &self.transcript else {
            return;
        };
        let line = serde_json::json!({
            "call": self.calls,
            "url": self.url,
            "curl_exit": code,
            "request": serde_json::from_str::<serde_json::Value>(body)
                .unwrap_or_else(|_| serde_json::json!(body)),
            "response": serde_json::from_str::<serde_json::Value>(stdout)
                .unwrap_or_else(|_| serde_json::json!(stdout)),
            "stderr": stderr,
        });
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Read the tool arguments from stdin. Keeping args off the command line means
/// a shell quoting slip can never rewrite a policy value.
pub fn args_from_stdin() -> String {
    use std::io::Read;
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("read stdin");
    s
}

/// Print the result the way every driver prints it: one JSON object with the
/// component's own output, the RPC call count and nothing invented.
pub fn emit(ok: bool, payload: serde_json::Value, calls: u32) {
    let out = if ok {
        serde_json::json!({ "ok": true, "rpc_calls": calls, "result": payload })
    } else {
        serde_json::json!({ "ok": false, "rpc_calls": calls, "error": payload })
    };
    println!("{out}");
}
