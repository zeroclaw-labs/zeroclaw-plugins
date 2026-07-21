//! Run one live proposal analysis outside the ZeroClaw host.
//!
//! The component itself talks to `wasi:http` through `waki`. This example
//! exercises the exact same pure core across the same `Transport` seam, but
//! posts through `curl`, so a reviewer can reproduce a mainnet result without
//! building a plugin-capable host and without adding a networking dependency
//! to the plugin.
//!
//! ```bash
//! cargo run --example live_lookup -- 6wR1jdhhJ31bbdRNXva8MxqsgsNLKTxargcdAyZ7FcRj
//! ```
//!
//! Operator configuration is read from the environment using the same key
//! names the host injects, prefixed with `REALMS_`. Only `proposal_address`
//! comes from the command line, mirroring what a model is allowed to supply.

use std::{
    collections::HashMap,
    io::Write,
    process::{Command, Stdio},
};

use realms_proposal_firewall::{
    analysis::analyze_proposal,
    config::Config,
    pubkey::Pubkey,
    rpc::{Transport, TransportError, TransportResponse},
};

const DEFAULT_PROPOSAL: &str = "6wR1jdhhJ31bbdRNXva8MxqsgsNLKTxargcdAyZ7FcRj";
const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const CONFIG_KEYS: &[&str] = &[
    "rpc_url",
    "expected_genesis_hash",
    "governance_program_ids",
    "allowed_destination_owners",
    "allowed_mints",
    "max_transactions",
    "max_instructions",
    "large_outflow_bps",
    "critical_outflow_bps",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proposal_address: Pubkey = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_PROPOSAL.to_owned())
        .parse()
        .map_err(|_| "proposal_address is not a valid Solana public key")?;

    let mut section: HashMap<String, String> = HashMap::new();
    for key in CONFIG_KEYS {
        if let Ok(value) = std::env::var(format!("REALMS_{}", key.to_uppercase())) {
            section.insert((*key).to_owned(), value);
        }
    }
    section
        .entry("rpc_url".to_owned())
        .or_insert_with(|| DEFAULT_RPC_URL.to_owned());
    section
        .entry("expected_genesis_hash".to_owned())
        .or_insert_with(|| MAINNET_GENESIS_HASH.to_owned());

    let config = Config::from_section(&section)
        .map_err(|error| format!("invalid operator configuration: {error}"))?;

    eprintln!(
        "analyzing {proposal_address} through {} at finalized commitment",
        config.rpc_url
    );

    let report = analyze_proposal(&config, proposal_address, CurlTransport)
        .map_err(|error| error.to_string())?;
    println!("{}", report.to_json());
    Ok(())
}

/// Posts JSON-RPC through the `curl` binary. Native errors are collapsed into
/// the same non-sensitive variants the component's `waki` transport reports.
struct CurlTransport;

impl Transport for CurlTransport {
    fn post(
        &self,
        url: &str,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<TransportResponse, TransportError> {
        let mut child = Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "30",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/json",
                "--header",
                "Accept: application/json",
                "--data-binary",
                "@-",
                "--write-out",
                "%{http_code}",
                url,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| TransportError::Connection)?;
        child
            .stdin
            .take()
            .ok_or(TransportError::Other)?
            .write_all(body)
            .map_err(|_| TransportError::Connection)?;
        let output = child
            .wait_with_output()
            .map_err(|_| TransportError::Connection)?;
        if !output.status.success() {
            // curl exit code 28 is a timeout; everything else is a connection
            // class failure for the purposes of this transport.
            return Err(match output.status.code() {
                Some(28) => TransportError::Timeout,
                _ => TransportError::Connection,
            });
        }

        let mut combined = output.stdout;
        if combined.len() < 3 {
            return Err(TransportError::Other);
        }
        let status_bytes = combined.split_off(combined.len() - 3);
        let status: u16 = std::str::from_utf8(&status_bytes)
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or(TransportError::Other)?;
        if status != 200 {
            return Ok(TransportResponse {
                status,
                body: Vec::new(),
            });
        }
        if combined.len() > max_response_bytes {
            return Err(TransportError::ResponseTooLarge);
        }
        Ok(TransportResponse {
            status,
            body: combined,
        })
    }
}
