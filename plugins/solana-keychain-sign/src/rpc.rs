//! Solana JSON-RPC client for `solana-keychain-sign`.
//!
//! Three operations the signer needs:
//!   - [`RpcClient::get_latest_blockhash`] — called at **sign time**, not
//!     build time. This is THE answer to bounty Trap #1: a blockhash fetched
//!     at build time can expire during human approval, so the signer re-fetches
//!     a fresh one immediately before posting to the backend.
//!   - [`RpcClient::send_transaction`] — submits a base64-encoded signed
//!     [`VersionedTransaction`] with `preflight_commitment: "confirmed"`.
//!   - [`RpcClient::get_signature_status`] — polls confirmation status for a
//!     signature.
//!
//! [`RpcClient::submit_and_confirm`] orchestrates the three: send, then poll
//! until the tx lands (confirmed or finalized), fails, or times out at
//! `confirm_timeout_secs`.
//!
//! ## Pure core + thin shim
//!
//! The trait seam is [`RpcTransport`] — a single `post_json` method. The
//! [`RpcClient<T>`] generic is fully host-testable against a mock transport;
//! the wasm-only [`WakiTransport`] impl lives under `cfg(target_family =
//! "wasm")` so the host test build never pulls in `waki` or `wasi:http`.

use core::time::Duration;
use serde_json::{json, Value};

/// JSON-RPC protocol version string — every request envelope.
const JSONRPC_VERSION: &str = "2.0";

/// Default confirmation timeout (seconds) when none is configured. See
/// [`RpcClient::new`].
pub const DEFAULT_CONFIRM_TIMEOUT_SECS: u64 = 30;

/// Default poll interval (milliseconds) for confirmation status. ~2s matches
/// the Solana mainnet slot time; overridable via [`RpcClient::new_full`] for
/// tests that need a tight loop.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 2_000;

/// Result of a successful `getLatestBlockhash` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blockhash {
    /// Base58-encoded recent blockhash.
    pub blockhash: String,
    /// Last block height at which this blockhash is still valid. Tracked for
    /// future use (re-submission / expiry messaging); the poll loop currently
    /// keys off `confirm_timeout_secs` only.
    pub last_valid_block_height: u64,
}

/// Signature confirmation status decoded from `getSignatureStatuses`.
///
/// `processed` alone is treated as [`Confirmation::Pending`] — the signer's
/// poll loop waits for at least `confirmed` (cluster-voted) before declaring
/// success, the conservative choice for an irreversible funds movement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    /// Entry present but `confirmationStatus` is `processed` (landed in a
    /// slot, not yet voted on by the cluster) — keep polling.
    Pending { slot: u64 },
    /// `confirmationStatus` is `confirmed` or `finalized` (err == null).
    Confirmed { slot: u64, level: String },
    /// Transaction landed but with a non-null `err` — hard stop, surface to
    /// the operator.
    Failed { slot: u64, err: String },
}

/// Low-level HTTP transport — abstracted so host tests supply a mock and the
/// wasm component supplies [`WakiTransport`]. Implementations are responsible
/// for any auth headers (the public Solana RPC needs none).
pub trait RpcTransport {
    /// POST `body` to `url` and return the parsed JSON response. Errors are
    /// operator-facing strings (no secrets should appear in `url`).
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, String>;
}

/// Generic Solana RPC client. The transport `T` makes this mockable in tests;
/// in the wasm component `T = WakiTransport`.
pub struct RpcClient<T: RpcTransport> {
    pub rpc_url: String,
    pub transport: T,
    /// Poll deadline for [`Self::submit_and_confirm`]. Clamped to ≥1 second.
    pub confirm_timeout_secs: u64,
    /// Sleep between confirmation polls. Default 2s; tests typically pass 0.
    pub poll_interval_ms: u64,
}

impl<T: RpcTransport> RpcClient<T> {
    /// Construct with the default 2s poll interval.
    pub fn new(rpc_url: impl Into<String>, transport: T, confirm_timeout_secs: u64) -> Self {
        Self::new_full(
            rpc_url,
            transport,
            confirm_timeout_secs,
            DEFAULT_POLL_INTERVAL_MS,
        )
    }

    /// Construct with every knob exposed. Used by tests to set a tight poll
    /// interval; production code should prefer [`Self::new`].
    pub fn new_full(
        rpc_url: impl Into<String>,
        transport: T,
        confirm_timeout_secs: u64,
        poll_interval_ms: u64,
    ) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            transport,
            // Clamp to ≥1s — a zero timeout would reject even instant
            // confirmations on a slow clock.
            confirm_timeout_secs: confirm_timeout_secs.max(1),
            poll_interval_ms,
        }
    }

    /// Fetch the latest recent blockhash + its last-valid block height.
    ///
    /// Called at **sign time** by the submit flow, NOT at build time. A
    /// blockhash fetched during `solana-build-tx` could easily expire across
    /// the human approval window; re-fetching here is the canonical fix for
    /// bounty Trap #1.
    pub fn get_latest_blockhash(&self) -> Result<Blockhash, String> {
        let req = build_request("getLatestBlockhash", &json!([]));
        let resp = self.transport.post_json(&self.rpc_url, &req)?;
        if let Some(err) = resp.get("error") {
            return Err(format!("getLatestBlockhash rpc error: {err}"));
        }
        let value = resp
            .get("result")
            .and_then(|r| r.get("value"))
            .ok_or_else(|| format!("getLatestBlockhash: missing result.value: {resp}"))?;
        let blockhash = value
            .get("blockhash")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("getLatestBlockhash: missing blockhash string: {resp}"))?
            .to_string();
        let last_valid_block_height = value
            .get("lastValidBlockHeight")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("getLatestBlockhash: missing lastValidBlockHeight: {resp}"))?;
        Ok(Blockhash {
            blockhash,
            last_valid_block_height,
        })
    }

    /// Submit a base64-encoded signed [`VersionedTransaction`]. Preflight
    /// commitment is pinned to `confirmed`; `max_retries: 0` because the
    /// signer runs its own poll loop rather than relying on the RPC's retry.
    ///
    /// Returns the transaction signature (base58) on success.
    pub fn send_transaction(&self, signed_tx_b64: &str) -> Result<String, String> {
        let req = build_request(
            "sendTransaction",
            &json!([
                signed_tx_b64,
                {
                    "preflight_commitment": "confirmed",
                    "encoding": "base64",
                    "max_retries": 0,
                }
            ]),
        );
        let resp = self.transport.post_json(&self.rpc_url, &req)?;
        if let Some(err) = resp.get("error") {
            return Err(format!("sendTransaction rpc error: {err}"));
        }
        let sig = resp
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("sendTransaction: missing result string: {resp}"))?
            .to_string();
        Ok(sig)
    }

    /// Look up the confirmation status of a single signature. Returns
    /// `Ok(None)` when the RPC has no record of the signature yet (the common
    /// case in the first poll after `sendTransaction`).
    pub fn get_signature_status(&self, signature: &str) -> Result<Option<Confirmation>, String> {
        let req = build_request("getSignatureStatuses", &json!([[signature]]));
        let resp = self.transport.post_json(&self.rpc_url, &req)?;
        if let Some(err) = resp.get("error") {
            return Err(format!("getSignatureStatuses rpc error: {err}"));
        }
        let arr = resp
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(Value::as_array)
            .ok_or_else(|| format!("getSignatureStatuses: missing result.value array: {resp}"))?;
        let entry = arr.first().unwrap_or(&Value::Null);
        decode_signature_status(entry)
    }

    /// Submit a signed transaction and poll until it is confirmed/finalized,
    /// fails, or `confirm_timeout_secs` elapses.
    ///
    /// This is the single canonical submit path for the signer —
    /// `submit.rs` calls it after assembling the signed versioned tx.
    ///
    /// Returns the signature on success, or an operator-facing error string
    /// on RPC failure, simulation revert, or timeout.
    pub fn submit_and_confirm(&self, signed_tx_b64: &str) -> Result<String, String> {
        let signature = self.send_transaction(signed_tx_b64)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(self.confirm_timeout_secs);
        let sleep = Duration::from_millis(self.poll_interval_ms);
        loop {
            if sleep > Duration::ZERO {
                std::thread::sleep(sleep);
            }
            match self.get_signature_status(&signature)? {
                Some(Confirmation::Confirmed { .. }) => return Ok(signature),
                Some(Confirmation::Failed { err, .. }) => {
                    return Err(format!("transaction landed with error: {err}"))
                }
                Some(Confirmation::Pending { .. }) | None => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "timeout: signature not confirmed within {}s: {signature}",
                    self.confirm_timeout_secs
                ));
            }
        }
    }
}

// ── pure helpers — usable without an RpcTransport ───────────────────────────

/// Build a JSON-RPC 2.0 request envelope. `id` is fixed at 1 — the signer
/// never multiplexes requests on a single transport.
pub fn build_request(method: &str, params: &Value) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 1,
        "method": method,
        "params": params,
    })
}

/// Decode a single `getSignatureStatuses` `value[i]` entry into a
/// [`Confirmation`]. `Value::Null` (signature not seen yet) → `None`.
/// Extracted as a free function so the classification logic is unit-testable
/// without spinning up a mock transport.
pub fn decode_signature_status(entry: &Value) -> Result<Option<Confirmation>, String> {
    if entry.is_null() {
        return Ok(None);
    }
    let slot = entry.get("slot").and_then(Value::as_u64).unwrap_or(0);
    let level = entry
        .get("confirmationStatus")
        .and_then(Value::as_str)
        .unwrap_or("");
    match entry.get("err") {
        // err absent OR explicitly null → did not fail.
        None | Some(Value::Null) => {
            if level == "confirmed" || level == "finalized" {
                Ok(Some(Confirmation::Confirmed {
                    slot,
                    level: level.to_string(),
                }))
            } else {
                // "processed" or unknown — keep polling.
                Ok(Some(Confirmation::Pending { slot }))
            }
        }
        Some(err_val) => Ok(Some(Confirmation::Failed {
            slot,
            err: err_val.to_string(),
        })),
    }
}

// ── wasm-only transport impl ────────────────────────────────────────────────

#[cfg(target_family = "wasm")]
mod waki_transport {
    use super::RpcTransport;
    use serde_json::Value;

    /// `waki`-backed [`RpcTransport`] for the wasm32-wasip2 component. Performs
    /// blocking `wasi:http` POSTs — TLS termination happens host-side per the
    /// ZeroClaw jail model. No auth header is added (Solana RPC is unauth);
    /// private RPCs with API keys in the URL work as-is.
    #[derive(Debug, Clone, Default)]
    pub struct WakiTransport;

    impl WakiTransport {
        pub fn new() -> Self {
            Self
        }
    }

    impl RpcTransport for WakiTransport {
        fn post_json(&self, url: &str, body: &Value) -> Result<Value, String> {
            let resp = waki::Client::new()
                .post(url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(body)
                .send()
                .map_err(|e| format!("waki POST {url} failed: {e}"))?;
            let val = resp
                .json::<Value>()
                .map_err(|e| format!("waki decode JSON from {url} failed: {e}"))?;
            Ok(val)
        }
    }
}

#[cfg(target_family = "wasm")]
pub use waki_transport::WakiTransport;
