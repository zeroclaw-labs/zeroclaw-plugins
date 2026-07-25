//! Attestation chain recovery: derive the next `(seq, prev_signature)` for a
//! device address from a SINGLE `getSignaturesForAddress` call.
//!
//! `getSignaturesForAddress` returns the newest signatures first, each with its
//! `memo`. We read the newest attestation's memo, take its `seq`, and hand back
//! `seq + 1` plus that signature as the `prev` link — so the next attestation
//! chains onto it. A device with no history is fresh: `(0, None)`. A newest
//! transaction whose memo is absent or not attestation JSON is a **gap** (the
//! chain is broken or something else wrote to the address) — surfaced, never
//! silently treated as fresh.

use serde_json::{json, Value};

use crate::rpc::{RpcClient, RpcError, RpcTransport};

#[derive(Debug, PartialEq)]
pub struct ChainState {
    /// The seq the NEXT attestation should use.
    pub seq: u64,
    /// The previous landed signature this attestation should chain onto.
    pub prev_signature: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum ChainError {
    Rpc(String),
    Decode(String),
    /// The device has history, but the newest tx is not a readable attestation.
    Gap(String),
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::Rpc(m) => write!(f, "rpc error: {m}"),
            ChainError::Decode(m) => write!(f, "malformed rpc response: {m}"),
            ChainError::Gap(m) => write!(f, "attestation chain gap: {m}"),
        }
    }
}

impl From<RpcError> for ChainError {
    fn from(e: RpcError) -> Self {
        match e {
            RpcError::Transport(m) => ChainError::Rpc(m),
            RpcError::Rpc { code, message } => ChainError::Rpc(format!("{code}: {message}")),
            RpcError::Decode(m) => ChainError::Decode(m),
        }
    }
}

/// Recover the next chain state for `device` in one RPC round-trip.
pub fn recover<T: RpcTransport>(
    device: &str,
    transport: T,
    finality: &str,
) -> Result<ChainState, ChainError> {
    let client = RpcClient::new(transport);
    let res = client.call(
        "getSignaturesForAddress",
        json!([device, { "commitment": finality, "limit": 1 }]),
    )?;
    let arr = res.as_array().ok_or_else(|| {
        ChainError::Decode("getSignaturesForAddress did not return an array".into())
    })?;

    let newest = match arr.first() {
        Some(x) => x,
        None => {
            return Ok(ChainState {
                seq: 0,
                prev_signature: None,
            })
        } // fresh device
    };

    let signature = newest
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| ChainError::Decode("signature entry missing `signature`".into()))?
        .to_string();

    let memo = newest
        .get("memo")
        .and_then(Value::as_str)
        .ok_or_else(|| ChainError::Gap("newest device tx has no memo".into()))?;

    let json_str = extract_json(memo)
        .ok_or_else(|| ChainError::Gap("newest memo is not attestation JSON".into()))?;
    let parsed: Value = serde_json::from_str(json_str)
        .map_err(|_| ChainError::Gap("newest memo JSON is unparseable".into()))?;
    let last_seq = parsed
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| ChainError::Gap("newest memo has no seq field".into()))?;

    Ok(ChainState {
        seq: last_seq + 1,
        prev_signature: Some(signature),
    })
}

/// The RPC `memo` field may be prefixed (e.g. `"[31] {...}"`). Return the
/// substring from the first `{` — our attestation memos are JSON objects.
fn extract_json(memo: &str) -> Option<&str> {
    memo.find('{').map(|i| &memo[i..])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock(Result<String, RpcError>);
    impl RpcTransport for Mock {
        fn send(&self, _req: &str) -> Result<String, RpcError> {
            self.0.clone()
        }
    }
    fn ok(result_json: &str) -> Mock {
        Mock(Ok(format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#
        )))
    }

    #[test]
    fn fresh_device_returns_zero_none() {
        let st = recover(
            "Dev11111111111111111111111111111111111111111",
            ok("[]"),
            "confirmed",
        )
        .unwrap();
        assert_eq!(
            st,
            ChainState {
                seq: 0,
                prev_signature: None
            }
        );
    }

    #[test]
    fn existing_chain_increments_seq_and_links_prev() {
        // Newest memo has seq 7 -> next is 8, prev is this signature.
        let sig = "5xNewestSig";
        let m = ok(&format!(
            r#"[{{"signature":"{sig}","slot":100,"memo":"[31] {{\"v\":1,\"dev\":\"k01\",\"seq\":7}}"}}]"#
        ));
        let st = recover(
            "Dev11111111111111111111111111111111111111111",
            m,
            "confirmed",
        )
        .unwrap();
        assert_eq!(st.seq, 8);
        assert_eq!(st.prev_signature.as_deref(), Some(sig));
    }

    #[test]
    fn memo_without_length_prefix_also_parses() {
        let m = ok(r#"[{"signature":"S","memo":"{\"v\":1,\"seq\":41}"}]"#);
        let st = recover(
            "Dev11111111111111111111111111111111111111111",
            m,
            "confirmed",
        )
        .unwrap();
        assert_eq!(st.seq, 42);
    }

    #[test]
    fn gap_when_newest_has_no_memo() {
        let m = ok(r#"[{"signature":"S","memo":null}]"#);
        let err = recover(
            "Dev11111111111111111111111111111111111111111",
            m,
            "confirmed",
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::Gap(_)), "got {err:?}");
    }

    #[test]
    fn gap_when_newest_memo_is_not_attestation_json() {
        let m = ok(r#"[{"signature":"S","memo":"just a plain memo"}]"#);
        let err = recover(
            "Dev11111111111111111111111111111111111111111",
            m,
            "confirmed",
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::Gap(_)), "got {err:?}");
    }

    #[test]
    fn rpc_error_surfaces_never_silently_fresh() {
        let m = Mock(Err(RpcError::Transport("node down".into())));
        let err = recover(
            "Dev11111111111111111111111111111111111111111",
            m,
            "confirmed",
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::Rpc(_)), "got {err:?}");
    }
}
