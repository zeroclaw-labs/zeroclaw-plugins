//! Solana RPC health checker — pure Rust core (no wasm dependency).
#![allow(dead_code)]

use serde::Serialize;

/// Result returned to the agent.
#[derive(Debug, Serialize)]
pub struct RpcHealthReport {
    pub healthy: bool,
    pub version: Option<String>,
    pub slot: Option<u64>,
    pub epoch: Option<u64>,
    pub epoch_progress_pct: Option<f64>,
    pub transaction_count: Option<u64>,
    pub summary: String,
}

/// Trait for HTTP POST (abstracts over real HTTP client or test mock).
pub trait HttpClient {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
}

/// Check the health of a Solana RPC endpoint.
pub fn check_rpc_health(
    client: &dyn HttpClient,
    rpc_url: &str,
) -> Result<RpcHealthReport, String> {
    // 1. getHealth
    let healthy = check_health(client, rpc_url)?;

    // 2. getVersion
    let version = get_version(client, rpc_url).ok();

    // 3. getSlot
    let slot = get_slot(client, rpc_url).ok();

    // 4. getEpochInfo
    let (epoch, progress_pct, tx_count) = get_epoch_info(client, rpc_url)
        .ok()
        .unwrap_or((None, None, None));

    let summary = if healthy {
        format!(
            "✅ RPC healthy | slot={} epoch={} | {}",
            slot.map_or("?".into(), |s| s.to_string()),
            epoch.map_or("?".into(), |e| e.to_string()),
            version.clone().unwrap_or_else(|| "unknown version".into())
        )
    } else {
        "🔴 RPC unhealthy".to_string()
    };

    Ok(RpcHealthReport {
        healthy,
        version,
        slot,
        epoch,
        epoch_progress_pct: progress_pct,
        transaction_count: tx_count,
        summary,
    })
}

fn rpc_call(
    client: &dyn HttpClient,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();

    let resp = client.post_json(rpc_url, &body)?;
    serde_json::from_str(&resp).map_err(|e| format!("RPC parse error: {e}"))
}

fn check_health(client: &dyn HttpClient, rpc_url: &str) -> Result<bool, String> {
    let v = rpc_call(client, rpc_url, "getHealth", serde_json::json!([]))?;
    match v["result"].as_str() {
        Some("ok") => Ok(true),
        _ => Ok(false),
    }
}

fn get_version(client: &dyn HttpClient, rpc_url: &str) -> Result<String, String> {
    let v = rpc_call(client, rpc_url, "getVersion", serde_json::json!([]))?;
    let solana_core = v["result"]["solana-core"]
        .as_str()
        .unwrap_or("unknown");
    let feature_set = v["result"]["feature-set"]
        .as_u64()
        .map(|f| f.to_string())
        .unwrap_or_else(|| "?".into());
    Ok(format!("solana-core {} (feature-set {})", solana_core, feature_set))
}

fn get_slot(client: &dyn HttpClient, rpc_url: &str) -> Result<u64, String> {
    let v = rpc_call(client, rpc_url, "getSlot", serde_json::json!([]))?;
    v["result"]
        .as_u64()
        .ok_or_else(|| "getSlot: missing result".into())
}

fn get_epoch_info(
    client: &dyn HttpClient,
    rpc_url: &str,
) -> Result<(Option<u64>, Option<f64>, Option<u64>), String> {
    let v = rpc_call(client, rpc_url, "getEpochInfo", serde_json::json!([]))?;
    let info = &v["result"];

    let epoch = info["epoch"].as_u64();
    let slot_index = info["slotIndex"].as_u64().unwrap_or(0);
    let slots_in_epoch = info["slotsInEpoch"].as_u64().unwrap_or(1);
    let transaction_count = info["transactionCount"].as_u64();

    let progress_pct = if slots_in_epoch > 0 {
        Some((slot_index as f64 / slots_in_epoch as f64) * 100.0)
    } else {
        None
    };

    Ok((epoch, progress_pct, transaction_count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct MockClient {
        responses: RefCell<VecDeque<String>>,
    }

    impl MockClient {
        fn new(responses: Vec<String>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
            }
        }
    }

    impl HttpClient for MockClient {
        fn post_json(&self, _url: &str, _body: &str) -> Result<String, String> {
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| "no mock response".into())
        }
    }

    #[test]
    fn test_healthy_rpc() {
        let health = r#"{"jsonrpc":"2.0","result":"ok","id":1}"#.to_string();
        let version = r#"{"jsonrpc":"2.0","result":{"solana-core":"2.1.0","feature-set":12345},"id":1}"#.to_string();
        let slot = r#"{"jsonrpc":"2.0","result":320000000,"id":1}"#.to_string();
        let epoch = r#"{"jsonrpc":"2.0","result":{"epoch":700,"slotIndex":100000,"slotsInEpoch":432000,"transactionCount":999999999},"id":1}"#.to_string();

        let client = MockClient::new(vec![health, version, slot, epoch]);
        let report = check_rpc_health(&client, "http://localhost").expect("should succeed");

        assert!(report.healthy);
        assert_eq!(report.slot, Some(320000000));
        assert_eq!(report.epoch, Some(700));
        assert!(report.version.unwrap().contains("2.1.0"));
        assert!(report.summary.starts_with("✅"));
    }

    #[test]
    fn test_unhealthy_rpc() {
        let health = r#"{"jsonrpc":"2.0","result":"error","id":1}"#.to_string();

        let client = MockClient::new(vec![health]);
        let report = check_rpc_health(&client, "http://localhost").expect("should succeed");

        assert!(!report.healthy);
        assert!(report.summary.starts_with("🔴"));
    }
}
