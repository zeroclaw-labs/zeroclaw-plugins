//! Host tests: the pure core against captured mainnet RPC fixtures.
//! No network, no wasm toolchain — `cargo test` on the host covers everything
//! the shim forwards.

use std::collections::HashMap;

use serde_json::Value;
use token_risk_check::risk::{run_check, RiskConfig};
use token_risk_check::rpc::RpcTransport;

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const PYUSD: &str = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";
const BERN: &str = "CKfatsPMUf8SkiURsDXs7eK6GWb4Jsd6UDbs7twMCWxo";

/// Replays captured fixture files keyed on (method, mint param).
struct FixtureTransport {
    prefix: &'static str,
}

impl RpcTransport for FixtureTransport {
    fn call(&self, method: &str, _params: &Value) -> Result<Value, String> {
        let suffix = match method {
            "getAccountInfo" => "account",
            "getTokenLargestAccounts" => "largest",
            other => return Err(format!("unexpected rpc method in test: {other}")),
        };
        let path = format!(
            "{}/tests/fixtures/{}_{suffix}.json",
            env!("CARGO_MANIFEST_DIR"),
            self.prefix
        );
        let raw = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
        let body: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        body.get("result")
            .cloned()
            .ok_or_else(|| "fixture missing result".to_string())
    }
}

fn default_cfg() -> RiskConfig {
    RiskConfig::from_section(&HashMap::new())
}

#[test]
fn usdc_is_amber_for_active_authorities_only() {
    let out = run_check(&FixtureTransport { prefix: "usdc" }, USDC, &default_cfg()).unwrap();
    assert!(out.contains("AMBER"), "USDC should be amber: {out}");
    assert!(out.contains("mint authority ACTIVE"));
    assert!(out.contains("freeze authority ACTIVE"));
    assert!(out.contains("spl-token"));
    // 36% top-10 is below the 50% amber threshold: no concentration finding.
    assert!(!out.contains("top 10 holders own"));
}

#[test]
fn pyusd_is_red_for_permanent_delegate() {
    let out = run_check(&FixtureTransport { prefix: "pyusd" }, PYUSD, &default_cfg()).unwrap();
    assert!(out.contains("RED"), "PYUSD should be red: {out}");
    assert!(out.contains("permanent delegate SET"));
    assert!(out.contains("transfer hook SET"));
    assert!(out.contains("token-2022"));
    // Concentration above the 80% red line.
    assert!(out.contains("top 10 holders own 84%"));
    // Fee extension present but zero bps: must not be reported as a fee.
    assert!(
        !out.contains("transfer fee"),
        "0 bps fee must not surface: {out}"
    );
}

#[test]
fn bern_is_amber_for_transfer_fee() {
    let out = run_check(&FixtureTransport { prefix: "bern" }, BERN, &default_cfg()).unwrap();
    assert!(out.contains("AMBER"), "BERN should be amber: {out}");
    assert!(out.contains("transfer fee 2.69%"));
    // Authorities are revoked on BERN.
    assert!(!out.contains("mint authority ACTIVE"));
    assert!(!out.contains("freeze authority ACTIVE"));
}

#[test]
fn output_is_compact() {
    // Trap #3 in the bounty brief: never flood the model's context.
    for prefix in ["usdc", "pyusd", "bern"] {
        let mint = match prefix {
            "usdc" => USDC,
            "pyusd" => PYUSD,
            _ => BERN,
        };
        let out = run_check(&FixtureTransport { prefix }, mint, &default_cfg()).unwrap();
        assert!(
            out.len() < 800,
            "{prefix} output too large ({} bytes):\n{out}",
            out.len()
        );
    }
}

#[test]
fn invalid_mint_is_rejected_before_any_rpc() {
    struct PanicTransport;
    impl RpcTransport for PanicTransport {
        fn call(&self, _: &str, _: &Value) -> Result<Value, String> {
            panic!("rpc must not be reached for invalid input");
        }
    }
    for bad in [
        "not-a-mint",
        "",
        "lucas.sol",
        "EPjF'; DROP TABLE mints;--",
        "https://evil.example/exfil",
    ] {
        let err = run_check(&PanicTransport, bad, &default_cfg()).unwrap_err();
        assert!(err.contains("not a valid"), "{bad}: {err}");
    }
}

#[test]
fn thresholds_come_from_config() {
    // Lower the amber threshold under USDC's 36%: concentration now surfaces.
    let mut section = HashMap::new();
    section.insert("concentration_amber_pct".to_string(), "30".to_string());
    let cfg = RiskConfig::from_section(&section);
    let out = run_check(&FixtureTransport { prefix: "usdc" }, USDC, &cfg).unwrap();
    assert!(out.contains("top 10 holders own 37%"), "{out}");
}

#[test]
fn concentration_failure_degrades_gracefully() {
    // Some RPC providers block getTokenLargestAccounts; the authority and
    // extension findings must still be produced.
    struct AccountOnly;
    impl RpcTransport for AccountOnly {
        fn call(&self, method: &str, params: &Value) -> Result<Value, String> {
            match method {
                "getAccountInfo" => FixtureTransport { prefix: "usdc" }.call(method, params),
                _ => Err("blocked by provider".to_string()),
            }
        }
    }
    let out = run_check(&AccountOnly, USDC, &default_cfg()).unwrap();
    assert!(out.contains("AMBER"));
    assert!(out.contains("mint authority ACTIVE"));
}
