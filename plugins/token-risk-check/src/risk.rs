//! Pure token-risk-check logic. No wit-bindgen or wasm dependency so it compiles
//! and tests on the host with a plain `cargo test`, while the wasm component
//! reuses the exact same logic through `lib.rs`.

use solana_core::rpc::SolanaRpc;
use solana_core::types::ShapedOutput;
use solana_core::types::TokenRiskReport;

/// Perform a full token risk check against the given mint on the given RPC endpoint.
///
/// Returns a JSON-formatted string with the shaped risk report (summary + structured data).
pub fn check_token(mint: &str, rpc_url: &str) -> Result<String, String> {
    let rpc = SolanaRpc::new(rpc_url);
    let report: TokenRiskReport = rpc.token_risk_check(mint)?;
    let shaped: ShapedOutput = rpc.format_risk_report(&report);
    serde_json::to_string_pretty(&shaped)
        .map_err(|e| format!("failed to serialize risk report: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_rpc_creation() {
        let rpc = SolanaRpc::new("https://api.mainnet-beta.solana.com");
        assert_eq!(rpc.url, "https://api.mainnet-beta.solana.com");
    }

    #[test]
    fn test_solana_rpc_creation_with_custom_url() {
        let rpc = SolanaRpc::new("https://rpc.ankr.com/solana");
        assert_eq!(rpc.url, "https://rpc.ankr.com/solana");
    }

    #[test]
    fn test_url_has_https_default() {
        let rpc = SolanaRpc::new("https://api.mainnet-beta.solana.com");
        assert!(rpc.url.starts_with("https://"));
    }
}