//! Durable nonce management for blockhash expiry mitigation.
//!
//! Solves the "blockhash expiry will bite you" trap from the ZeroClaw bounty.
//! When an agent builds a transaction that enters a human approval gate,
//! by the time the human approves, the blockhash may be dead.
//!
//! A durable nonce account allows the transaction to be valid indefinitely
//! (until the nonce is advanced).

use crate::types::*;
use crate::rpc::SolanaRpc;

/// Manages durable nonce accounts for offline transaction signing.
#[derive(Debug, Clone)]
pub struct DurableNonceManager {
    pub nonce_account: String,
    pub authority: String,
}

impl DurableNonceManager {
    /// Create a new nonce manager for the given account + authority.
    pub fn new(nonce_account: impl Into<String>, authority: impl Into<String>) -> Self {
        Self {
            nonce_account: nonce_account.into(),
            authority: authority.into(),
        }
    }

    /// Get the current nonce value (blockhash substitute).
    pub fn get_nonce(&self, rpc: &SolanaRpc) -> Result<String, String> {
        let info = rpc.get_account_info(&self.nonce_account)?;
        // The nonce value is stored at offset 4+32 in the account data
        // (4 bytes version + 32 bytes authority + 32 bytes blockhash)
        let raw = info.data.get(0).ok_or("no account data")?;
        let bytes = bs58::decode(raw)
            .into_vec()
            .map_err(|e| format!("base58: {e}"))?;

        if bytes.len() < 68 {
            return Err(format!(
                "nonce account data too short: {} bytes",
                bytes.len()
            ));
        }

        // Nonce value is bytes 36..68
        let nonce_bytes = &bytes[36..68];
        Ok(bs58::encode(nonce_bytes).into_string())
    }

    /// Format nonce status for LLM output (~200 tokens).
    pub fn format_nonce_status(&self, nonce: &str) -> ShapedOutput {
        ShapedOutput::text(format!(
            "Durable nonce | Account: {}... | Authority: {}... | Nonce: {}",
            &self.nonce_account[..8],
            &self.authority[..8],
            nonce
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_manager_construction() {
        let mgr = DurableNonceManager::new(
            "NonceAccount111111111111111111111",
            "Auth111111111111111111111111111",
        );
        assert_eq!(&mgr.nonce_account[..12], "NonceAccount");
    }

    #[test]
    fn test_format_nonce_status() {
        let mgr = DurableNonceManager::new("abc123def456ghi789", "def456abc123ghi789");
        let out = mgr.format_nonce_status("nonceVal111");
        assert!(out.summary.contains("Durable nonce"));
        assert!(out.summary.contains("nonceVal111"));
    }
}