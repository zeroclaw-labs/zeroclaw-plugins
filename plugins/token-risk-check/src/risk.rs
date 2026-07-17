use std::fmt;

use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskError {
    InvalidMint,
    InvalidRpcUrl,
}

impl fmt::Display for RiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMint => f.write_str("mint must be a 32-byte base58 public key"),
            Self::InvalidRpcUrl => {
                f.write_str("RPC URL must be HTTPS without credentials, query, or fragment")
            }
        }
    }
}

impl std::error::Error for RiskError {}

pub fn validate_mint(mint: &str) -> Result<(), RiskError> {
    let decoded = bs58::decode(mint)
        .into_vec()
        .map_err(|_| RiskError::InvalidMint)?;
    if decoded.len() != 32 {
        return Err(RiskError::InvalidMint);
    }
    Ok(())
}

pub fn validate_rpc_url(raw: &str) -> Result<String, RiskError> {
    let url = Url::parse(raw).map_err(|_| RiskError::InvalidRpcUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RiskError::InvalidRpcUrl);
    }
    Ok(url.to_string())
}
