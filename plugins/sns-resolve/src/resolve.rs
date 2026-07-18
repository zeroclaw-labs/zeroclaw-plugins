//! Pure SNS resolution core. No wasm, no sockets: chain access goes through
//! [`HttpTransport`], mocked in host tests.
//!
//! Resolves a `.sol` domain to the wallet address that owns it — the flow that
//! keeps the payment tools honest: the agent asks this tool for the address
//! behind "lucas.sol" instead of guessing one. T0, read-only, zero custody.

use std::collections::HashMap;

use zeroclaw_solana_core::rpc::{get_account, HttpTransport};
use zeroclaw_solana_core::sns::{derive_domain_key, normalize_domain, parse_registry_owner};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

pub struct ResolveConfig {
    pub rpc_url: String,
}

impl ResolveConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        Self {
            rpc_url: section
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string()),
        }
    }
}

#[derive(Debug)]
pub struct Resolution {
    pub domain: String,
    pub owner: String,
    pub registry: String,
    pub text: String,
}

/// Resolve `input` (`"lucas.sol"` or `"lucas"`) to its owner wallet.
pub fn resolve_domain<T: HttpTransport>(
    transport: &T,
    input: &str,
    cfg: &ResolveConfig,
) -> Result<Resolution, String> {
    let label = normalize_domain(input)?;
    let registry = derive_domain_key(&label)?;

    let account = get_account(transport, &cfg.rpc_url, &registry)?
        .ok_or_else(|| format!("{label}.sol is not registered"))?;

    // A registered .sol domain's registry account is owned by the SPL Name
    // Service program; anything else means the derived address collided with
    // an unrelated account and must not be treated as a resolution.
    if account.owner != zeroclaw_solana_core::sns::name_program() {
        return Err(format!("{label}.sol does not resolve to a name registry"));
    }

    let owner = parse_registry_owner(&account.data)?;
    let owner_b58 = owner.to_base58();
    let text = format!(
        "{label}.sol resolves to {owner_b58}\n(registry account {})",
        registry.to_base58()
    );
    Ok(Resolution {
        domain: format!("{label}.sol"),
        owner: owner_b58,
        registry: registry.to_base58(),
        text,
    })
}
