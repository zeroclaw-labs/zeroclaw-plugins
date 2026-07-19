//! Pure payment-watch core (T0 — read only).

use std::collections::HashMap;

use caixa_core::memo::memo_contains_invoice;
use caixa_core::pubkey::{usdc_mint_mainnet, Pubkey};
use caixa_core::rpc::{RpcClient, RpcTransport};
use caixa_core::shape_output;

#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub rpc_url: String,
    pub default_recipient: Option<Pubkey>,
    pub default_mint: Pubkey,
    pub lookback: usize,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.mainnet-beta.solana.com".into(),
            default_recipient: None,
            default_mint: usdc_mint_mainnet(),
            lookback: 25,
        }
    }
}

impl WatchConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let mut cfg = Self::default();
        if let Some(u) = section.get("rpc_url").filter(|s| !s.is_empty()) {
            if u.contains("api-key=") || u.contains("api_key=") {
                return Err("rpc_url must not embed API keys".into());
            }
            cfg.rpc_url = u.clone();
        }
        if let Some(r) = section.get("recipient").filter(|s| !s.is_empty()) {
            cfg.default_recipient = Some(Pubkey::from_base58(r)?);
        }
        if let Some(m) = section.get("mint").filter(|s| !s.is_empty()) {
            cfg.default_mint = Pubkey::from_base58(m)?;
        }
        if let Some(v) = section.get("lookback").filter(|s| !s.is_empty()) {
            cfg.lookback = v.parse().map_err(|_| "lookback must be an integer")?;
            if cfg.lookback == 0 || cfg.lookback > 100 {
                return Err("lookback must be 1..=100".into());
            }
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone)]
pub struct WatchArgs {
    pub recipient: Option<String>,
    pub invoice_id: String,
    pub amount_usdc: Option<String>,
    pub mint: Option<String>,
    pub reference: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WatchResult {
    pub summary: String,
    pub paid: bool,
}

pub fn execute_watch<T: RpcTransport>(
    args: &WatchArgs,
    cfg: &WatchConfig,
    transport: &T,
) -> Result<WatchResult, String> {
    reject_injection(args)?;

    let recipient = match &args.recipient {
        Some(r) => Pubkey::from_base58(r)?,
        None => cfg
            .default_recipient
            .ok_or_else(|| "recipient is required (arg or config)".to_string())?,
    };
    let _mint = match &args.mint {
        Some(m) => Pubkey::from_base58(m)?,
        None => cfg.default_mint,
    };

    let client = RpcClient::new(cfg.rpc_url.clone(), transport);
    let sigs = client
        .get_signatures_for_address(&recipient, cfg.lookback)
        .map_err(|e| e.0)?;

    for sig in sigs.into_iter().filter(|s| s.ok) {
        // Prefer RPC-provided memo; otherwise fetch tx meta.
        let memo_hit = if let Some(m) = &sig.memo {
            memo_contains_invoice(m, &args.invoice_id)
                || args
                    .reference
                    .as_ref()
                    .map(|r| m.contains(r))
                    .unwrap_or(false)
        } else {
            false
        };

        let (memos, fee_payer) = if memo_hit {
            (vec![sig.memo.clone().unwrap_or_default()], None)
        } else {
            match client.get_transaction_memo_and_pre_balances(&sig.signature) {
                Ok(meta) => (meta.memos, meta.fee_payer),
                Err(_) => continue,
            }
        };

        let matched = memos.iter().any(|m| {
            memo_contains_invoice(m, &args.invoice_id)
                || args
                    .reference
                    .as_ref()
                    .map(|r| m.contains(r.as_str()))
                    .unwrap_or(false)
        });
        if !matched && !memo_hit {
            continue;
        }

        let amount_bit = args
            .amount_usdc
            .as_ref()
            .map(|a| format!(" {a} USDC"))
            .unwrap_or_default();
        let from = fee_payer
            .as_deref()
            .map(|f| {
                if f.len() > 8 {
                    format!("{}…{}", &f[..4], &f[f.len() - 4..])
                } else {
                    f.to_string()
                }
            })
            .unwrap_or_else(|| "unknown".into());

        let summary = shape_output(&format!(
            "Invoice #{} paid →{} from {}.\n\
             Signature: {}\n\
             Recipient: {}\n\
             Custody: T0 read-only watch — no keys, no transfers.",
            args.invoice_id,
            amount_bit,
            from,
            short_sig(&sig.signature),
            recipient.short()
        ));
        return Ok(WatchResult {
            summary,
            paid: true,
        });
    }

    Ok(WatchResult {
        summary: shape_output(&format!(
            "Invoice #{} not seen yet on {} (lookback {}). Still waiting.",
            args.invoice_id,
            recipient.short(),
            cfg.lookback
        )),
        paid: false,
    })
}

fn short_sig(sig: &str) -> String {
    if sig.len() <= 12 {
        sig.to_string()
    } else {
        format!("{}…{}", &sig[..6], &sig[sig.len() - 4..])
    }
}

fn reject_injection(args: &WatchArgs) -> Result<(), String> {
    let lower = args.invoice_id.to_ascii_lowercase();
    for needle in ["private_key", "secret_key", "mnemonic"] {
        if lower.contains(needle) {
            return Err("refusing watch: invoice_id looks like an injection/secret payload".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use caixa_core::MockTransport;
    use serde_json::json;

    #[test]
    fn detects_paid_via_signature_memo() {
        let mock = MockTransport::single(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [{
                "signature": "5".repeat(64),
                "err": null,
                "memo": "INV=412 BRL=25.00"
            }]
        }));
        let mut cfg = WatchConfig::default();
        cfg.default_recipient =
            Some(Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap());
        cfg.rpc_url = "https://example.invalid".into();
        let out = execute_watch(
            &WatchArgs {
                recipient: None,
                invoice_id: "412".into(),
                amount_usdc: Some("5.000000".into()),
                mint: None,
                reference: None,
            },
            &cfg,
            &mock,
        )
        .unwrap();
        assert!(out.paid);
        assert!(out.summary.contains("paid"));
    }

    #[test]
    fn waiting_when_no_match() {
        let mock = MockTransport::single(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [{
                "signature": "abc",
                "err": null,
                "memo": "INV=999"
            }]
        }));
        let mut cfg = WatchConfig::default();
        cfg.default_recipient =
            Some(Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap());
        let out = execute_watch(
            &WatchArgs {
                recipient: None,
                invoice_id: "412".into(),
                amount_usdc: None,
                mint: None,
                reference: None,
            },
            &cfg,
            &mock,
        )
        .unwrap();
        assert!(!out.paid);
        assert!(out.summary.contains("not seen"));
    }
}
