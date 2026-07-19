//! Pure unsigned SPL transfer builder with durable-nonce support.

use std::collections::HashMap;

use caixa_core::pubkey::{usdc_mint_mainnet, Pubkey};
use caixa_core::rpc::{RpcClient, RpcTransport};
use caixa_core::spl::{advance_nonce_instruction, build_spl_transfer_plan, SplTransferRequest};
use caixa_core::tx::{build_legacy_unsigned_tx, TxBuildInput};
use caixa_core::{build_invoice_memo, shape_output};

#[derive(Debug, Clone)]
pub struct TransferConfig {
    pub rpc_url: String,
    pub allowed_mints: Vec<Pubkey>,
    pub max_usdc: f64,
    pub default_mint: Pubkey,
    pub nonce_account: Option<Pubkey>,
    pub require_nonce: bool,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.mainnet-beta.solana.com".into(),
            allowed_mints: vec![usdc_mint_mainnet()],
            max_usdc: 1_000.0,
            default_mint: usdc_mint_mainnet(),
            nonce_account: None,
            require_nonce: true,
        }
    }
}

impl TransferConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let mut cfg = Self::default();
        if let Some(u) = section.get("rpc_url").filter(|s| !s.is_empty()) {
            if u.contains("api-key=") || u.contains("api_key=") {
                return Err("rpc_url must not embed API keys; use a keyless URL + host secrets".into());
            }
            cfg.rpc_url = u.clone();
        }
        if let Some(m) = section.get("allowed_mints").filter(|s| !s.is_empty()) {
            cfg.allowed_mints = m
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(Pubkey::from_base58)
                .collect::<Result<Vec<_>, _>>()?;
        }
        if let Some(m) = section.get("mint").filter(|s| !s.is_empty()) {
            cfg.default_mint = Pubkey::from_base58(m)?;
        }
        if let Some(v) = section.get("max_usdc").filter(|s| !s.is_empty()) {
            cfg.max_usdc = v.parse().map_err(|_| "max_usdc must be a number")?;
        }
        if let Some(n) = section.get("nonce_account").filter(|s| !s.is_empty()) {
            cfg.nonce_account = Some(Pubkey::from_base58(n)?);
        }
        if let Some(v) = section.get("require_nonce").filter(|s| !s.is_empty()) {
            cfg.require_nonce = v.eq_ignore_ascii_case("true");
        }
        if !cfg.allowed_mints.iter().any(|m| *m == cfg.default_mint) {
            return Err("mint is not in allowed_mints".into());
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone)]
pub struct TransferArgs {
    pub source_owner: String,
    pub destination: String,
    pub amount_usdc: String,
    pub invoice_id: Option<String>,
    pub memo_extra: Option<String>,
    pub amount_brl: Option<String>,
    pub mint: Option<String>,
    pub create_dest_ata: bool,
    pub nonce_authority: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TransferBuildResult {
    pub summary: String,
    pub tx_base64: String,
}

pub fn execute_transfer_build<T: RpcTransport>(
    args: &TransferArgs,
    cfg: &TransferConfig,
    transport: &T,
) -> Result<TransferBuildResult, String> {
    reject_injection(args)?;

    let source_owner = Pubkey::from_base58(&args.source_owner)?;
    let destination = Pubkey::from_base58(&args.destination)?;
    let mint = match &args.mint {
        Some(m) => Pubkey::from_base58(m)?,
        None => cfg.default_mint,
    };
    if !cfg.allowed_mints.iter().any(|m| *m == mint) {
        return Err(format!(
            "mint {} is not allowlisted — refusing transfer build",
            mint.to_base58()
        ));
    }

    let amount_f: f64 = args
        .amount_usdc
        .parse()
        .map_err(|_| "amount_usdc must be a decimal number".to_string())?;
    if !(amount_f.is_finite() && amount_f > 0.0) {
        return Err("amount_usdc must be positive".into());
    }
    if amount_f > cfg.max_usdc {
        return Err(format!(
            "amount_usdc {} exceeds max_usdc {}",
            args.amount_usdc, cfg.max_usdc
        ));
    }

    let memo = match &args.invoice_id {
        Some(inv) => Some(build_invoice_memo(
            inv,
            args.amount_brl.as_deref(),
            args.memo_extra.as_deref(),
        )?),
        None => args.memo_extra.clone(),
    };

    let plan = build_spl_transfer_plan(&SplTransferRequest {
        payer: source_owner,
        source_owner,
        destination_owner: destination,
        mint,
        amount: args.amount_usdc.clone(),
        memo: memo.clone(),
        create_dest_ata: args.create_dest_ata,
    })?;

    let client = RpcClient::new(cfg.rpc_url.clone(), transport);

    let (blockhash, used_nonce) = if let Some(nonce_account) = cfg.nonce_account {
        let nonce = client.get_nonce_value(&nonce_account).map_err(|e| e.0)?;
        (nonce, Some(nonce_account))
    } else if cfg.require_nonce {
        return Err(
            "durable nonce required: set config.nonce_account (approval queues kill recent blockhashes)"
                .into(),
        );
    } else {
        (client.get_latest_blockhash().map_err(|e| e.0)?, None)
    };

    let mut ixs = Vec::new();
    if let Some(nonce_account) = used_nonce {
        let authority = match &args.nonce_authority {
            Some(a) => Pubkey::from_base58(a)?,
            None => source_owner,
        };
        ixs.push(advance_nonce_instruction(&nonce_account, &authority));
    }
    ixs.extend(plan.instructions);

    let tx = build_legacy_unsigned_tx(&TxBuildInput {
        fee_payer: source_owner,
        recent_blockhash: blockhash,
        instructions: ixs,
    })?;

    let mut lines = vec![
        "Caixa unsigned transfer (T1 — human/Squads must sign).".to_string(),
        format!("Amount: {} USDC", args.amount_usdc),
        format!("Mint: {}", mint.short()),
        format!("From: {}", source_owner.short()),
        format!("To: {}", destination.short()),
    ];
    if let Some(m) = &memo {
        lines.push(format!("Memo: {m}"));
    }
    if used_nonce.is_some() {
        lines.push("Durable nonce: yes (survives approval queue).".into());
    } else {
        lines.push("Durable nonce: no (sign quickly — blockhash expires).".into());
    }
    lines.push(format!("Signers required: {}", tx.num_signers));
    lines.push(format!("tx_base64: {}", tx.tx_base64));

    Ok(TransferBuildResult {
        summary: shape_output(&lines.join("\n")),
        tx_base64: tx.tx_base64,
    })
}

fn reject_injection(args: &TransferArgs) -> Result<(), String> {
    for (name, val) in [
        ("memo_extra", args.memo_extra.as_deref()),
        ("invoice_id", args.invoice_id.as_deref()),
        ("amount_brl", args.amount_brl.as_deref()),
    ] {
        if let Some(v) = val {
            let lower = v.to_ascii_lowercase();
            for needle in ["private_key", "secret_key", "mnemonic", "seed phrase"] {
                if lower.contains(needle) {
                    return Err(format!(
                        "refusing transfer build: {name} looks like an injection/secret payload"
                    ));
                }
            }
        }
    }
    // Never accept a signing key argument — field must not exist in schema, but belt+suspenders.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg_with_nonce() -> TransferConfig {
        let mut c = TransferConfig::default();
        c.nonce_account =
            Some(Pubkey::from_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap());
        c.rpc_url = "https://example.invalid".into();
        c
    }

    fn nonce_mock() -> caixa_core::MockTransport {
        let mut data = vec![0u8; 80];
        data[40..72].copy_from_slice(&[3u8; 32]);
        let b64 = caixa_core::base64::encode(&data);
        caixa_core::MockTransport::single(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "value": { "data": [b64, "base64"] } }
        }))
    }

    #[test]
    fn builds_with_nonce() {
        let mock = nonce_mock();
        let out = execute_transfer_build(
            &TransferArgs {
                source_owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
                destination: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".into(),
                amount_usdc: "10".into(),
                invoice_id: Some("412".into()),
                memo_extra: None,
                amount_brl: Some("50.00".into()),
                mint: None,
                create_dest_ata: true,
                nonce_authority: None,
            },
            &cfg_with_nonce(),
            &mock,
        )
        .unwrap();
        assert!(out.summary.contains("Durable nonce: yes"));
        assert!(!out.tx_base64.is_empty());
    }

    #[test]
    fn requires_nonce_by_default() {
        let mock = caixa_core::MockTransport::default();
        let mut cfg = TransferConfig::default();
        cfg.nonce_account = None;
        cfg.require_nonce = true;
        let err = execute_transfer_build(
            &TransferArgs {
                source_owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
                destination: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".into(),
                amount_usdc: "1".into(),
                invoice_id: None,
                memo_extra: None,
                amount_brl: None,
                mint: None,
                create_dest_ata: false,
                nonce_authority: None,
            },
            &cfg,
            &mock,
        )
        .unwrap_err();
        assert!(err.contains("nonce"));
    }

    #[test]
    fn injection_over_max_fails() {
        let mock = nonce_mock();
        let err = execute_transfer_build(
            &TransferArgs {
                source_owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
                destination: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".into(),
                amount_usdc: "999999".into(),
                invoice_id: Some("x".into()),
                memo_extra: Some("private_key dump".into()),
                amount_brl: None,
                mint: None,
                create_dest_ata: false,
                nonce_authority: None,
            },
            &cfg_with_nonce(),
            &mock,
        )
        .unwrap_err();
        assert!(err.contains("injection") || err.contains("max_usdc") || err.contains("secret"));
    }
}
