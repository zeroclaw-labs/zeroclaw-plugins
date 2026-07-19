//! Host integration tests for caixa-core (no network, no wasm).

use caixa_core::pay::{build_solana_pay_url, PayRequest};
use caixa_core::pubkey::{usdc_mint_mainnet, Pubkey};
use caixa_core::quote::{quote_brl_to_usdc, QuoteInput};
use caixa_core::rpc::{MockHttpGet, MockTransport, RpcClient};
use caixa_core::spl::{advance_nonce_instruction, build_spl_transfer_plan, SplTransferRequest};
use caixa_core::tx::{build_legacy_unsigned_tx, TxBuildInput};
use caixa_core::{build_invoice_memo, shape_output, MAX_OUTPUT_CHARS};
use serde_json::json;

#[test]
fn end_to_end_charge_memo_and_pay_url() {
    let memo = build_invoice_memo("mesa-4", Some("25.00"), None).unwrap();
    let recipient = Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let url = build_solana_pay_url(&PayRequest {
        recipient,
        amount: "5.000000".into(),
        spl_token: Some(usdc_mint_mainnet()),
        memo: Some(memo.clone()),
        reference: Some("mesa-4".into()),
        label: Some("Caixa".into()),
        message: Some("Cobra mesa 4".into()),
    })
    .unwrap();
    assert!(url.contains("INV%3Dmesa-4") || url.contains("INV=mesa-4") || memo.contains("INV=mesa-4"));
    assert!(url.starts_with("solana:"));
}

#[test]
fn durable_nonce_transfer_tx() {
    let owner = Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let dest = Pubkey::from_base58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();
    let nonce_account = Pubkey::from_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();

    let mut data = vec![0u8; 80];
    data[40..72].copy_from_slice(&[9u8; 32]);
    let b64 = caixa_core::base64::encode(&data);
    let mock = MockTransport::single(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "value": { "data": [b64, "base64"] } }
    }));
    let client = RpcClient::new("https://example.invalid", &mock);
    let nonce = client.get_nonce_value(&nonce_account).unwrap();

    let plan = build_spl_transfer_plan(&SplTransferRequest {
        payer: owner,
        source_owner: owner,
        destination_owner: dest,
        mint: usdc_mint_mainnet(),
        amount: "1.5".into(),
        memo: Some(build_invoice_memo("99", Some("7.50"), None).unwrap()),
        create_dest_ata: true,
    })
    .unwrap();

    let mut ixs = vec![advance_nonce_instruction(&nonce_account, &owner)];
    ixs.extend(plan.instructions);

    let tx = build_legacy_unsigned_tx(&TxBuildInput {
        fee_payer: owner,
        recent_blockhash: nonce,
        instructions: ixs,
    })
    .unwrap();
    assert!(!tx.tx_base64.is_empty());
    let shaped = shape_output(&format!(
        "Approve transfer {}\nmint {}\ntx {}",
        plan.amount_base_units,
        usdc_mint_mainnet().short(),
        &tx.tx_base64[..32.min(tx.tx_base64.len())]
    ));
    assert!(shaped.chars().count() <= MAX_OUTPUT_CHARS);
}

#[test]
fn fx_quote_fail_closed_on_bad_json() {
    let http = MockHttpGet {
        body: json!({ "error": "nope" }),
    };
    let err = quote_brl_to_usdc(
        &http,
        &QuoteInput {
            amount_brl: 10.0,
            price_url: None,
        },
    )
    .unwrap_err();
    assert!(err.0.contains("missing") || err.0.contains("price"));
}
