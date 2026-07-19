use caixa_core::base64;
use caixa_core::MockTransport;
use caixa_transfer_build::transfer::{execute_transfer_build, TransferArgs, TransferConfig};
use serde_json::json;

fn nonce_cfg() -> TransferConfig {
    let mut c = TransferConfig::default();
    c.nonce_account = Some(
        caixa_core::Pubkey::from_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap(),
    );
    c.rpc_url = "https://example.invalid".into();
    c
}

fn nonce_mock() -> MockTransport {
    let mut data = vec![0u8; 80];
    data[40..72].fill(2);
    MockTransport::single(json!({
        "jsonrpc":"2.0","id":1,
        "result":{"value":{"data":[base64::encode(&data),"base64"]}}
    }))
}

#[test]
fn zero_amount_rejected() {
    let err = execute_transfer_build(
        &TransferArgs {
            source_owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
            destination: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".into(),
            amount_usdc: "0".into(),
            invoice_id: None,
            memo_extra: None,
            amount_brl: None,
            mint: None,
            create_dest_ata: false,
            nonce_authority: None,
        },
        &nonce_cfg(),
        &nonce_mock(),
    )
    .unwrap_err();
    assert!(err.contains("positive") || err.contains("amount") || err.contains("> 0"));
}

#[test]
fn bad_destination_rejected() {
    assert!(execute_transfer_build(
        &TransferArgs {
            source_owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
            destination: "not-a-key".into(),
            amount_usdc: "1".into(),
            invoice_id: None,
            memo_extra: None,
            amount_brl: None,
            mint: None,
            create_dest_ata: false,
            nonce_authority: None,
        },
        &nonce_cfg(),
        &nonce_mock(),
    )
    .is_err());
}

#[test]
fn summary_mentions_unsigned() {
    let out = execute_transfer_build(
        &TransferArgs {
            source_owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
            destination: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".into(),
            amount_usdc: "2.5".into(),
            invoice_id: Some("77".into()),
            memo_extra: None,
            amount_brl: Some("12.50".into()),
            mint: None,
            create_dest_ata: true,
            nonce_authority: None,
        },
        &nonce_cfg(),
        &nonce_mock(),
    )
    .unwrap();
    assert!(out.summary.to_ascii_lowercase().contains("unsigned") || out.summary.contains("T1"));
    assert!(out.summary.contains("INV=77") || out.tx_base64.len() > 32);
}

#[test]
fn recent_blockhash_path_when_nonce_optional() {
    let mock = MockTransport::single(json!({
        "jsonrpc":"2.0","id":1,
        "result":{"value":{"blockhash":"11111111111111111111111111111111","lastValidBlockHeight":1}}
    }));
    let mut cfg = TransferConfig::default();
    cfg.require_nonce = false;
    cfg.nonce_account = None;
    let out = execute_transfer_build(
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
    .unwrap();
    assert!(out.summary.contains("Durable nonce: no"));
}
