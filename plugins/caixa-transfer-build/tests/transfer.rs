use std::collections::HashMap;

use caixa_core::base64;
use caixa_core::MockTransport;
use caixa_transfer_build::transfer::{execute_transfer_build, TransferArgs, TransferConfig};
use serde_json::json;

#[test]
fn config_rejects_embedded_api_key() {
    let mut map = HashMap::new();
    map.insert(
        "rpc_url".into(),
        "https://example.com/?api-key=secret".into(),
    );
    let err = TransferConfig::from_section(&map).unwrap_err();
    assert!(err.contains("API"));
}

#[test]
fn allowlist_blocks_wrong_mint() {
    let mut data = vec![0u8; 80];
    data[40..72].fill(1);
    let mock = MockTransport::single(json!({
        "jsonrpc":"2.0","id":1,
        "result":{"value":{"data":[base64::encode(&data),"base64"]}}
    }));
    let mut cfg = TransferConfig::default();
    cfg.nonce_account = Some(
        caixa_core::Pubkey::from_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap(),
    );
    let err = execute_transfer_build(
        &TransferArgs {
            source_owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
            destination: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".into(),
            amount_usdc: "1".into(),
            invoice_id: None,
            memo_extra: None,
            amount_brl: None,
            mint: Some("So11111111111111111111111111111111111111112".into()),
            create_dest_ata: false,
            nonce_authority: None,
        },
        &cfg,
        &mock,
    )
    .unwrap_err();
    assert!(err.contains("allowlisted"));
}
