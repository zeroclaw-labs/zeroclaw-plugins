use solana_safety_inspector::inspector::parse_rpc_response;

/// Menguji perilaku analisis ketika token dalam kondisi AMAN (Otoritas Cetak & Beku dinonaktifkan)
#[test]
fn test_parse_safe_token() {
    let mint_address = "EPjFWdd5AufqSSjvk8t7v9yY3dg6fG73Xp1Asut1m1yc"; // Contoh alamat USDC asli
    
    // Data tiruan (mock JSON response) dari Solana RPC untuk token aman (mint & freeze authority adalah null)
    let mock_rpc_response = r#"{
        "jsonrpc": "2.0",
        "result": {
            "context": { "slot": 240000000 },
            "value": {
                "data": {
                    "parsed": {
                        "info": {
                            "decimals": 6,
                            "freezeAuthority": null,
                            "isInitialized": true,
                            "mintAuthority": null,
                            "supply": "1000000000000000"
                        },
                        "type": "mint"
                    },
                    "program": "spl-token",
                    "space": 82
                },
                "executable": false,
                "lamports": 1461600,
                "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            }
        },
        "id": 1
    }"#;

    let result = parse_rpc_response(mint_address, mock_rpc_response);
    
    assert!(result.is_ok(), "Seharusnya sukses memparse data token");
    let report = result.unwrap();
    
    assert_eq!(report.mint_address, mint_address);
    assert_eq!(report.decimals, 6);
    assert_eq!(report.supply, "1000000000000000");
    
    // Pastikan terdeteksi AMAN
    assert!(report.mint_authority_renounced);
    assert!(report.freeze_authority_disabled);
    assert!(report.is_safe);
    assert!(report.message.contains("🟢 Status Keamanan: AMAN"));
}

/// Menguji perilaku analisis ketika token dalam kondisi SANGAT BERBAHAYA (Otoritas Cetak & Beku aktif)
#[test]
fn test_parse_unsafe_token() {
    let mint_address = "FakeTokenAddress111111111111111111111111111";
    
    // Data tiruan RPC untuk token berisiko tinggi (mint & freeze authority memiliki alamat pemilik)
    let mock_rpc_response = r#"{
        "jsonrpc": "2.0",
        "result": {
            "context": { "slot": 240000000 },
            "value": {
                "data": {
                    "parsed": {
                        "info": {
                            "decimals": 9,
                            "freezeAuthority": "4Nd1mBQvC4v38uH8Mtfj28C14S8G8Xp9gU21L5t8s2o",
                            "isInitialized": true,
                            "mintAuthority": "4Nd1mBQvC4v38uH8Mtfj28C14S8G8Xp9gU21L5t8s2o",
                            "supply": "1000000000"
                        },
                        "type": "mint"
                    },
                    "program": "spl-token",
                    "space": 82
                },
                "executable": false,
                "lamports": 1461600,
                "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            }
        },
        "id": 1
    }"#;

    let result = parse_rpc_response(mint_address, mock_rpc_response);
    
    assert!(result.is_ok());
    let report = result.unwrap();
    
    // Pastikan terdeteksi BERBAHAYA
    assert!(!report.mint_authority_renounced);
    assert!(!report.freeze_authority_disabled);
    assert!(!report.is_safe);
    assert!(report.message.contains("🔴 Status Keamanan: SANGAT BERBAHAYA"));
}

/// Menguji penanganan ketika respon RPC tidak valid (misalnya format JSON rusak atau error dari RPC)
#[test]
fn test_parse_invalid_response() {
    let mint_address = "InvalidAddress";
    let mock_broken_json = r#"{"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid param"}, "id": 1}"#;

    let result = parse_rpc_response(mint_address, mock_broken_json);
    
    // Seharusnya menghasilkan Err karena RPC merespon error
    assert!(result.is_err());
    let err_msg = result.err().unwrap();
    assert!(err_msg.contains("Galat RPC"));
}