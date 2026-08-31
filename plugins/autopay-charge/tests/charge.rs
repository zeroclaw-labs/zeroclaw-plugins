use solana_plugin_core::{HttpRequester, Pubkey, get_associated_token_address};
use autopay_charge::charge::execute_charge;

struct MockHttpRequester {
    account_info_response: String,
    signatures_response: String,
    transaction_response: String,
}

impl HttpRequester for MockHttpRequester {
    fn post(&self, _url: &str, body: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
        let method = req["method"].as_str().ok_or("Missing method")?;
        
        match method {
            "getAccountInfo" => Ok(self.account_info_response.clone()),
            "getSignaturesForAddress" => Ok(self.signatures_response.clone()),
            "getTransaction" => Ok(self.transaction_response.clone()),
            "getLatestBlockhash" => {
                Ok(serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "context": { "slot": 1 },
                        "value": {
                            "blockhash": "5KfgXnZ4tF7Yw7p1F67Zp9Y4aB7c8D9eF21a2b3c4d5",
                            "lastValidBlockHeight": 12345
                        }
                    },
                    "id": 1
                }).to_string())
            }
            "sendTransaction" => {
                Ok(serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": "5KfgXnZ4tF7Yw7p1F67Zp9Y4aB7c8D9eF21a2b3c4d5Signature",
                    "id": 1
                }).to_string())
            }
            _ => Err(format!("Mock not implemented for: {method}")),
        }
    }
}

#[test]
fn test_execute_charge_success() {
    let agent_private_key = [1u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&agent_private_key);
    let agent_pubkey = Pubkey(signing_key.verifying_key().to_bytes());
    
    let owner = Pubkey::from_string("DBD8hAwLDRQkTsu6EqviaYNGKPnsAMmQonxf7AH8ZcFY").unwrap();
    let merchant = Pubkey::from_string("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU").unwrap();
    let mint = Pubkey::from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
    
    // Mock user's token account with sufficient allowance and balance
    let account_info = serde_json::json!({
        "jsonrpc": "2.0",
        "result": {
            "context": { "slot": 1 },
            "value": {
                "data": {
                    "program": "spl-token",
                    "parsed": {
                        "info": {
                            "mint": mint.to_string(),
                            "owner": owner.to_string(),
                            "state": "initialized",
                            "delegate": agent_pubkey.to_string(),
                            "delegatedAmount": {
                                "amount": "100000000", // 100 USDC allowance
                                "decimals": 6
                            },
                            "tokenAmount": {
                                "amount": "200000000", // 200 USDC balance
                                "decimals": 6
                            }
                        },
                        "type": "account"
                    }
                }
            }
        },
        "id": 1
    }).to_string();
    
    // Mock zero transactions in history
    let signatures = serde_json::json!({
        "jsonrpc": "2.0",
        "result": [],
        "id": 1
    }).to_string();
    
    let mock = MockHttpRequester {
        account_info_response: account_info,
        signatures_response: signatures,
        transaction_response: "".to_string(),
    };
    
    let current_time = 1700000000i64;
    let res = execute_charge(
        &mock,
        "http://mock",
        &agent_private_key,
        &owner,
        &merchant,
        &mint,
        10_000_000, // 10 USDC
        50_000_000, // 50 USDC daily cap
        current_time,
    );
    
    assert!(res.is_ok(), "Success case failed: {:?}", res.err());
    assert_eq!(res.unwrap(), "5KfgXnZ4tF7Yw7p1F67Zp9Y4aB7c8D9eF21a2b3c4d5Signature");
}

#[test]
fn test_execute_charge_insufficient_allowance() {
    let agent_private_key = [1u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&agent_private_key);
    let agent_pubkey = Pubkey(signing_key.verifying_key().to_bytes());
    
    let owner = Pubkey::from_string("DBD8hAwLDRQkTsu6EqviaYNGKPnsAMmQonxf7AH8ZcFY").unwrap();
    let merchant = Pubkey::from_string("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU").unwrap();
    let mint = Pubkey::from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
    
    // Mock user's token account with only 5 USDC allowance (requested 10 USDC)
    let account_info = serde_json::json!({
        "jsonrpc": "2.0",
        "result": {
            "context": { "slot": 1 },
            "value": {
                "data": {
                    "program": "spl-token",
                    "parsed": {
                        "info": {
                            "mint": mint.to_string(),
                            "owner": owner.to_string(),
                            "state": "initialized",
                            "delegate": agent_pubkey.to_string(),
                            "delegatedAmount": {
                                "amount": "5000000", // 5 USDC allowance
                                "decimals": 6
                            },
                            "tokenAmount": {
                                "amount": "200000000",
                                "decimals": 6
                            }
                        },
                        "type": "account"
                    }
                }
            }
        },
        "id": 1
    }).to_string();
    
    let mock = MockHttpRequester {
        account_info_response: account_info,
        signatures_response: "[]".to_string(),
        transaction_response: "".to_string(),
    };
    
    let res = execute_charge(
        &mock,
        "http://mock",
        &agent_private_key,
        &owner,
        &merchant,
        &mint,
        10_000_000, // 10 USDC
        50_000_000,
        1700000000,
    );
    
    assert!(res.is_err());
    let err_msg = res.err().unwrap();
    assert!(err_msg.contains("Insufficient delegation allowance"), "Unexpected error: {}", err_msg);
}

#[test]
fn test_execute_charge_daily_cap_exceeded() {
    let agent_private_key = [1u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&agent_private_key);
    let agent_pubkey = Pubkey(signing_key.verifying_key().to_bytes());
    
    let owner = Pubkey::from_string("DBD8hAwLDRQkTsu6EqviaYNGKPnsAMmQonxf7AH8ZcFY").unwrap();
    let merchant = Pubkey::from_string("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU").unwrap();
    let mint = Pubkey::from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
    
    let user_ata = get_associated_token_address(&owner, &mint);
    
    let account_info = serde_json::json!({
        "jsonrpc": "2.0",
        "result": {
            "context": { "slot": 1 },
            "value": {
                "data": {
                    "program": "spl-token",
                    "parsed": {
                        "info": {
                            "mint": mint.to_string(),
                            "owner": owner.to_string(),
                            "state": "initialized",
                            "delegate": agent_pubkey.to_string(),
                            "delegatedAmount": {
                                "amount": "100000000",
                                "decimals": 6
                            },
                            "tokenAmount": {
                                "amount": "200000000",
                                "decimals": 6
                            }
                        },
                        "type": "account"
                    }
                }
            }
        },
        "id": 1
    }).to_string();
    
    // Mock signature history showing a previous transaction in the last 24h
    let current_time = 1700000000i64;
    let signatures = serde_json::json!({
        "jsonrpc": "2.0",
        "result": [
            {
                "signature": "PrevTxSignatureString",
                "slot": 12345,
                "err": null,
                "blockTime": current_time - 1000 // 1000 seconds ago (well within 24h)
            }
        ],
        "id": 1
    }).to_string();
    
    // Mock the previous transaction details showing a 45 USDC transfer
    let tx_details = serde_json::json!({
        "jsonrpc": "2.0",
        "result": {
            "slot": 12345,
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "program": "spl-token",
                            "parsed": {
                                "type": "transfer",
                                "info": {
                                    "source": user_ata.to_string(),
                                    "destination": "AnyMerchantATA",
                                    "amount": "45000000", // 45 USDC spent
                                    "authority": agent_pubkey.to_string()
                                }
                            }
                        }
                    ]
                }
            },
            "meta": {
                "err": null,
                "innerInstructions": []
            }
        },
        "id": 1
    }).to_string();
    
    let mock = MockHttpRequester {
        account_info_response: account_info,
        signatures_response: signatures,
        transaction_response: tx_details,
    };
    
    // Spent 45 USDC in last 24h + 10 USDC requested charge = 55 USDC.
    // This exceeds the 50 USDC daily cap!
    let res = execute_charge(
        &mock,
        "http://mock",
        &agent_private_key,
        &owner,
        &merchant,
        &mint,
        10_000_000, // 10 USDC
        50_000_000, // 50 USDC daily cap
        current_time,
    );
    
    assert!(res.is_err(), "Daily cap check should have failed");
    let err_msg = res.err().unwrap();
    assert!(err_msg.contains("Daily spending cap exceeded"), "Unexpected error: {}", err_msg);
}
