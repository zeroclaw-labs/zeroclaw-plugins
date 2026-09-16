#![allow(dead_code)]

use std::{cell::RefCell, collections::HashMap, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use nanosol::pubkey::{Pubkey, LEGACY_TOKEN_PROGRAM_ID};
use serde_json::{json, Value};
use spl_transfer_build::rpc::{RpcTransport, TransportError};

pub const SENDER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
pub const RECIPIENT: &str = "FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa";
pub const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const OTHER_MINT: &str = "So11111111111111111111111111111111111111112";
pub const BLOCKHASH: &str = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";
pub const RPC_URL: &str = "https://rpc.example.invalid/solana";

pub fn pubkey(value: &str) -> Pubkey {
    Pubkey::from_str(value).expect("public key fixture")
}

pub fn mint_data(decimals: u8) -> Vec<u8> {
    let mut data = vec![0; 82];
    data[44] = decimals;
    data[45] = 1;
    data
}

pub fn token_2022_data(decimals: u8, entries: &[(u16, usize)]) -> Vec<u8> {
    if entries.is_empty() {
        return mint_data(decimals);
    }
    let mut data = vec![0; 166];
    data[..82].copy_from_slice(&mint_data(decimals));
    data[165] = 1;
    for (kind, length) in entries {
        data.extend_from_slice(&kind.to_le_bytes());
        data.extend_from_slice(
            &u16::try_from(*length)
                .expect("fixture length")
                .to_le_bytes(),
        );
        data.extend(std::iter::repeat(0).take(*length));
    }
    data
}

pub fn envelope(id: u64, result: Value) -> String {
    json!({"jsonrpc":"2.0","id":id,"result":result}).to_string()
}

pub fn account_response(owner: Pubkey, data: &[u8]) -> String {
    envelope(
        1,
        json!({
            "context":{"slot":123},
            "value":{
                "data":[STANDARD.encode(data),"base64"],
                "executable":false,
                "lamports":1,
                "owner":owner.to_string(),
                "space":data.len()
            }
        }),
    )
}

pub fn blockhash_response() -> String {
    envelope(
        2,
        json!({
            "context":{"slot":124},
            "value":{"blockhash":BLOCKHASH,"lastValidBlockHeight":500000}
        }),
    )
}

pub fn simulation_response(error: Value) -> String {
    envelope(
        3,
        json!({"context":{"slot":125},"value":{"err":error,"logs":[]}}),
    )
}

#[derive(Debug)]
pub struct MockTransport {
    pub mint: String,
    pub blockhash: String,
    pub simulation: String,
    pub transport_error: Option<TransportError>,
    pub calls: RefCell<Vec<(String, String, usize)>>,
}

impl MockTransport {
    pub fn valid(decimals: u8) -> Self {
        Self {
            mint: account_response(LEGACY_TOKEN_PROGRAM_ID, &mint_data(decimals)),
            blockhash: blockhash_response(),
            simulation: simulation_response(Value::Null),
            transport_error: None,
            calls: RefCell::new(Vec::new()),
        }
    }

    pub fn methods(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .map(|(_, body, _)| {
                serde_json::from_str::<Value>(body).expect("request JSON")["method"]
                    .as_str()
                    .expect("method")
                    .to_string()
            })
            .collect()
    }
}

impl RpcTransport for MockTransport {
    fn post(
        &self,
        endpoint: &str,
        request_body: &str,
        maximum_bytes: usize,
    ) -> Result<String, TransportError> {
        self.calls.borrow_mut().push((
            endpoint.to_string(),
            request_body.to_string(),
            maximum_bytes,
        ));
        if let Some(error) = &self.transport_error {
            return Err(error.clone());
        }
        let request: Value =
            serde_json::from_str(request_body).map_err(|_| TransportError::Unavailable)?;
        match request["method"].as_str() {
            Some("getAccountInfo") => Ok(self.mint.clone()),
            Some("getLatestBlockhash") => Ok(self.blockhash.clone()),
            Some("simulateTransaction") => Ok(self.simulation.clone()),
            _ => Err(TransportError::Unavailable),
        }
    }
}

pub fn valid_config() -> HashMap<String, String> {
    HashMap::from([
        ("rpc_url".to_string(), RPC_URL.to_string()),
        ("sender_pubkey".to_string(), SENDER.to_string()),
        ("mint_allowlist".to_string(), MINT.to_string()),
        ("max_amounts".to_string(), format!("{MINT}=1000")),
        ("mint_aliases".to_string(), format!("USDC={MINT}")),
        ("recipient_allowlist".to_string(), RECIPIENT.to_string()),
    ])
}

pub fn config_for(sender: &str, recipient: &str, cap: &str) -> HashMap<String, String> {
    HashMap::from([
        ("rpc_url".to_string(), RPC_URL.to_string()),
        ("sender_pubkey".to_string(), sender.to_string()),
        ("mint_allowlist".to_string(), MINT.to_string()),
        ("max_amounts".to_string(), format!("{MINT}={cap}")),
        ("mint_aliases".to_string(), format!("USDC={MINT}")),
        ("recipient_allowlist".to_string(), recipient.to_string()),
    ])
}

pub fn valid_args() -> Value {
    json!({
        "recipient": RECIPIENT,
        "amount": "25.01",
        "mint": "USDC",
        "memo": "invoice 412",
        "invoice_id": "412"
    })
}

/// Reproduce the checked-out host boundary: caller config is removed before
/// the resolved operator map is inserted.
pub fn host_inject(mut args: Value, trusted: &HashMap<String, String>) -> String {
    let object = args.as_object_mut().expect("arguments object");
    object.remove("__config");
    object.insert("__config".to_string(), json!(trusted));
    serde_json::to_string(&args).expect("component input")
}
