#![allow(dead_code)]

//! Shared fixtures: settled-transaction builders and a programmable mock RPC.
//!
//! Transaction wire bytes are built with `nanosol`'s instruction and message
//! codecs, which are themselves golden-tested byte-for-byte against the official
//! `solana-message`, `solana-transaction`, and SPL Token crates in the core
//! crate's own suite. These fixtures therefore describe real wire shapes without
//! pulling a Solana SDK into a plugin's dependency tree.

use std::{cell::RefCell, collections::HashMap, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use nanosol::{
    instruction::{transfer_checked, AccountMeta, Instruction, TokenProgram},
    message::{Message, MessageVersion, Transaction, SIGNATURE_BYTES},
    pubkey::{
        derive_associated_token_address, Pubkey, LEGACY_TOKEN_PROGRAM_ID, MEMO_V3_PROGRAM_ID,
        TOKEN_2022_PROGRAM_ID,
    },
    reference::derive_payment_reference,
    signature::Signature,
};
use serde_json::{json, Value};
use solana_pay_confirm::rpc::{RpcTransport, TransportError};

pub const PAYER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
pub const RECIPIENT: &str = "FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa";
pub const OTHER_RECIPIENT: &str = "9aa1DfPZ4TR9nUqBpGVFhtsFocaqfhpjNiTLuxfJQQmv";
pub const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const OTHER_MINT: &str = "So11111111111111111111111111111111111111112";
pub const RPC_URL: &str = "https://rpc.example.invalid/solana";
pub const RPC_URL_SECONDARY: &str = "https://backup.example.invalid/solana";
pub const INVOICE: &str = "412";
pub const AMOUNT: &str = "1.5";
pub const DECIMALS: u8 = 6;
pub const RAW_AMOUNT: u64 = 1_500_000;
pub const SLOT: u64 = 300_112;

pub fn pubkey(value: &str) -> Pubkey {
    Pubkey::from_str(value).expect("public key fixture")
}

pub fn signature(byte: u8) -> Signature {
    Signature::new([byte; SIGNATURE_BYTES])
}

/// The reference `solana-pay-request` derives for the standard fixture invoice.
pub fn fixture_reference() -> Pubkey {
    derive_payment_reference(&pubkey(RECIPIENT), Some(&pubkey(MINT)), AMOUNT, INVOICE)
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

pub fn account_result(owner: Pubkey, data: &[u8]) -> Value {
    json!({
        "context": {"slot": SLOT},
        "value": {
            "data": [STANDARD.encode(data), "base64"],
            "executable": false,
            "lamports": 1_461_600,
            "owner": owner.to_string(),
            "space": data.len()
        }
    })
}

pub fn mint_result(decimals: u8) -> Value {
    account_result(LEGACY_TOKEN_PROGRAM_ID, &mint_data(decimals))
}

pub fn token_2022_mint_result(decimals: u8, extensions: &[(u16, usize)]) -> Value {
    account_result(
        TOKEN_2022_PROGRAM_ID,
        &token_2022_data(decimals, extensions),
    )
}

/// One `getSignaturesForAddress` entry.
pub fn signature_entry(signature: &Signature, status: &str, slot: u64, failed: bool) -> Value {
    json!({
        "signature": signature.to_string(),
        "slot": slot,
        "err": if failed { json!({"InstructionError": [1, "Custom"]}) } else { Value::Null },
        "memo": Value::Null,
        "blockTime": 1_777_000_000_u64,
        "confirmationStatus": status
    })
}

pub fn token_balance(
    index: usize,
    mint: Pubkey,
    owner: Pubkey,
    raw: u64,
    decimals: u8,
    program: Pubkey,
) -> Value {
    json!({
        "accountIndex": index,
        "mint": mint.to_string(),
        "owner": owner.to_string(),
        "programId": program.to_string(),
        "uiTokenAmount": {
            "amount": raw.to_string(),
            "decimals": decimals,
            "uiAmount": 0.0,
            "uiAmountString": "0"
        }
    })
}

/// A settled SPL token transfer, in the shapes a real wallet submits.
#[derive(Debug, Clone)]
pub struct SettledTransfer {
    pub version: MessageVersion,
    /// `true` builds `TransferChecked`, `false` a plain `Transfer`.
    pub checked: bool,
    pub authority: Pubkey,
    pub recipient: Pubkey,
    pub mint: Pubkey,
    pub token_program: TokenProgram,
    pub decimals: u8,
    pub amount: u64,
    /// Attached to the transfer instruction as a read-only non-signer.
    pub reference_in_transfer: Option<Pubkey>,
    /// Attach the reference to the transfer instruction as a *writable* account
    /// instead, which Solana Pay never does.
    pub reference_writable: bool,
    /// Present in the transaction, but on an unrelated instruction.
    pub reference_elsewhere: Option<Pubkey>,
    /// Append a second, identical transfer instruction.
    pub second_transfer: bool,
    /// Overrides the derived destination associated token account.
    pub destination_override: Option<Pubkey>,
    pub signature_byte: u8,
}

impl SettledTransfer {
    /// The honest fixture: exactly what a wallet paying the fixture invoice does.
    pub fn paying(reference: Pubkey) -> Self {
        Self {
            version: MessageVersion::V0,
            checked: true,
            authority: pubkey(PAYER),
            recipient: pubkey(RECIPIENT),
            mint: pubkey(MINT),
            token_program: TokenProgram::Legacy,
            decimals: DECIMALS,
            amount: RAW_AMOUNT,
            reference_in_transfer: Some(reference),
            reference_writable: false,
            reference_elsewhere: None,
            second_transfer: false,
            destination_override: None,
            signature_byte: 0x11,
        }
    }

    pub fn signature(&self) -> Signature {
        signature(self.signature_byte)
    }

    pub fn destination(&self) -> Pubkey {
        self.destination_override.unwrap_or_else(|| {
            derive_associated_token_address(&self.recipient, &self.mint, &self.token_program.id())
                .expect("destination ATA")
                .0
        })
    }

    fn source(&self) -> Pubkey {
        derive_associated_token_address(&self.authority, &self.mint, &self.token_program.id())
            .expect("source ATA")
            .0
    }

    pub fn message(&self) -> Message {
        let mut transfer = if self.checked {
            transfer_checked(
                self.source(),
                self.mint,
                self.destination(),
                self.authority,
                self.amount,
                self.decimals,
                self.token_program,
            )
        } else {
            // SPL Token `Transfer`: no mint account, no decimals.
            let mut data = Vec::with_capacity(9);
            data.push(3);
            data.extend_from_slice(&self.amount.to_le_bytes());
            Instruction {
                program_id: self.token_program.id(),
                accounts: vec![
                    AccountMeta::writable(self.source(), false),
                    AccountMeta::writable(self.destination(), false),
                    AccountMeta::readonly(self.authority, true),
                ],
                data,
            }
        };
        if let Some(reference) = self.reference_in_transfer {
            transfer.accounts.push(if self.reference_writable {
                AccountMeta::writable(reference, false)
            } else {
                AccountMeta::readonly(reference, false)
            });
        }
        let mut instructions = vec![transfer.clone()];
        if self.second_transfer {
            instructions.push(transfer);
        }
        if let Some(reference) = self.reference_elsewhere {
            instructions.push(Instruction {
                program_id: MEMO_V3_PROGRAM_ID,
                accounts: vec![AccountMeta::readonly(reference, false)],
                data: b"invoice".to_vec(),
            });
        }
        Message::compile(self.version, self.authority, [7; 32], &instructions)
            .expect("settled message")
    }

    pub fn bytes(&self) -> Vec<u8> {
        let message = self.message();
        let signatures = vec![
            [self.signature_byte; SIGNATURE_BYTES];
            usize::from(message.header.num_required_signatures)
        ];
        Transaction {
            signatures,
            message,
        }
        .serialize()
        .expect("settled transaction bytes")
    }

    /// The account-list index a token balance must use for the destination.
    pub fn destination_index(&self) -> usize {
        let destination = self.destination();
        self.message()
            .account_keys
            .iter()
            .position(|key| key == &destination)
            .expect("destination in account keys")
    }

    /// A `getTransaction` result whose balances show exactly `received` arriving.
    pub fn result(&self, received: u64) -> Value {
        self.result_with_balances(
            json!([]),
            json!([token_balance(
                self.destination_index(),
                self.mint,
                self.recipient,
                received,
                self.decimals,
                self.token_program.id()
            )]),
            Value::Null,
        )
    }

    pub fn result_with_balances(&self, pre: Value, post: Value, error: Value) -> Value {
        json!({
            "slot": SLOT,
            "blockTime": 1_777_000_000_u64,
            "transaction": [STANDARD.encode(self.bytes()), "base64"],
            "meta": {
                "err": error,
                "fee": 5000,
                "logMessages": ["Program log: Instruction: TransferChecked"],
                "preTokenBalances": pre,
                "postTokenBalances": post
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub endpoint: String,
    pub body: String,
    pub maximum_bytes: usize,
}

impl Call {
    pub fn method(&self) -> String {
        self.json()["method"].as_str().expect("method").to_string()
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("request JSON")
    }
}

/// A programmable RPC endpoint pair.
///
/// Results are stored without an envelope and wrapped with the *request's* id,
/// so fixtures never hardcode request ids; a dedicated test covers id mismatch
/// through `raw_override`.
#[derive(Debug, Default)]
pub struct MockRpc {
    pub mint: Option<Value>,
    pub signatures: Value,
    pub transactions: HashMap<String, Value>,
    /// When `Some`, this endpoint answers `RPC_URL_SECONDARY`.
    pub secondary_transactions: Option<HashMap<String, Value>>,
    pub transport_error: Option<TransportError>,
    pub raw_override: Option<String>,
    pub calls: RefCell<Vec<Call>>,
}

impl MockRpc {
    /// A cluster where the fixture invoice was paid exactly once.
    pub fn paid(settled: &SettledTransfer) -> Self {
        Self::paid_with(settled, RAW_AMOUNT, "finalized")
    }

    pub fn paid_with(settled: &SettledTransfer, received: u64, status: &str) -> Self {
        Self {
            mint: Some(mint_result(DECIMALS)),
            signatures: json!([signature_entry(&settled.signature(), status, SLOT, false)]),
            transactions: HashMap::from([(
                settled.signature().to_string(),
                settled.result(received),
            )]),
            ..Self::default()
        }
    }

    /// A cluster where nothing references the invoice.
    pub fn unpaid() -> Self {
        Self {
            mint: Some(mint_result(DECIMALS)),
            signatures: json!([]),
            ..Self::default()
        }
    }

    pub fn with_secondary(mut self, transactions: HashMap<String, Value>) -> Self {
        self.secondary_transactions = Some(transactions);
        self
    }

    pub fn methods(&self) -> Vec<String> {
        self.calls.borrow().iter().map(Call::method).collect()
    }

    pub fn endpoints(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .map(|call| call.endpoint.clone())
            .collect()
    }

    pub fn call_bodies(&self, method: &str) -> Vec<Value> {
        self.calls
            .borrow()
            .iter()
            .filter(|call| call.method() == method)
            .map(Call::json)
            .collect()
    }
}

impl RpcTransport for MockRpc {
    fn post(
        &self,
        endpoint: &str,
        request_body: &str,
        maximum_bytes: usize,
    ) -> Result<String, TransportError> {
        self.calls.borrow_mut().push(Call {
            endpoint: endpoint.to_string(),
            body: request_body.to_string(),
            maximum_bytes,
        });
        if let Some(error) = &self.transport_error {
            return Err(error.clone());
        }
        if let Some(raw) = &self.raw_override {
            return Ok(raw.clone());
        }
        let request: Value =
            serde_json::from_str(request_body).map_err(|_| TransportError::Unavailable)?;
        let id = request["id"].as_u64().ok_or(TransportError::Unavailable)?;
        let result = match request["method"].as_str() {
            Some("getAccountInfo") => self
                .mint
                .clone()
                .unwrap_or_else(|| json!({"context": {"slot": SLOT}, "value": Value::Null})),
            Some("getSignaturesForAddress") => self.signatures.clone(),
            Some("getTransaction") => {
                let requested = request["params"][0].as_str().unwrap_or_default();
                let table = match (endpoint, &self.secondary_transactions) {
                    (RPC_URL_SECONDARY, Some(secondary)) => secondary,
                    _ => &self.transactions,
                };
                table.get(requested).cloned().unwrap_or(Value::Null)
            }
            _ => return Err(TransportError::Unavailable),
        };
        Ok(json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string())
    }
}

pub fn valid_config() -> HashMap<String, String> {
    HashMap::from([
        ("rpc_url".to_string(), RPC_URL.to_string()),
        ("allowed_recipients".to_string(), RECIPIENT.to_string()),
        ("mint_allowlist".to_string(), MINT.to_string()),
        ("mint_aliases".to_string(), format!("USDC={MINT}")),
    ])
}

pub fn config_with(key: &str, value: &str) -> HashMap<String, String> {
    let mut config = valid_config();
    config.insert(key.to_string(), value.to_string());
    config
}

pub fn valid_args() -> Value {
    json!({
        "recipient": RECIPIENT,
        "amount": AMOUNT,
        "mint": "USDC",
        "invoice_id": INVOICE
    })
}

/// Reproduce the host boundary: any caller-supplied `__config` is removed before
/// the resolved operator section is injected.
pub fn host_inject(mut args: Value, trusted: &HashMap<String, String>) -> String {
    let object = args.as_object_mut().expect("arguments object");
    object.remove("__config");
    object.insert("__config".to_string(), json!(trusted));
    serde_json::to_string(&args).expect("component input")
}

pub fn output(response: &solana_pay_confirm::confirm::ToolResponse) -> Value {
    assert!(
        response.success,
        "expected success, got refusal: {:?}",
        response.error
    );
    serde_json::from_str(&response.output).expect("tool output JSON")
}
