use base64::Engine;
use serde_json::{json, Value};

use crate::keys::Pubkey;
use crate::nonce::{parse_nonce_account, NonceState};
use crate::{CoreError, CoreResult};

const MODERN_MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const LEGACY_MEMO_PROGRAM_ID: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";

pub trait HttpClient {
    fn post_json(&self, url: &str, body: &Value) -> CoreResult<Value>;
}

pub struct Rpc<'a, H: HttpClient> {
    pub url: &'a str,
    pub http: &'a H,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureInfo {
    pub signature: String,
    pub block_time: Option<i64>,
    pub err: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMemoTx {
    pub signature: String,
    pub block_time: Option<i64>,
    pub memo: String,
}

impl<'a, H: HttpClient> Rpc<'a, H> {
    pub fn get_account_data(&self, pubkey: &Pubkey) -> CoreResult<Vec<u8>> {
        let response = self.call(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [
                pubkey.to_base58(),
                { "encoding": "base64" }
            ]
        }))?;
        let value = response
            .get("value")
            .ok_or_else(|| CoreError::msg("missing account value"))?;
        if value.is_null() {
            return Err(CoreError::msg("account not found"));
        }

        let data = value
            .get("data")
            .ok_or_else(|| CoreError::msg("missing account data"))?;
        let encoded = data
            .as_array()
            .and_then(|data| data.first())
            .and_then(Value::as_str)
            .ok_or_else(|| CoreError::msg("missing base64 account data"))?;

        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| CoreError::msg(format!("invalid base64 account data: {e}")))
    }

    pub fn get_nonce(&self, nonce_account: &Pubkey) -> CoreResult<NonceState> {
        let data = self.get_account_data(nonce_account)?;
        parse_nonce_account(&data)
    }

    pub fn get_signatures_for_address(
        &self,
        address: &Pubkey,
        limit: usize,
    ) -> CoreResult<Vec<SignatureInfo>> {
        let response = self.call(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [
                address.to_base58(),
                { "limit": limit }
            ]
        }))?;
        let items = response
            .as_array()
            .ok_or_else(|| CoreError::msg("signatures result must be an array"))?;

        items
            .iter()
            .map(|item| {
                let signature = item
                    .get("signature")
                    .and_then(Value::as_str)
                    .ok_or_else(|| CoreError::msg("signature entry missing signature"))?
                    .to_string();
                let block_time = item.get("blockTime").and_then(Value::as_i64);
                let err = item.get("err").filter(|err| !err.is_null()).cloned();

                Ok(SignatureInfo {
                    signature,
                    block_time,
                    err,
                })
            })
            .collect()
    }

    pub fn get_transaction_memo(&self, signature: &str) -> CoreResult<Option<ParsedMemoTx>> {
        let response = self.call(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }
            ]
        }))?;
        if response.is_null() {
            return Ok(None);
        }

        let block_time = response.get("blockTime").and_then(Value::as_i64);
        let instructions = response
            .pointer("/transaction/message/instructions")
            .and_then(Value::as_array)
            .ok_or_else(|| CoreError::msg("transaction missing instructions"))?;

        for instruction in instructions {
            let Some(program_id) = instruction.get("programId").and_then(Value::as_str) else {
                continue;
            };
            if !is_memo_program(program_id) {
                continue;
            }

            if let Some(memo) = extract_memo(instruction) {
                return Ok(Some(ParsedMemoTx {
                    signature: signature.to_string(),
                    block_time,
                    memo,
                }));
            }
        }

        Ok(None)
    }

    fn call(&self, body: Value) -> CoreResult<Value> {
        if self.url.trim().is_empty() {
            return Err(CoreError::msg("rpc url is empty"));
        }

        let response = self.http.post_json(self.url, &body)?;
        if let Some(error) = response.get("error") {
            return Err(rpc_error(error));
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| CoreError::msg("rpc response missing result"))
    }
}

fn is_memo_program(program_id: &str) -> bool {
    program_id == MODERN_MEMO_PROGRAM_ID || program_id == LEGACY_MEMO_PROGRAM_ID
}

fn extract_memo(instruction: &Value) -> Option<String> {
    instruction
        .get("parsed")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            instruction
                .pointer("/parsed/info/memo")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
}

fn rpc_error(error: &Value) -> CoreError {
    let code = error
        .get("code")
        .map(value_to_short_string)
        .unwrap_or_else(|| "unknown".to_string());
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown rpc error");

    CoreError::msg(format!("rpc error {code}: {message}"))
}

fn value_to_short_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
