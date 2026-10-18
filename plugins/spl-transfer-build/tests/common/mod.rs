//! Fixtures and builders shared by the transfer-builder tests.
//!
//! Nothing here touches the network: every RPC response is assembled by hand
//! and replayed through `MockTransport`.

#![allow(dead_code)]

use base64::Engine;
use serde_json::{json, Value};
use solana_wasi::prelude::*;

/// The wallet the operator configures as the sender. A public key.
pub const SENDER: &str = "GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ";

/// An ordinary recipient wallet.
pub const RECIPIENT: &str = "9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP";

/// USDC.
pub const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// A second mint, never allowlisted in these tests.
pub const OTHER_MINT: &str = "So11111111111111111111111111111111111111112";

/// `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
pub const TOKEN_PROGRAM_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`
pub const TOKEN_2022_PROGRAM_STR: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// A real base58 blockhash, so the encoded transaction is well formed.
pub const BLOCKHASH: &str = "BkGvfegN5Xqa5s5Pv8kgHvg1sx3iaSipqKyKTiuWeKkT";

pub fn key(s: &str) -> Pubkey {
    Pubkey::from_base58(s).unwrap()
}

fn account(owner: &str, data: &[u8]) -> Value {
    json!({
        "lamports": 2_039_280u64,
        "owner": owner,
        "data": [base64::engine::general_purpose::STANDARD.encode(data), "base64"],
        "executable": false,
        "rentEpoch": 0
    })
}

/// A wallet: system-owned, no data.
pub fn wallet_account() -> Value {
    account("11111111111111111111111111111111", &[])
}

/// The 82-byte base mint, optionally with a Token-2022 extension area.
pub struct MintFixture {
    decimals: u8,
    freeze_authority: Option<Pubkey>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Default for MintFixture {
    fn default() -> Self {
        MintFixture {
            decimals: 6,
            freeze_authority: None,
            extensions: Vec::new(),
        }
    }
}

impl MintFixture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decimals(mut self, decimals: u8) -> Self {
        self.decimals = decimals;
        self
    }

    pub fn freeze_authority(mut self, key: Pubkey) -> Self {
        self.freeze_authority = Some(key);
        self
    }

    pub fn extension(mut self, kind: u16, value: Vec<u8>) -> Self {
        self.extensions.push((kind, value));
        self
    }

    pub fn non_transferable(self) -> Self {
        self.extension(9, Vec::new())
    }

    pub fn default_frozen(self) -> Self {
        self.extension(6, vec![2])
    }

    pub fn paused(self, authority: Pubkey) -> Self {
        let mut v = authority.as_bytes().to_vec();
        v.push(1);
        self.extension(26, v)
    }

    pub fn transfer_hook(self, program: Pubkey) -> Self {
        let mut v = vec![0u8; 32];
        v.extend_from_slice(program.as_bytes());
        self.extension(14, v)
    }

    pub fn permanent_delegate(self, delegate: Pubkey) -> Self {
        self.extension(12, delegate.as_bytes().to_vec())
    }

    pub fn transfer_fee(self, bps: u16) -> Self {
        let mut v = vec![0u8; 72];
        for _ in 0..2 {
            v.extend_from_slice(&600u64.to_le_bytes());
            v.extend_from_slice(&0u64.to_le_bytes());
            v.extend_from_slice(&bps.to_le_bytes());
        }
        self.extension(1, v)
    }

    fn bytes(&self) -> Vec<u8> {
        let mut data = vec![0u8; 82];
        data[36..44].copy_from_slice(&1_000_000_000_000u64.to_le_bytes());
        data[44] = self.decimals;
        data[45] = 1;
        if let Some(k) = self.freeze_authority {
            data[46..50].copy_from_slice(&1u32.to_le_bytes());
            data[50..82].copy_from_slice(k.as_bytes());
        }
        if self.extensions.is_empty() {
            return data;
        }
        data.resize(165, 0);
        data.push(1); // account type: mint
        for (kind, value) in &self.extensions {
            data.extend_from_slice(&kind.to_le_bytes());
            data.extend_from_slice(&(value.len() as u16).to_le_bytes());
            data.extend_from_slice(value);
        }
        data
    }

    /// The `getAccountInfo` response for this mint.
    pub fn response(&self) -> Value {
        let owner = if self.extensions.is_empty() {
            TOKEN_PROGRAM_STR
        } else {
            TOKEN_2022_PROGRAM_STR
        };
        json!({ "context": { "slot": 1 }, "value": account(owner, &self.bytes()) })
    }

    pub fn program(&self) -> TokenProgram {
        if self.extensions.is_empty() {
            TokenProgram::Legacy
        } else {
            TokenProgram::Token2022
        }
    }
}

/// A 165-byte token account holding `amount`.
pub fn token_account(mint: &str, owner: &str, amount: u64, frozen: bool) -> Value {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(key(mint).as_bytes());
    data[32..64].copy_from_slice(key(owner).as_bytes());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = if frozen { 2 } else { 1 };
    account(TOKEN_PROGRAM_STR, &data)
}

/// A `getMultipleAccounts` response, in the order the builder asks for them.
pub fn multiple(values: Vec<Value>) -> Value {
    json!({ "context": { "slot": 1 }, "value": values })
}

/// An initialized nonce account.
pub fn nonce_account(authority: &str) -> Value {
    let mut data = vec![0u8; 80];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..36].copy_from_slice(key(authority).as_bytes());
    data[36..68].copy_from_slice(&[9u8; 32]);
    data[68..76].copy_from_slice(&5_000u64.to_le_bytes());
    account("11111111111111111111111111111111", &data)
}

pub fn blockhash_response() -> Value {
    json!({
        "context": { "slot": 1 },
        "value": { "blockhash": BLOCKHASH, "lastValidBlockHeight": 400_000_000u64 }
    })
}

pub fn simulation_ok() -> Value {
    json!({
        "context": { "slot": 1 },
        "value": { "err": Value::Null, "logs": [], "unitsConsumed": 4218 }
    })
}

pub fn simulation_failed(err: &str) -> Value {
    json!({
        "context": { "slot": 1 },
        "value": { "err": err, "logs": [], "unitsConsumed": 0 }
    })
}
