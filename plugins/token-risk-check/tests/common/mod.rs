//! Fixtures and builders shared by the risk tests.
//!
//! Two real mainnet mints, frozen as bytes, plus a builder for the synthetic
//! Token-2022 mints that exercise the extensions no real token combines. No
//! test here touches the network.

#![allow(dead_code)]

use base64::Engine;
use serde_json::{json, Value};
use solana_wasi::prelude::*;
use solana_wasi::metadata::metadata_address;

/// USDC: legacy SPL Token, freeze and mint authority live, no extensions.
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// PayPal USD: Token-2022 with a permanent delegate, an unarmed transfer hook,
/// a zero-but-raisable fee, and confidential transfers.
pub const PYUSD_MINT: &str = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";

/// `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
pub const TOKEN_PROGRAM_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`
pub const TOKEN_2022_PROGRAM_STR: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
/// `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s`
pub const METAPLEX_PROGRAM_STR: &str = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";

/// An arbitrary well-formed address used as an authority in synthetic mints.
pub const SOME_AUTHORITY: &str = "9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP";

/// The real 82-byte USDC mint account.
pub const USDC_MINT_DATA_B64: &str = concat!(
    "AQAAAJj+huiNm+Lqi8HMpIeLKYjCQPUrhCS/tA7Rot3LXhmbCAVUbg2lHAAGAQEAAABicKqK",
    "WcWUBbRShshncubNEm6bil06OFNtN/e0FOi2Zw==",
);

/// The real 866-byte PYUSD mint account.
pub const PYUSD_MINT_DATA_B64: &str = concat!(
    "AQAAAGyRqkllkBL4q+lh7CS2EHSSZUdTL/CU7VtpOYLbmHMTZD6dDu5sAgAGAQEAAAAXhTJh",
    "72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAQMAIAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKwwAIAAXhTJh72q4Uypn",
    "8FOGWq0xKT/PB88SCrW5oVcGVI3AKwEAbAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcG",
    "VI3AKxeFMmHvarhTKmfwU4ZarTEpP88HzxIKtbmhVwZUjcArAAAAAAAAAABdAgAAAAAAAAAA",
    "AAAAAAAAAABdAgAAAAAAAAAAAAAAAAAAAAAEAEEAF4UyYe9quFMqZ/BThlqtMSk/zwfPEgq1",
    "uaFXBlSNwCsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAIEAF4UyYe9quFMq",
    "Z/BThlqtMSk/zwfPEgq1uaFXBlSNwCscN+ZDO3ME3YJzeuQNm4vzxJ9bDmxJqNUzKLPlBpAc",
    "VwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAADgBAABeFMmHvarhTKmfwU4ZarTEpP88HzxIKtbmhVwZUjcArAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAEAAF4UyYe9quFMqZ/BThlqtMSk/zwfPEgq1",
    "uaFXBlSNwCsXkkg7bIoqh7dHHYFPlZH5OVyECpzj2fTVun06S4p0nhMArgAXhTJh72q4Uypn",
    "8FOGWq0xKT/PB88SCrW5oVcGVI3AKxeSSDtsiiqHt0cdgU+Vkfk5XIQKnOPZ9NW6fTpLinSe",
    "CgAAAFBheVBhbCBVU0QFAAAAUFlVU0RPAAAAaHR0cHM6Ly90b2tlbi1tZXRhZGF0YS5wYXhv",
    "cy5jb20vcHl1c2RfbWV0YWRhdGEvcHJvZC9zb2xhbmEvcHl1c2RfbWV0YWRhdGEuanNvbgAA",
    "AAA=",
);


/// Build a Token-2022 mint buffer: the 82-byte base, padded to 165, the mint
/// account-type byte, then TLV extension entries.
pub struct MintBuilder {
    mint_authority: Option<Pubkey>,
    freeze_authority: Option<Pubkey>,
    supply: u64,
    decimals: u8,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Default for MintBuilder {
    fn default() -> Self {
        MintBuilder {
            mint_authority: None,
            freeze_authority: None,
            supply: 1_000_000_000_000,
            decimals: 6,
            extensions: Vec::new(),
        }
    }
}

impl MintBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mint_authority(mut self, key: Pubkey) -> Self {
        self.mint_authority = Some(key);
        self
    }

    pub fn freeze_authority(mut self, key: Pubkey) -> Self {
        self.freeze_authority = Some(key);
        self
    }

    pub fn supply(mut self, supply: u64) -> Self {
        self.supply = supply;
        self
    }

    /// Add a raw TLV entry. Raw on purpose: several tests need a payload that
    /// no well-behaved mint would ever write.
    pub fn extension(mut self, kind: u16, value: Vec<u8>) -> Self {
        self.extensions.push((kind, value));
        self
    }

    pub fn permanent_delegate(self, delegate: Pubkey) -> Self {
        self.extension(12, delegate.as_bytes().to_vec())
    }

    pub fn non_transferable(self) -> Self {
        self.extension(9, Vec::new())
    }

    pub fn default_frozen(self) -> Self {
        self.extension(6, vec![2])
    }

    pub fn pausable(self, authority: Pubkey, paused: bool) -> Self {
        let mut v = authority.as_bytes().to_vec();
        v.push(u8::from(paused));
        self.extension(26, v)
    }

    pub fn transfer_hook(self, authority: Option<Pubkey>, program: Option<Pubkey>) -> Self {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(authority.map(|a| *a.as_bytes()).unwrap_or([0u8; 32]).as_slice());
        v.extend_from_slice(program.map(|a| *a.as_bytes()).unwrap_or([0u8; 32]).as_slice());
        self.extension(14, v)
    }

    pub fn transfer_fee(self, authority: Option<Pubkey>, bps: u16) -> Self {
        let mut v = Vec::with_capacity(108);
        v.extend_from_slice(authority.map(|a| *a.as_bytes()).unwrap_or([0u8; 32]).as_slice());
        v.extend_from_slice(&[0u8; 32]); // withdraw withheld authority
        v.extend_from_slice(&0u64.to_le_bytes()); // withheld amount
        for _ in 0..2 {
            v.extend_from_slice(&600u64.to_le_bytes()); // epoch
            v.extend_from_slice(&0u64.to_le_bytes()); // maximum fee
            v.extend_from_slice(&bps.to_le_bytes());
        }
        self.extension(1, v)
    }

    /// The `TokenMetadata` extension, carrying whatever strings a test wants.
    pub fn token_metadata(self, name: &str, symbol: &str, uri: &str) -> Self {
        let mut v = Vec::new();
        v.extend_from_slice(&[0u8; 32]); // update authority: none
        v.extend_from_slice(&[0u8; 32]); // mint
        for s in [name, symbol, uri] {
            v.extend_from_slice(&(s.len() as u32).to_le_bytes());
            v.extend_from_slice(s.as_bytes());
        }
        v.extend_from_slice(&0u32.to_le_bytes()); // no additional metadata
        self.extension(19, v)
    }

    /// Serialize as a legacy SPL Token mint: 82 bytes, no extension area.
    pub fn legacy_bytes(&self) -> Vec<u8> {
        let mut data = vec![0u8; 82];
        if let Some(key) = self.mint_authority {
            data[0..4].copy_from_slice(&1u32.to_le_bytes());
            data[4..36].copy_from_slice(key.as_bytes());
        }
        data[36..44].copy_from_slice(&self.supply.to_le_bytes());
        data[44] = self.decimals;
        data[45] = 1;
        if let Some(key) = self.freeze_authority {
            data[46..50].copy_from_slice(&1u32.to_le_bytes());
            data[50..82].copy_from_slice(key.as_bytes());
        }
        data
    }

    /// Serialize as a Token-2022 mint with its extension area.
    pub fn bytes(&self) -> Vec<u8> {
        let mut data = self.legacy_bytes();
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

    pub fn legacy_account(&self) -> Value {
        raw_account(TOKEN_PROGRAM_STR, &self.legacy_bytes())
    }

    pub fn account(&self) -> Value {
        raw_account(TOKEN_2022_PROGRAM_STR, &self.bytes())
    }
}

/// A Metaplex `MetadataV1` account, for the legacy-token metadata path.
pub fn metaplex_account(name: &str, symbol: &str, uri: &str, mutable: bool) -> Value {
    let mut data = vec![4u8]; // key: MetadataV1
    data.extend_from_slice(&[1u8; 32]); // update authority
    data.extend_from_slice(&[2u8; 32]); // mint
    for s in [name, symbol, uri] {
        data.extend_from_slice(&(s.len() as u32).to_le_bytes());
        data.extend_from_slice(s.as_bytes());
    }
    data.extend_from_slice(&0u16.to_le_bytes()); // seller fee
    data.push(0); // no creators
    data.push(0); // primary sale
    data.push(u8::from(mutable));
    raw_account(METAPLEX_PROGRAM_STR, &data)
}

fn raw_account(owner: &str, data: &[u8]) -> Value {
    json!({
        "lamports": 1_000_000u64,
        "owner": owner,
        "data": [base64::engine::general_purpose::STANDARD.encode(data), "base64"],
        "executable": false,
        "rentEpoch": 0
    })
}

/// The `getMultipleAccounts` response for `[mint, metadata]`.
pub fn multiple(mint: Value, metadata: Option<Value>) -> Value {
    json!({
        "context": { "slot": 1 },
        "value": [mint, metadata.unwrap_or(Value::Null)]
    })
}

/// A `getTokenLargestAccounts` response with the given raw balances.
pub fn largest(amounts: &[u128]) -> Value {
    let rows: Vec<Value> = amounts
        .iter()
        .map(|a| json!({ "address": USDC_MINT, "amount": a.to_string(), "decimals": 6 }))
        .collect();
    json!({ "context": { "slot": 1 }, "value": rows })
}

pub fn key(s: &str) -> Pubkey {
    Pubkey::from_base58(s).unwrap()
}

/// The metadata PDA a check will ask for, so a test can assert the batch.
pub fn metadata_pda_of(mint: &str) -> Pubkey {
    metadata_address(&key(mint)).unwrap()
}
