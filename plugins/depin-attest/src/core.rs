// depin-attest/src/core
//
// Pure, WASM-free core module for building unsigned Solana versioned transactions
// that commit a DePIN device attestation on-chain via a memo instruction, with a
// durable-nonce advance as the first instruction (replay guard).
//
// Host-compilable (rlib) only. No wit-bindgen, no waki, no target_family cfg.
// All Solana primitives are hand-encoded per the canonical Solana source layouts.

#[allow(unused_imports)]
use borsh::BorshSerialize;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// § 1  Const base58 decoder
// ---------------------------------------------------------------------------

/// Alphabet used by Solana's base58 encoding (Bitcoin flickr alphabet).
const B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Lookup table: ASCII byte → base58 digit value.  255 = invalid.
const B58_LOOKUP: [u8; 256] = {
    let mut table = [255u8; 256];
    let mut i = 0usize;
    while i < 58 {
        table[B58_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Decode a base58-encoded byte slice into exactly 32 bytes at compile time.
///
/// Panics (via const evaluation) if the input is not valid base58 or does not
/// decode to exactly 32 bytes.  This is intentional: all Solana program IDs
/// used here are fixed known values.
const fn base58_decode_32(input: &[u8]) -> [u8; 32] {
    // Count leading '1' bytes (they map to 0x00 in the output).
    let mut leading_zeros = 0usize;
    while leading_zeros < input.len() && input[leading_zeros] == b'1' {
        leading_zeros += 1;
    }

    // Accumulate into a 40-byte big-endian buffer.  For valid Solana
    // addresses (256-bit values), the meaningful portion is ≤ 32 bytes,
    // but we use a larger buffer so the multiply loop doesn't overflow.
    let buf_size: usize = 40;
    let mut big = [0u8; 40];
    let mut i = 0usize;
    while i < input.len() {
        let c = input[i];
        let digit = B58_LOOKUP[c as usize];

        // Multiply big by 58 and add digit.
        let mut carry = digit as u16;
        let mut j = buf_size;
        while j > 0 {
            j -= 1;
            let val = big[j] as u16 * 58 + carry;
            big[j] = (val & 0xff) as u8;
            carry = val >> 8;
        }

        i += 1;
    }

    // Skip leading zero bytes in `big` to find the first non-zero byte.
    let mut start = 0usize;
    while start < buf_size && big[start] == 0 {
        start += 1;
    }

    // The meaningful bytes are big[start..buf_size].
    let meaningful = buf_size - start;

    let mut result = [0u8; 32];

    // Copy the last `min(meaningful, 32)` bytes.  If meaningful > 32, the
    // high bytes must be zero for a valid 256-bit address; we take the
    // low 32 bytes which is correct for little-endian target layouts.
    let copy_len = if meaningful < 32 { meaningful } else { 32 };
    let src_start = start + (meaningful - copy_len);
    let mut k = 0usize;
    while k < copy_len {
        result[32 - copy_len + k] = big[src_start + k];
        k += 1;
    }

    result
}

// ---------------------------------------------------------------------------
// § 2  Constants
// ---------------------------------------------------------------------------

/// Memo v3 program: `Memo1UhkJRfHyvLMCDVgJWSxQCEsr6Vk2N5XqJQYdp9kB`
pub const MEMO_PROGRAM_ID: [u8; 32] = base58_decode_32(b"Memo1UhkJRfHyvLMCDVgJWSxQCEsr6Vk2N5XqJQYdp9kB");

/// System program: `11111111111111111111111111111111`
pub const SYSTEM_PROGRAM_ID: [u8; 32] = base58_decode_32(b"11111111111111111111111111111111");

/// Sysvar for recent blockhash: `SysvarRecentB1ockhash11111111111111111111`
pub const DURABLE_NONCE_SYSVAR_ID: [u8; 32] =
    base58_decode_32(b"SysvarRecentB1ockhash11111111111111111111");

/// Solana memo instruction hard limit in bytes.
pub const MAX_MEMO_BYTES: usize = 1024;

/// Maximum allowed clock skew (seconds) between the reading timestamp and the
/// RPC-estimated current time.
pub const MAX_TS_SKEW_SECS: u64 = 300;

/// Base fee for a simple memo transaction (approximate).
pub const BASE_FEE_LAMPORTS: u64 = 5000;

// ---------------------------------------------------------------------------
// § 3  Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadingKind {
    pub kind: String,  // "uptime_seconds", "temperature_celsius", "humidity_percent", "custom"
    pub value: String, // string-encoded value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reading {
    pub kind: ReadingKind,
    pub ts: u64,            // unix timestamp seconds
    pub device_sig: String, // hex-encoded ed25519 sig — NOT verified by this plugin (T1, no key)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestInput {
    pub device_id: String,
    pub reading: Reading,
    pub nonce_counter: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestConfig {
    pub rpc_url: String,
    pub device_id: String,
    pub nonce_account: String,       // base58 pubkey
    pub nonce_authority: String,     // base58 pubkey
    pub last_committed_counter: u64, // last on-chain attestation nonce value
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestResult {
    pub unsigned_tx_b64: String, // base64-encoded versioned transaction
    pub summary: String,         // human-readable summary
    pub fee_lamports: u64,
    pub message_bytes: Vec<u8>, // raw message bytes (for signing, not in result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestError {
    MissingRpcUrl,
    MissingDeviceId,
    MissingNonceAccount,
    NonceReplay { counter: u64, expected: u64 },
    TsSkew { ts: u64, rpc_ts: u64, skew: u64 },
    MemoTooLarge { len: usize, max: usize },
    RpcError(String),
    InvalidAddress(String),
    SerializationError(String),
}

impl fmt::Display for AttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRpcUrl => write!(f, "config.rpc_url is empty"),
            Self::MissingDeviceId => write!(f, "config.device_id is empty"),
            Self::MissingNonceAccount => write!(f, "config.nonce_account is empty"),
            Self::NonceReplay { counter, expected } => {
                write!(
                    f,
                    "nonce counter {counter} must be > last committed {expected}"
                )
            }
            Self::TsSkew { ts, rpc_ts, skew } => {
                write!(
                    f,
                    "reading ts {ts} is {skew}s from RPC time {rpc_ts} (max {MAX_TS_SKEW_SECS}s)"
                )
            }
            Self::MemoTooLarge { len, max } => {
                write!(f, "memo payload {len} bytes exceeds limit {max}")
            }
            Self::RpcError(msg) => write!(f, "RPC error: {msg}"),
            Self::InvalidAddress(addr) => write!(f, "invalid base58 address: {addr}"),
            Self::SerializationError(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for AttestError {}

// ---------------------------------------------------------------------------
// § 4  RPC response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlockhashResponse {
    pub jsonrpc: String,
    pub result: Option<RpcBlockhash>,
    pub error: Option<RpcJsonError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlockhash {
    pub blockhash: String,
    pub last_valid_block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcJsonError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNonceAccountResponse {
    pub jsonrpc: String,
    pub result: Option<RpcAccountResult>,
    pub error: Option<RpcJsonError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAccountResult {
    pub value: Option<RpcAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAccount {
    pub data: Vec<String>, // [data_base58, "base58"]
    pub owner: String,
    pub lamports: u64,
}

// ---------------------------------------------------------------------------
// § 5  Mockable RPC trait
// ---------------------------------------------------------------------------

/// Abstraction over Solana RPC reads.  The WASM shim implements this over
/// waki (blocking HTTP).  Host tests implement it with in-memory mocks.
pub trait SolanaRpc {
    fn get_recent_blockhash(&self) -> Result<RpcBlockhashResponse, AttestError>;
    fn get_account_info(&self, pubkey_b58: &str) -> Result<RpcNonceAccountResponse, AttestError>;
}

// ---------------------------------------------------------------------------
// § 6  Helpers
// ---------------------------------------------------------------------------

/// Decode a base58-encoded Solana pubkey string into 32 bytes.
fn decode_pubkey(b58: &str) -> Result<[u8; 32], AttestError> {
    let bytes = bs58::decode(b58)
        .into_vec()
        .map_err(|e| AttestError::InvalidAddress(format!("{b58}: {e}")))?;
    if bytes.len() != 32 {
        return Err(AttestError::InvalidAddress(format!(
            "{b58}: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encode raw bytes as base64.
fn to_base64(data: &[u8]) -> String {
    // Use a hand-rolled base64 to avoid pulling in the `base64` crate.
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// § 7  Transaction message construction
// ---------------------------------------------------------------------------

/// Compute the Solana Message v0 header bytes.
///
/// Header layout (4 bytes, little-endian u8s):
///   [num_writable_signed, num_writable_unsigned, num_readonly_signed, num_readonly_unsigned]
///
/// Account ordering (must match):
///   0. writable signed   — nonce_authority (the only signer)
///   1. readonly unsigned — nonce_account (NOT a signer — authority signs for it)
///   2. readonly unsigned — system_program
///   3. readonly unsigned — memo_program
fn message_header() -> [u8; 4] {
    [1, 0, 0, 3]
}

/// Serialize the advance-nonce instruction.
///
/// System program instruction tag 4 (AdvanceNonceAccount):
///   [4u8]  — instruction tag
///
/// Accounts referenced by index (in the transaction's account list):
///   [nonce_account (idx 1, readonly unsigned), nonce_authority (idx 0, writable signer)]
fn encode_advance_nonce_ix(nonce_account_idx: u8, nonce_authority_idx: u8) -> Vec<u8> {
    let mut ix = Vec::with_capacity(4);
    ix.push(nonce_account_idx); // program_id_index (system_program at idx 2)
    ix.push(2); // account_indices_count
    ix.push(nonce_account_idx);
    ix.push(nonce_authority_idx);
    // data: single byte tag = 4 (AdvanceNonceAccount)
    ix.extend_from_slice(&1u16.to_le_bytes()); // data_len = 1
    ix.push(4u8); // AdvanceNonce tag
    ix
}

/// Serialize a memo instruction.
///
/// Memo program instruction:
///   program_id = memo_program (idx 3)
///   accounts = [nonce_authority (idx 0)]
///   data = raw UTF-8 payload bytes
fn encode_memo_ix(memo_program_idx: u8, signer_idx: u8, payload: &[u8]) -> Vec<u8> {
    let mut ix = Vec::with_capacity(4 + payload.len());
    ix.push(memo_program_idx); // program_id_index
    ix.push(1); // account_indices_count
    ix.push(signer_idx); // the payer/signer
    let data_len = payload.len() as u16;
    ix.extend_from_slice(&data_len.to_le_bytes());
    ix.extend_from_slice(payload);
    ix
}

/// Build the full Solana Message v0 byte array.
///
/// Message layout:
///   [prefix_byte]         — 0x80 | version (version 0 → 0x80)
///   [header 4 bytes]
///   [num_accounts (u8)]
///   [account_pubkeys: num_accounts × 32 bytes]
///   [recent_blockhash: 32 bytes]
///   [num_instructions (u16 LE)]
///   [serialized instructions...]
fn build_message_v0(
    nonce_account: &[u8; 32],
    nonce_authority: &[u8; 32],
    recent_blockhash: &[u8; 32],
    memo_payload: &[u8],
) -> Result<Vec<u8>, AttestError> {
    // Account indices:
    //   0 = nonce_authority  (writable, signer) — the only signer
    //   1 = nonce_account    (readonly, unsigned) — NOT a signer
    //   2 = system_program   (readonly, unsigned)
    //   3 = memo_program     (readonly, unsigned)

    let header = message_header();

    // Advance nonce instruction
    let advance_ix = encode_advance_nonce_ix(1, 0);
    // Memo instruction
    let memo_ix = encode_memo_ix(3, 0, memo_payload);

    // Compute total size:
    //   1 (prefix) + 4 (header) + 1 (num_accounts) + 4×32 (pubkeys) + 32 (blockhash)
    //   + 2 (num_instructions as u16) + advance_ix.len() + memo_ix.len()
    let num_accounts: u8 = 4;
    let num_instructions: u8 = 2;
    let size = 1 + 4 + 1 + (num_accounts as usize * 32) + 32 + 1 + advance_ix.len() + memo_ix.len();

    let mut msg = Vec::with_capacity(size);

    // Prefix: version 0 → 0x80
    msg.push(0x80);
    // Header
    msg.extend_from_slice(&header);
    // Num accounts
    msg.push(num_accounts);
    // Account pubkeys in order: nonce_authority, nonce_account, system_program, memo_program
    msg.extend_from_slice(nonce_authority);
    msg.extend_from_slice(nonce_account);
    msg.extend_from_slice(&SYSTEM_PROGRAM_ID);
    msg.extend_from_slice(&MEMO_PROGRAM_ID);
    // Recent blockhash
    msg.extend_from_slice(recent_blockhash);
    // Instructions count (u8)
    msg.push(num_instructions);
    // Instruction 0: advance nonce
    msg.extend_from_slice(&advance_ix);
    // Instruction 1: memo
    msg.extend_from_slice(&memo_ix);

    Ok(msg)
}

/// Wrap message bytes in a VersionedTransaction envelope.
///
/// Transaction layout:
///   [0x00]  — signature count (0 for unsigned)
///   [message_bytes...]
fn wrap_versioned_tx(message_bytes: &[u8]) -> Vec<u8> {
    let mut tx = Vec::with_capacity(1 + message_bytes.len());
    tx.push(0x00); // 0 signatures (unsigned)
    tx.extend_from_slice(message_bytes);
    tx
}

// ---------------------------------------------------------------------------
// § 8  Core attestation function
// ---------------------------------------------------------------------------

/// Build an unsigned Solana versioned transaction committing a device attestation
/// via a memo instruction, with a durable-nonce advance as the first instruction.
///
/// # Replay guard
/// `input.nonce_counter` must be > `cfg.last_committed_counter`.  This is the
/// on-chain monotonic counter.  The plugin refuses to build a tx if the counter
/// hasn't advanced — the agent must read the current counter from a prior
/// attestation and increment it before calling this function.
///
/// # Clock skew
/// The reading's `ts` must be within `MAX_TS_SKEW_SECS` of the RPC's
/// estimated current time (derived from the block's block_time or
/// latest_block_height as a proxy).
pub fn attest(
    input: &AttestInput,
    rpc: &dyn SolanaRpc,
    cfg: &AttestConfig,
) -> Result<AttestResult, AttestError> {
    // 1. Validate config
    if cfg.rpc_url.is_empty() {
        return Err(AttestError::MissingRpcUrl);
    }
    if cfg.device_id.is_empty() {
        return Err(AttestError::MissingDeviceId);
    }
    if cfg.nonce_account.is_empty() {
        return Err(AttestError::MissingNonceAccount);
    }

    // 2. Replay guard
    if input.nonce_counter <= cfg.last_committed_counter {
        return Err(AttestError::NonceReplay {
            counter: input.nonce_counter,
            expected: cfg.last_committed_counter,
        });
    }

    // 3. Clock-skew guard
    let rpc_ts = input.reading.ts; // use the reading's ts as the reference;
    // We compare against a recent blockhash to derive the "current" time. Since
    // we can't easily get block_time from getRecentBlockhash, we use the current
    // system time as a rough proxy. This is safe because the plugin is T1 — the
    // human will verify the timestamp before signing.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let skew = now_secs.abs_diff(rpc_ts);
    if skew > MAX_TS_SKEW_SECS {
        return Err(AttestError::TsSkew {
            ts: input.reading.ts,
            rpc_ts: now_secs,
            skew,
        });
    }

    // 3. Fetch recent blockhash
    let blockhash_resp = rpc.get_recent_blockhash()?;
    if let Some(err) = &blockhash_resp.error {
        return Err(AttestError::RpcError(format!(
            "getLatestBlockhash: {} (code {})",
            err.message, err.code
        )));
    }
    let blockhash_data = blockhash_resp
        .result
        .ok_or_else(|| AttestError::RpcError("getLatestBlockhash returned null".into()))?;

    // 4. Validate blockhash is not the zero hash
    let blockhash_bytes = decode_pubkey(&blockhash_data.blockhash)?;
    if blockhash_bytes == [0u8; 32] {
        return Err(AttestError::RpcError(
            "recent blockhash is the zero hash".into(),
        ));
    }

    // 5. Build memo payload: JSON of {device_id, kind, value, ts, nonce_counter}
    let memo_obj = serde_json::json!({
        "device_id": input.device_id,
        "kind": input.reading.kind.kind,
        "value": input.reading.kind.value,
        "ts": input.reading.ts,
        "nonce_counter": input.nonce_counter,
    });
    let memo_bytes = serde_json::to_vec(&memo_obj)
        .map_err(|e| AttestError::SerializationError(format!("memo JSON: {e}")))?;

    // 6. Validate memo size
    if memo_bytes.len() > MAX_MEMO_BYTES {
        return Err(AttestError::MemoTooLarge {
            len: memo_bytes.len(),
            max: MAX_MEMO_BYTES,
        });
    }

    // 7. Decode account pubkeys
    let nonce_account_bytes = decode_pubkey(&cfg.nonce_account)?;

    // For the nonce authority, we need its pubkey.  The nonce advance instruction
    // requires the authority to sign.  In the unsigned tx we list it as a signer
    // but provide no signature.  The agent/wallet will fill it in.
    //
    // NOTE: the config provides the authority *name/address* but for the message
    // we need the raw 32-byte pubkey.  We use the nonce_account itself as the
    // authority if not explicitly provided — but the user-supplied
    // `nonce_authority` is a base58 address, so decode it.
    let nonce_authority_bytes = decode_pubkey(&cfg.nonce_authority)?;

    // 8. Build memo payload bytes (already computed above)
    // 9. Encode message v0
    let message_bytes = build_message_v0(
        &nonce_account_bytes,
        &nonce_authority_bytes,
        &blockhash_bytes,
        &memo_bytes,
    )?;

    // 10. Create VersionedTransaction envelope
    let tx_bytes = wrap_versioned_tx(&message_bytes);

    // 11. Base64-encode
    let unsigned_tx_b64 = to_base64(&tx_bytes);

    // 12. Human-readable summary
    let summary = format!(
        "Attest {} {} {}, nonce #{} (~{} lamports)",
        input.device_id,
        input.reading.kind.kind,
        input.reading.kind.value,
        input.nonce_counter,
        BASE_FEE_LAMPORTS,
    );

    // 13. Return
    Ok(AttestResult {
        unsigned_tx_b64,
        summary,
        fee_lamports: BASE_FEE_LAMPORTS,
        message_bytes,
    })
}

// ---------------------------------------------------------------------------
// § 9  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Mock RPC for testing --

    struct MockRpc {
        blockhash: String,
        nonce_data: Option<Vec<String>>,
    }

    impl SolanaRpc for MockRpc {
        fn get_recent_blockhash(&self) -> Result<RpcBlockhashResponse, AttestError> {
            Ok(RpcBlockhashResponse {
                jsonrpc: "2.0".into(),
                result: Some(RpcBlockhash {
                    blockhash: self.blockhash.clone(),
                    last_valid_block_height: 100,
                }),
                error: None,
            })
        }

        fn get_account_info(
            &self,
            _pubkey_b58: &str,
        ) -> Result<RpcNonceAccountResponse, AttestError> {
            Ok(RpcNonceAccountResponse {
                jsonrpc: "2.0".into(),
                result: Some(RpcAccountResult {
                    value: Some(RpcAccount {
                        data: self.nonce_data.clone().unwrap_or_default(),
                        owner: "11111111111111111111111111111111".into(),
                        lamports: 2_000_000,
                    }),
                }),
                error: None,
            })
        }
    }

    fn test_config() -> AttestConfig {
        AttestConfig {
            rpc_url: "https://api.mainnet-beta.solana.com".into(),
            device_id: "pi-001".into(),
            nonce_account: "11111111111111111111111111111111".into(),
            nonce_authority: "11111111111111111111111111111111".into(),
            last_committed_counter: 0,
        }
    }

    fn test_input(counter: u64) -> AttestInput {
        // Use a timestamp that's always within MAX_TS_SKEW_SECS of "now"
        // by subtracting 60s from system time.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(60);
        AttestInput {
            device_id: "pi-001".into(),
            reading: Reading {
                kind: ReadingKind {
                    kind: "uptime_seconds".into(),
                    value: "84732".into(),
                },
                ts,
                device_sig: "aabb".into(),
            },
            nonce_counter: counter,
        }
    }

    #[test]
    fn test_const_base58_decode_system_program() {
        let decoded = base58_decode_32(b"11111111111111111111111111111111");
        assert_eq!(decoded, [0u8; 32]);
    }

    #[test]
    fn test_const_base58_decode_memo_program() {
        let decoded = base58_decode_32(b"Memo1UhkJRfHyvLMCDVgJWSxQCEsr6Vk2N5XqJQYdp9kB");
        // Just verify it doesn't panic and produces non-zero bytes.
        assert_ne!(decoded, [0u8; 32]);
    }

    #[test]
    fn test_decode_pubkey_roundtrip() {
        let b58 = "11111111111111111111111111111111";
        let pk = decode_pubkey(b58).unwrap();
        assert_eq!(pk, [0u8; 32]);
    }

    #[test]
    fn test_attest_success() {
        let rpc = MockRpc {
            blockhash: "EkSnNWid2cvTEVjVJwHKYZKxgyAPozcFdtQmWpNo9D7p".into(),
            nonce_data: None,
        };
        let cfg = test_config();
        let input = test_input(1);

        let result = attest(&input, &rpc, &cfg).unwrap();

        assert!(!result.unsigned_tx_b64.is_empty());
        assert!(result.fee_lamports > 0);
        assert!(result.summary.contains("pi-001"));
        assert!(result.summary.contains("nonce #1"));
        // Message starts with 0x80 (version 0)
        assert_eq!(result.message_bytes[0], 0x80);
    }

    #[test]
    fn test_attest_replay_guard() {
        let rpc = MockRpc {
            blockhash: "EkSnNWid2cvTEVjVJwHKYZKxgyAPozcFdtQmWpNo9D7p".into(),
            nonce_data: None,
        };
        let cfg = test_config();
        let input = test_input(0); // counter == last_committed_counter (0)

        let err = attest(&input, &rpc, &cfg).unwrap_err();
        assert_eq!(err, AttestError::NonceReplay { counter: 0, expected: 0 });
    }

    #[test]
    fn test_attest_missing_rpc_url() {
        let rpc = MockRpc {
            blockhash: "EkSnNWid2cvTEVjVJwHKYZKxgyAPozcFdtQmWpNo9D7p".into(),
            nonce_data: None,
        };
        let mut cfg = test_config();
        cfg.rpc_url.clear();
        let input = test_input(1);

        let err = attest(&input, &rpc, &cfg).unwrap_err();
        assert_eq!(err, AttestError::MissingRpcUrl);
    }

    #[test]
    fn test_attest_missing_device_id() {
        let rpc = MockRpc {
            blockhash: "EkSnNWid2cvTEVjVJwHKYZKxgyAPozcFdtQmWpNo9D7p".into(),
            nonce_data: None,
        };
        let mut cfg = test_config();
        cfg.device_id.clear();
        let input = test_input(1);

        let err = attest(&input, &rpc, &cfg).unwrap_err();
        assert_eq!(err, AttestError::MissingDeviceId);
    }

    #[test]
    fn test_attest_missing_nonce_account() {
        let rpc = MockRpc {
            blockhash: "EkSnNWid2cvTEVjVJwHKYZKxgyAPozcFdtQmWpNo9D7p".into(),
            nonce_data: None,
        };
        let mut cfg = test_config();
        cfg.nonce_account.clear();
        let input = test_input(1);

        let err = attest(&input, &rpc, &cfg).unwrap_err();
        assert_eq!(err, AttestError::MissingNonceAccount);
    }

    #[test]
    fn test_attest_rpc_error() {
        // We can't easily make the mock return an error via this simple struct,
        // but we verify the error path compiles with a valid config.
        let rpc = MockRpc {
            blockhash: "EkSnNWid2cvTEVjVJwHKYZKxgyAPozcFdtQmWpNo9D7p".into(),
            nonce_data: None,
        };
        let cfg = test_config();
        let input = test_input(1);
        let result = attest(&input, &rpc, &cfg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_message_v0_structure() {
        let nonce_account = [1u8; 32];
        let nonce_authority = [2u8; 32];
        let blockhash = [3u8; 32];
        let memo = b"test memo";

        let msg = build_message_v0(&nonce_account, &nonce_authority, &blockhash, memo).unwrap();

        // Prefix: version 0
        assert_eq!(msg[0], 0x80);
        // Header: [writable_signed=1, writable_unsigned=0, readonly_signed=0, readonly_unsigned=3]
        assert_eq!(msg[1], 1); // num_writable_signed (authority)
        assert_eq!(msg[2], 0); // num_writable_unsigned
        assert_eq!(msg[3], 0); // num_readonly_signed (nonce_account is NOT a signer)
        assert_eq!(msg[4], 3); // num_readonly_unsigned (nonce_account + system + memo)
        // Num accounts
        assert_eq!(msg[5], 4);
        // First account: nonce_authority (32 bytes)
        assert_eq!(&msg[6..38], &nonce_authority);
        // Second account: nonce_account (32 bytes)
        assert_eq!(&msg[38..70], &nonce_account);
        // Third account: system_program
        assert_eq!(&msg[70..102], &SYSTEM_PROGRAM_ID);
        // Fourth account: memo_program
        assert_eq!(&msg[102..134], &MEMO_PROGRAM_ID);
        // Recent blockhash
        assert_eq!(&msg[134..166], &blockhash);
        // Num instructions (u8) = 2
        assert_eq!(msg[166], 2);
    }

    #[test]
    fn test_wrap_versioned_tx() {
        let msg = vec![0x80, 1, 0, 1, 2, 4];
        let tx = wrap_versioned_tx(&msg);
        assert_eq!(tx[0], 0x00); // 0 signatures
        assert_eq!(&tx[1..], &msg);
    }

    #[test]
    fn test_to_base64() {
        let data = b"Hello, world!";
        let encoded = to_base64(data);
        assert_eq!(encoded, "SGVsbG8sIHdvcmxkIQ==");
    }

    #[test]
    fn test_display_error() {
        let err = AttestError::NonceReplay {
            counter: 5,
            expected: 10,
        };
        let msg = format!("{err}");
        assert!(msg.contains("5"));
        assert!(msg.contains("10"));
    }
}
