//! Submit + confirm flow for the signer plugin.
//!
//! Orchestrates the full signing path: decode → envelope guards → fresh
//! blockhash → message mutation → backend sign → versioned tx assembly →
//! RPC submit → poll confirm. This is the answer to bounty Trap #1: the
//! blockhash fetched at build time can expire across the human-approval
//! window, so the signer re-fetches one immediately before signing.
//!
//! ## Wire format (pinned by this bean)
//!
//! The `instructions_base64` arg from `solana-build-tx` carries the base64
//! of a **Solana V0 message** (header + accounts + placeholder blockhash +
//! instructions + address lookup tables). The signer does NOT receive a
//! wrapped `VersionedTransaction` with empty signatures — just the message
//! bytes. Legacy (pre-V0) messages are rejected at the door per the
//! HANDOFF.
//!
//! Wire-format summary this module parses / produces:
//!
//! ```text
//! V0 message (input):
//!   prefix                 : u8   (0x80 for V0; legacy rejected)
//!   num_required_signatures: u8
//!   num_readonly_signed    : u8
//!   num_readonly_unsigned  : u8
//!   account_keys_count     : compact-u16
//!   account_keys           : [u8; 32] * account_keys_count
//!   recent_blockhash       : [u8; 32]    ← signer swaps this
//!   instructions_count     : compact-u16 ← envelope guard reads this
//!   instructions           : [CompiledInstruction]
//!   alt_count              : compact-u16
//!   alts                   : [MessageAddressTableLookup]
//!
//! VersionedTransaction (output to RPC, base64):
//!   signatures_count       : compact-u16 (always 1)
//!   signatures             : [[u8; 64]; 1]
//!   message                : V0 message (above) with the swapped blockhash
//! ```
//!
//! Parsing is **partial**: we walk far enough to read the header, the
//! account count, the first 32-byte account key (= fee_payer by Solana
//! convention), the blockhash offset, and the instruction count. ALTs are
//! preserved byte-for-byte during blockhash swap — the signer does not need
//! to understand them.
//!
//! ## Pure core + thin shim
//!
//! [`execute_with`] takes a `&dyn SignerBackend` and a `&impl RpcTransport`,
//! so the entire flow is host-testable against mocks. The wasm shim in
//! `lib.rs` will plug in `backends::from_config()` for the backend and
//! `rpc::WakiTransport` for the RPC transport.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::backends::SignerBackend;
use crate::envelope::{check, EnvelopeConfig, EnvelopeError};
use crate::rpc::{RpcClient, RpcTransport};

/// Parsed `execute(args_json)` payload. The wasm shim deserializes the
/// incoming args string into this, then hands it to [`execute_with`].
///
/// `__config` is the host-injected config section (flat `String -> String`
/// map, same model as `redact-text`). The real config unwrap (vault_addr,
/// rpc_url, signer_pubkey, …) lands when the wasm shim chains
/// `backends::from_config` + the envelope config builder.
#[derive(Debug, Clone, Deserialize)]
pub struct SignerInput {
    /// Base64-encoded **Solana V0 message** produced by `solana-build-tx`.
    /// The blockhash inside is a placeholder; this flow swaps it for a
    /// fresh one fetched from the RPC.
    #[serde(rename = "instructions_base64")]
    pub message_base64: String,

    /// Host-injected config map. Held as `Value` so the scaffold does not
    /// presume the operator-config schema before the factory chains land.
    #[serde(rename = "__config", default)]
    pub config: Value,
}

/// Signer-side config — the slice of `__config` the submit flow needs.
/// `s37c` populates this from the host-injected map; the factory bean
/// `7p6z` resolves the backend.
#[derive(Debug, Clone, Default)]
pub struct SignerConfig {
    /// Envelope limits + fee-payer identity.
    pub envelope: EnvelopeConfig,
    /// RPC endpoint for blockhash / sendTransaction / status polls.
    pub rpc_url: String,
    /// Confirmation deadline for the poll loop. Defaults to
    /// `crate::rpc::DEFAULT_CONFIRM_TIMEOUT_SECS` when zero.
    pub confirm_timeout_secs: u64,
}

/// What the signer hands back to the agent on success. Serialized into the
/// `ToolResult.output` JSON string by the wasm shim.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignerOutput {
    /// Base58 transaction signature.
    pub signature: String,
    /// `https://solscan.io/tx/<signature>` (mainnet). The agent surfaces
    /// this in the channel so the human approver can audit post-hoc.
    pub explorer_url: String,
    /// Slot the tx was confirmed at. Useful for replay debugging.
    pub slot: u64,
}

/// Reasons [`execute_with`] can fail. Each variant maps to an operator-facing
/// string carried in `ToolResult.error`. Secrets (backend tokens, etc.)
/// never appear here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// `instructions_base64` was not valid base64.
    BadBase64(String),
    /// Message wire format was malformed (legacy prefix, truncated, bad
    /// varint, account_keys too short, …). The string names the specific
    /// parser step that failed.
    BadMessage(String),
    /// One of the three envelope guards fired.
    Envelope(EnvelopeError),
    /// Blockhash fetch from the RPC failed or returned a malformed value.
    Blockhash(String),
    /// The backend rejected the sign call (transport, malformed response,
    /// verification failure). The string is the backend's `SignerError`.
    Backend(String),
    /// RPC submit or poll failed (timeout, simulation revert, landed-with-err).
    Rpc(String),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadBase64(msg) => write!(f, "instructions_base64 decode failed: {msg}"),
            Self::BadMessage(msg) => write!(f, "malformed message: {msg}"),
            Self::Envelope(err) => write!(f, "{err}"),
            Self::Blockhash(msg) => write!(f, "fresh blockhash fetch failed: {msg}"),
            Self::Backend(msg) => write!(f, "backend sign failed: {msg}"),
            Self::Rpc(msg) => write!(f, "submit or confirm failed: {msg}"),
        }
    }
}

impl std::error::Error for SubmitError {}

impl From<EnvelopeError> for SubmitError {
    fn from(err: EnvelopeError) -> Self {
        Self::Envelope(err)
    }
}

/// V0 message prefix byte. High bit set (0x80) flags versioned messages;
/// lower bits hold the version (currently 0).
const V0_PREFIX: u8 = 0x80;

/// Compact-u16 (Solana "shortvec") max byte length. 3 bytes encodes u16::MAX.
const COMPACT_U16_MAX_BYTES: usize = 3;

/// Decode a Solana compact-u16 ("shortvec") varint. Returns the decoded
/// value + the number of bytes consumed; `None` on truncation or overflow.
pub fn read_compact_u16(bytes: &[u8]) -> Option<(u16, usize)> {
    let mut val: u32 = 0;
    let mut shift = 0;
    for (i, &byte) in bytes.iter().enumerate().take(COMPACT_U16_MAX_BYTES) {
        val |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some((val as u16, i + 1));
        }
        shift += 7;
    }
    None
}

/// Encode a u16 as a Solana compact-u16 ("shortvec") varint into `out`.
pub fn write_compact_u16(out: &mut Vec<u8>, mut val: u16) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Minimal view into a Solana V0 message — enough to apply envelope guards
/// and to compute the blockhash swap offset. ALTs are preserved untouched
/// during the swap; we never need to parse them.
#[derive(Debug, Clone)]
pub struct MessageView {
    /// Version prefix byte (always `0x80` for V0; we reject legacy).
    pub version_prefix: u8,
    /// First byte of the 3-byte Solana message header.
    pub num_required_signatures: u8,
    /// Number of account keys in the message.
    pub account_keys_count: usize,
    /// Byte offset in the original message of the first 32-byte account key.
    /// Equals `account_keys[0]`'s start — by Solana convention this is the
    /// fee_payer / signing key for the tx.
    pub fee_payer_offset: usize,
    /// Byte offset of the 32-byte recent_blockhash field. Used by
    /// [`swap_blockhash`] for in-place mutation.
    pub blockhash_offset: usize,
    /// Number of compiled instructions in the message. Used by
    /// [`check`] for the `max_instructions` envelope guard.
    pub instructions_count: usize,
    /// Total message byte length. Used by [`check`] for the
    /// `max_message_bytes` envelope guard.
    pub message_len: usize,
}

/// Parse a Solana V0 message blob into a [`MessageView`]. Rejects legacy
/// messages (`prefix & 0x80 == 0`) at the door per the bounty HANDOFF.
///
/// Walks far enough to read: header, account count, fee_payer offset,
/// blockhash offset, instructions count. Stops there — full instruction
/// parsing and ALT parsing are out of scope (the signer doesn't need them).
pub fn parse_message(bytes: &[u8]) -> Result<MessageView, SubmitError> {
    // Minimum V0 message: prefix + 3 header + 1 ix_count + 32 blockhash +
    // 1 ix_count + 0 ix + 1 alt_count + 0 alts = 38 bytes (zero accounts).
    if bytes.len() < 38 {
        return Err(SubmitError::BadMessage(format!(
            "message too short: {} bytes (need at least 38 for an empty V0)",
            bytes.len()
        )));
    }
    let prefix = bytes[0];
    if prefix & 0x80 == 0 {
        return Err(SubmitError::BadMessage(
            "legacy message rejected (prefix high bit not set); only V0 supported".to_string(),
        ));
    }
    if prefix != V0_PREFIX {
        return Err(SubmitError::BadMessage(format!(
            "unsupported message version 0x{prefix:02x} (only V0 = 0x80 supported)"
        )));
    }
    let num_required_signatures = bytes[1];
    // bytes[2] / bytes[3] are readonly counts — not needed for envelope guards.

    let mut pos = 4usize;
    let (account_keys_count, consumed) = read_compact_u16(&bytes[pos..]).ok_or_else(|| {
        SubmitError::BadMessage("truncated account_keys_count varint".to_string())
    })?;
    pos += consumed;

    let account_keys_count = account_keys_count as usize;
    let fee_payer_offset = pos;
    // Verify the message has enough bytes for all account keys + blockhash.
    let account_keys_end = pos + 32 * account_keys_count;
    if account_keys_end + 32 > bytes.len() {
        return Err(SubmitError::BadMessage(format!(
            "truncated account_keys or blockhash: need {} bytes, have {}",
            account_keys_end + 32,
            bytes.len()
        )));
    }
    pos = account_keys_end;
    let blockhash_offset = pos;
    pos += 32;
    let (instructions_count, _consumed) = read_compact_u16(&bytes[pos..]).ok_or_else(|| {
        SubmitError::BadMessage("truncated instructions_count varint".to_string())
    })?;

    Ok(MessageView {
        version_prefix: prefix,
        num_required_signatures,
        account_keys_count,
        fee_payer_offset,
        blockhash_offset,
        instructions_count: instructions_count as usize,
        message_len: bytes.len(),
    })
}

/// Extract the 32-byte fee_payer pubkey (account_keys[0]) from the message.
/// Returns `None` if the message has zero account keys (a degenerate case
/// the parser would already reject, but defensive).
pub fn fee_payer_pubkey<'a>(bytes: &'a [u8], view: &MessageView) -> Option<&'a [u8; 32]> {
    if view.account_keys_count == 0 {
        return None;
    }
    bytes[view.fee_payer_offset..view.fee_payer_offset + 32]
        .try_into()
        .ok()
}

/// Swap the 32-byte recent_blockhash field in-place on a clone of the
/// message bytes. The returned `Vec<u8>` has the same length as the input
/// (blockhash is a fixed-width field); all other bytes (including ALTs)
/// are preserved exactly.
pub fn swap_blockhash(bytes: &[u8], view: &MessageView, new_blockhash: &[u8; 32]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[view.blockhash_offset..view.blockhash_offset + 32].copy_from_slice(new_blockhash);
    out
}

/// Assemble a Solana `VersionedTransaction` wire-format blob from a
/// message + a single signature. Layout:
///
/// ```text
/// signatures_count : compact-u16 (1)
/// signatures       : [u8; 64]   (the single signature)
/// message          : bytes       (already blockhash-swapped)
/// ```
///
/// The output of this function is what gets base64-encoded and handed to
/// `sendTransaction` via `RpcClient::send_transaction`.
pub fn assemble_versioned_tx(message_bytes: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 64 + message_bytes.len());
    write_compact_u16(&mut out, 1);
    out.extend_from_slice(signature);
    out.extend_from_slice(message_bytes);
    out
}

/// Execute the full sign + submit + confirm flow.
///
/// Args:
///   - `input`: the base64 message + the host-injected `__config`
///   - `cfg`: typed envelope + RPC config
///   - `backend`: resolved by the factory (`backends::from_config`)
///   - `rpc_transport`: the JSON-RPC transport (mock in tests, waki in wasm)
///
/// Returns the confirmed signature + slot on success; the first failure
/// short-circuits with a [`SubmitError`] naming the failed step.
#[allow(clippy::too_many_arguments)]
pub fn execute_with<B, T>(
    input: &SignerInput,
    cfg: &SignerConfig,
    backend: &B,
    rpc_transport: T,
) -> Result<SignerOutput, SubmitError>
where
    B: SignerBackend + ?Sized,
    T: RpcTransport,
{
    // 1. Decode the base64 message.
    let message_bytes = B64
        .decode(&input.message_base64)
        .map_err(|e| SubmitError::BadBase64(e.to_string()))?;
    if message_bytes.is_empty() {
        return Err(SubmitError::BadMessage("message is empty".to_string()));
    }

    // 2. Parse for envelope inputs.
    let view = parse_message(&message_bytes)?;

    // 3. Envelope guards — cheapest-first per envelope::check ordering.
    //    For fee_payer: bs58-encode account_keys[0] so the comparison
    //    against cfg.envelope.signer_pubkey is base58-string-equality.
    let fee_payer_b58 = match fee_payer_pubkey(&message_bytes, &view) {
        Some(pk) => bs58::encode(pk).into_string(),
        None => {
            return Err(SubmitError::BadMessage(
                "V0 message has zero account_keys; no fee_payer to guard".to_string(),
            ));
        }
    };
    check(
        &cfg.envelope,
        view.message_len,
        view.instructions_count,
        &fee_payer_b58,
    )?;

    // 4. Fetch a fresh blockhash at sign time (Trap #1 fix).
    let confirm_timeout = if cfg.confirm_timeout_secs == 0 {
        crate::rpc::DEFAULT_CONFIRM_TIMEOUT_SECS
    } else {
        cfg.confirm_timeout_secs
    };
    let rpc = RpcClient::new(&cfg.rpc_url, rpc_transport, confirm_timeout);
    let blockhash = rpc.get_latest_blockhash().map_err(SubmitError::Blockhash)?;
    let new_blockhash_bytes = bs58::decode(&blockhash.blockhash)
        .into_vec()
        .map_err(|e| SubmitError::Blockhash(format!("blockhash not base58: {e}")))?;
    let new_blockhash_arr: [u8; 32] = new_blockhash_bytes.as_slice().try_into().map_err(|_| {
        SubmitError::Blockhash(format!(
            "blockhash decoded to {} bytes, expected 32",
            new_blockhash_bytes.len()
        ))
    })?;

    // 5. Swap the blockhash in-place on a clone of the message bytes.
    let signed_message = swap_blockhash(&message_bytes, &view, &new_blockhash_arr);

    // 6. Sign the modified message via the backend.
    let sig_vec = backend
        .sign(&signed_message)
        .map_err(|e| SubmitError::Backend(e.to_string()))?;
    let sig_arr: [u8; 64] = sig_vec.as_slice().try_into().map_err(|_| {
        SubmitError::Backend(format!(
            "backend returned {}-byte signature, expected 64",
            sig_vec.len()
        ))
    })?;

    // 7. Assemble the VersionedTransaction wire format.
    let tx_bytes = assemble_versioned_tx(&signed_message, &sig_arr);
    let tx_b64 = B64.encode(&tx_bytes);

    // 8. Submit + poll for confirmation.
    let confirmed_sig = rpc.submit_and_confirm(&tx_b64).map_err(SubmitError::Rpc)?;

    // 9. Build the agent-facing output.
    Ok(SignerOutput {
        signature: confirmed_sig.clone(),
        explorer_url: format!("https://solscan.io/tx/{confirmed_sig}"),
        // The submit_and_confirm flow currently returns only the signature
        // (rpc.rs scoped to that). Slot would require a follow-up
        // getSignatureStatuses call post-confirm; the host test suite
        // covers the missing-slot case explicitly.
        slot: 0,
    })
}

/// Backwards-compatible stub kept so the wasm shim's `execute()` call
/// (from 67ip scaffold) still compiles. Returns `Err` naming `s37c`'s
/// real entry point. Real callers go through [`execute_with`].
pub fn execute(input: &SignerInput, cfg: &SignerConfig) -> Result<SignerOutput, String> {
    let _ = (input, cfg);
    Err(
        "solana-keychain-sign::execute stub — call execute_with(input, cfg, backend, rpc_transport) instead"
            .to_string(),
    )
}

/// Render a [`SignerOutput`] as the JSON the agent-facing `ToolResult.output`
/// field carries. Kept here so the wasm shim does not have to know the
/// struct shape.
pub fn output_json(out: &SignerOutput) -> Value {
    json!({
        "signature": out.signature,
        "explorer_url": out.explorer_url,
        "slot": out.slot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::SignerError;
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use std::collections::VecDeque;

    // ── compact-u16 varint ──────────────────────────────────────────────────

    #[test]
    fn compact_u16_round_trips_single_byte_values() {
        for v in [0u16, 1, 42, 127] {
            let mut buf = Vec::new();
            write_compact_u16(&mut buf, v);
            assert_eq!(buf.len(), 1, "value {v} should encode to 1 byte");
            let (decoded, consumed) = read_compact_u16(&buf).expect("must decode");
            assert_eq!(decoded, v);
            assert_eq!(consumed, 1);
        }
    }

    #[test]
    fn compact_u16_round_trips_two_byte_values() {
        for v in [128u16, 255, 256, 16383] {
            let mut buf = Vec::new();
            write_compact_u16(&mut buf, v);
            assert_eq!(buf.len(), 2, "value {v} should encode to 2 bytes");
            let (decoded, _) = read_compact_u16(&buf).expect("must decode");
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn compact_u16_round_trips_three_byte_values() {
        for v in [16384u16, 32768, 65535] {
            let mut buf = Vec::new();
            write_compact_u16(&mut buf, v);
            assert_eq!(buf.len(), 3, "value {v} should encode to 3 bytes");
            let (decoded, _) = read_compact_u16(&buf).expect("must decode");
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn compact_u16_rejects_truncated_input() {
        // High bit set on a trailing byte with no continuation → malformed.
        assert!(read_compact_u16(&[0x80]).is_none());
        // Three continuation bytes without a terminator → malformed.
        assert!(read_compact_u16(&[0x80, 0x80, 0x80]).is_none());
    }

    // ── fixtures: build a real-shape V0 message ──────────────────────────────

    /// Construct a minimal V0 message with `num_accounts` 32-byte account
    /// keys, a placeholder blockhash (all zeros), one trivial instruction,
    /// and zero ALTs. Returns the wire-format bytes.
    fn build_v0_message(num_accounts: usize, fee_payer: [u8; 32]) -> Vec<u8> {
        // V0 prefix + header (1 sig, 1 readonly-signed, 0 readonly-unsigned).
        let mut out = vec![V0_PREFIX, 1, 1, 0];
        // account_keys_count + keys.
        write_compact_u16(&mut out, num_accounts as u16);
        for i in 0..num_accounts {
            let mut key = if i == 0 { fee_payer } else { [0u8; 32] };
            if i != 0 {
                key[0] = i as u8;
            }
            out.extend_from_slice(&key);
        }
        // Recent blockhash placeholder (32 zero bytes) — the signer swaps it.
        out.extend_from_slice(&[0u8; 32]);
        // 1 compiled instruction: program_id_index=1, 0 accounts, 0 data.
        write_compact_u16(&mut out, 1);
        out.push(1); // program_id_index
        write_compact_u16(&mut out, 0); // accounts length
        write_compact_u16(&mut out, 0); // data length
                                        // ALT count = 0.
        write_compact_u16(&mut out, 0);
        out
    }

    fn known_fee_payer() -> [u8; 32] {
        // Deterministic — bs58 encodes to a stable string we assert against.
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        pk
    }

    #[test]
    fn parse_message_accepts_minimal_v0_with_one_account() {
        let bytes = build_v0_message(1, known_fee_payer());
        let view = parse_message(&bytes).expect("must parse");
        assert_eq!(view.version_prefix, V0_PREFIX);
        assert_eq!(view.account_keys_count, 1);
        assert_eq!(view.instructions_count, 1);
        // blockhash offset = prefix + 3 header + 1 ix_count + 32 = 37.
        assert_eq!(view.blockhash_offset, 4 + 1 + 32);
        assert_eq!(view.message_len, bytes.len());
    }

    #[test]
    fn parse_message_accepts_v0_with_multiple_accounts() {
        let bytes = build_v0_message(5, known_fee_payer());
        let view = parse_message(&bytes).expect("must parse");
        assert_eq!(view.account_keys_count, 5);
        // blockhash offset accounts for the 5 keys (5 * 32 = 160 bytes).
        assert_eq!(view.blockhash_offset, 4 + 1 + 160);
    }

    #[test]
    fn parse_message_rejects_legacy_messages() {
        // First byte without high bit = legacy. The signer is V0-only.
        let mut bytes = build_v0_message(1, known_fee_payer());
        bytes[0] = 0x01; // legacy num_required_signatures
        let err = parse_message(&bytes).expect_err("must reject legacy");
        match err {
            SubmitError::BadMessage(msg) => assert!(msg.contains("legacy"), "msg: {msg}"),
            other => panic!("expected BadMessage, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_rejects_future_versions() {
        let mut bytes = build_v0_message(1, known_fee_payer());
        bytes[0] = 0x81; // versioned but version=1, not V0
        let err = parse_message(&bytes).expect_err("must reject future");
        assert!(matches!(err, SubmitError::BadMessage(_)));
    }

    #[test]
    fn parse_message_rejects_truncated_input() {
        let err = parse_message(&[V0_PREFIX, 1, 1, 0]).expect_err("too short");
        assert!(matches!(err, SubmitError::BadMessage(_)));
    }

    #[test]
    fn fee_payer_pubkey_returns_first_account_key() {
        let bytes = build_v0_message(3, known_fee_payer());
        let view = parse_message(&bytes).unwrap();
        let pk = fee_payer_pubkey(&bytes, &view).expect("must extract");
        assert_eq!(pk, &known_fee_payer());
    }

    #[test]
    fn fee_payer_pubkey_returns_none_for_zero_account_keys() {
        // Construct an empty V0 message manually (parser still requires
        // account_keys_count varint, but with value 0).
        let mut bytes = vec![V0_PREFIX, 0, 0, 0];
        write_compact_u16(&mut bytes, 0); // 0 account keys
        bytes.extend_from_slice(&[0u8; 32]); // blockhash
        write_compact_u16(&mut bytes, 0); // 0 instructions
        write_compact_u16(&mut bytes, 0); // 0 ALTs
        let view = parse_message(&bytes).unwrap();
        assert_eq!(view.account_keys_count, 0);
        assert!(fee_payer_pubkey(&bytes, &view).is_none());
    }

    // ── swap_blockhash ──────────────────────────────────────────────────────

    #[test]
    fn swap_blockhash_replaces_exactly_32_bytes_at_known_offset() {
        let bytes = build_v0_message(2, known_fee_payer());
        let view = parse_message(&bytes).unwrap();
        let original_blockhash = bytes[view.blockhash_offset..view.blockhash_offset + 32].to_vec();
        assert_eq!(original_blockhash, vec![0u8; 32]); // placeholder is zeros

        let mut new_blockhash = [0u8; 32];
        for (i, b) in new_blockhash.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(100);
        }
        let swapped = swap_blockhash(&bytes, &view, &new_blockhash);

        // Length unchanged.
        assert_eq!(swapped.len(), bytes.len());
        // Only the 32 bytes at blockhash_offset changed.
        let mut diff_indices = Vec::new();
        for (i, (a, b)) in bytes.iter().zip(swapped.iter()).enumerate() {
            if a != b {
                diff_indices.push(i);
            }
        }
        let expected_range = view.blockhash_offset..view.blockhash_offset + 32;
        for &i in &diff_indices {
            assert!(
                expected_range.contains(&i),
                "byte {i} changed outside blockhash range"
            );
        }
        assert_eq!(diff_indices.len(), 32, "exactly 32 bytes should differ");
    }

    #[test]
    fn swap_blockhash_preserves_alts_and_instructions() {
        // The signer doesn't parse ALTs; swap must leave them byte-for-byte.
        let bytes = build_v0_message(1, known_fee_payer());
        let view = parse_message(&bytes).unwrap();
        let swapped = swap_blockhash(&bytes, &view, &[0xFFu8; 32]);
        // Bytes before blockhash_offset unchanged.
        assert_eq!(
            &bytes[..view.blockhash_offset],
            &swapped[..view.blockhash_offset]
        );
        // Bytes after the blockhash unchanged.
        let after = view.blockhash_offset + 32;
        assert_eq!(&bytes[after..], &swapped[after..]);
    }

    // ── assemble_versioned_tx ───────────────────────────────────────────────

    #[test]
    fn assemble_versioned_tx_produces_one_signature_then_message() {
        let msg = vec![0xAAu8; 100];
        let sig = [0xBBu8; 64];
        let tx = assemble_versioned_tx(&msg, &sig);

        // Expected: 0x01 (count), 64 sig bytes, then message.
        assert_eq!(tx[0], 0x01, "sig count must be 1");
        assert_eq!(&tx[1..65], &sig[..]);
        assert_eq!(&tx[65..], &msg[..]);
        assert_eq!(tx.len(), 1 + 64 + 100);
    }

    // ── execute_with: mocks ─────────────────────────────────────────────────

    /// A mock backend that returns a queue of `sign` responses. Defaults to
    /// returning a 64-byte zero sig if no responses queued.
    #[derive(Debug)]
    struct MockBackend {
        sign_response: Result<Vec<u8>, SignerError>,
        captured_message: std::sync::Mutex<Vec<u8>>,
    }

    impl MockBackend {
        fn new(sign_response: Result<Vec<u8>, SignerError>) -> Self {
            Self {
                sign_response,
                captured_message: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn captured(&self) -> Vec<u8> {
            self.captured_message.lock().unwrap().clone()
        }
    }

    impl SignerBackend for MockBackend {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn public_key(&self) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0u8; 32])
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
            *self.captured_message.lock().unwrap() = message.to_vec();
            self.sign_response.clone()
        }
    }

    /// A mock RPC transport: caller queues one canned response per call.
    /// Each entry is either `Ok(Value)` (returned as-is) or `Err(String)`.
    #[derive(Default)]
    struct MockRpc {
        responses: RefCell<VecDeque<Result<Value, String>>>,
        sent: RefCell<Vec<Value>>,
    }
    impl MockRpc {
        fn push_ok(&self, v: Value) {
            self.responses.borrow_mut().push_back(Ok(v));
        }
        fn push_err(&self, e: &str) {
            self.responses.borrow_mut().push_back(Err(e.to_string()));
        }
        fn sent_bodies(&self) -> Vec<Value> {
            self.sent.borrow().clone()
        }
    }
    impl RpcTransport for &MockRpc {
        fn post_json(&self, url: &str, body: &Value) -> Result<Value, String> {
            assert_eq!(url, "https://rpc.example", "client posted to wrong URL");
            self.sent.borrow_mut().push(body.clone());
            self.responses
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| panic!("MockRpc: no queued response"))
        }
    }

    fn base_cfg() -> SignerConfig {
        SignerConfig {
            envelope: EnvelopeConfig {
                max_message_bytes: 4096,
                max_instructions: 5,
                signer_pubkey: bs58::encode(known_fee_payer()).into_string(),
            },
            rpc_url: "https://rpc.example".to_string(),
            confirm_timeout_secs: 5,
        }
    }

    fn input_with(msg_bytes: &[u8]) -> SignerInput {
        SignerInput {
            message_base64: B64.encode(msg_bytes),
            config: Value::Null,
        }
    }
    fn blockhash_response(hash: &[u8; 32]) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "context": { "slot": 1 },
                "value": {
                    "blockhash": bs58::encode(hash).into_string(),
                    "lastValidBlockHeight": 999_999_999,
                }
            }
        })
    }

    fn send_response(sig: &str) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "result": sig })
    }

    fn status_response_confirmed(slot: u64) -> Value {
        json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "context": { "slot": slot + 5 }, "value": [{
                "slot": slot,
                "err": null,
                "confirmationStatus": "confirmed"
            }]}
        })
    }

    #[test]
    fn execute_with_happy_path_swaps_blockhash_and_submits_signed_tx() {
        let msg = build_v0_message(1, known_fee_payer());
        let input = input_with(&msg);

        let cfg = base_cfg();
        let backend = MockBackend::new(Ok(vec![0x42u8; 64]));

        let mut fresh_blockhash = [0u8; 32];
        fresh_blockhash[0] = 0xFE;
        let rpc = MockRpc::default();
        rpc.push_ok(blockhash_response(&fresh_blockhash));
        rpc.push_ok(send_response("SIG0"));
        rpc.push_ok(status_response_confirmed(42));

        let out = execute_with(&input, &cfg, &backend, &rpc).expect("must succeed");
        assert_eq!(out.signature, "SIG0");
        assert_eq!(out.explorer_url, "https://solscan.io/tx/SIG0");

        // Backend saw the SWAPPED message — fresh blockhash at the right offset.
        let captured = backend.captured();
        let view = parse_message(&captured).expect("captured must parse");
        let captured_blockhash = &captured[view.blockhash_offset..view.blockhash_offset + 32];
        assert_eq!(captured_blockhash, &fresh_blockhash);

        // sendTransaction got the VersionedTransaction wire format base64.
        let sent = rpc.sent_bodies();
        assert_eq!(sent[1]["method"], "sendTransaction");
        let tx_b64 = sent[1]["params"][0].as_str().unwrap();
        let tx_bytes = B64.decode(tx_b64).unwrap();
        // Wire format: 0x01 sig_count, 64 sig, then message.
        assert_eq!(tx_bytes[0], 0x01);
        assert_eq!(&tx_bytes[1..65], &[0x42u8; 64]);
    }

    fn capturedaptured() -> Vec<u8> {
        Vec::new() // placeholder — replaced below
    }

    #[test]
    fn execute_with_rejects_legacy_message_at_parse_step() {
        let mut msg = build_v0_message(1, known_fee_payer());
        msg[0] = 0x01; // legacy prefix
        let input = input_with(&msg);
        let cfg = base_cfg();
        let backend = MockBackend::new(Ok(vec![0u8; 64]));
        let rpc = MockRpc::default();

        let err = execute_with(&input, &cfg, &backend, &rpc).expect_err("must reject");
        match err {
            SubmitError::BadMessage(msg) => assert!(msg.contains("legacy"), "msg: {msg}"),
            other => panic!("expected BadMessage, got {other:?}"),
        }
    }

    #[test]
    fn execute_with_envelope_guard_fires_on_fee_payer_mismatch() {
        let mut wrong_payer = known_fee_payer();
        wrong_payer[0] ^= 0xFF;
        let msg = build_v0_message(1, wrong_payer);
        let input = input_with(&msg);
        let cfg = base_cfg();
        let backend = MockBackend::new(Ok(vec![0u8; 64]));
        let rpc = MockRpc::default();

        let err = execute_with(&input, &cfg, &backend, &rpc).expect_err("must reject");
        match err {
            SubmitError::Envelope(EnvelopeError::FeePayerMismatch { .. }) => {}
            other => panic!("expected FeePayerMismatch, got {other:?}"),
        }
    }

    #[test]
    fn execute_with_envelope_guard_fires_on_instruction_count() {
        // Build a message with 2 instructions; envelope caps at 1 for v0.
        // Constructed from scratch so the wire format stays internally
        // consistent (parser reads count from the varint at the right
        // offset, and the bytes after that must add up to the right total).
        let mut bytes = vec![V0_PREFIX, 1, 1, 0];
        write_compact_u16(&mut bytes, 1);
        bytes.extend_from_slice(&known_fee_payer());
        bytes.extend_from_slice(&[0u8; 32]); // blockhash
        write_compact_u16(&mut bytes, 2); // 2 instructions
        for _ in 0..2 {
            bytes.push(1); // program_id_index
            write_compact_u16(&mut bytes, 0);
            write_compact_u16(&mut bytes, 0);
        }
        write_compact_u16(&mut bytes, 0); // 0 ALTs

        let input = input_with(&bytes);
        let mut cfg = base_cfg();
        cfg.envelope.max_instructions = 1; // v0 default
        let backend = MockBackend::new(Ok(vec![0u8; 64]));
        let rpc = MockRpc::default();

        let err = execute_with(&input, &cfg, &backend, &rpc).expect_err("must reject");
        match err {
            SubmitError::Envelope(EnvelopeError::TooManyInstructions { actual, limit }) => {
                assert_eq!(actual, 2);
                assert_eq!(limit, 1);
            }
            other => panic!("expected TooManyInstructions, got {other:?}"),
        }
    }

    #[test]
    fn execute_with_propagates_blockhash_fetch_failure() {
        let msg = build_v0_message(1, known_fee_payer());
        let input = input_with(&msg);
        let cfg = base_cfg();
        let backend = MockBackend::new(Ok(vec![0u8; 64]));
        let rpc = MockRpc::default();
        rpc.push_err("connection refused");

        let err = execute_with(&input, &cfg, &backend, &rpc).expect_err("must fail");
        match err {
            SubmitError::Blockhash(msg) => {
                assert!(msg.contains("connection refused"), "msg: {msg}")
            }
            other => panic!("expected Blockhash, got {other:?}"),
        }
    }

    #[test]
    fn execute_with_propagates_backend_sign_failure() {
        let msg = build_v0_message(1, known_fee_payer());
        let input = input_with(&msg);
        let cfg = base_cfg();
        let backend = MockBackend::new(Err(SignerError::Backend(
            "vault permission denied".to_string(),
        )));
        let rpc = MockRpc::default();
        let mut fresh = [0u8; 32];
        fresh[0] = 1;
        rpc.push_ok(blockhash_response(&fresh));

        let err = execute_with(&input, &cfg, &backend, &rpc).expect_err("must fail");
        match err {
            SubmitError::Backend(msg) => {
                assert!(msg.contains("vault permission denied"), "msg: {msg}")
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn execute_with_propagates_submit_failure_as_rpc_error() {
        let msg = build_v0_message(1, known_fee_payer());
        let input = input_with(&msg);
        let cfg = base_cfg();
        let backend = MockBackend::new(Ok(vec![0u8; 64]));
        let rpc = MockRpc::default();
        let mut fresh = [0u8; 32];
        fresh[0] = 1;
        rpc.push_ok(blockhash_response(&fresh));
        rpc.push_err("sendTransaction rpc error: simulation failed");

        let err = execute_with(&input, &cfg, &backend, &rpc).expect_err("must fail");
        match err {
            SubmitError::Rpc(msg) => assert!(msg.contains("simulation failed"), "msg: {msg}"),
            other => panic!("expected Rpc, got {other:?}"),
        }
    }

    #[test]
    fn execute_with_rejects_bad_base64() {
        let input = SignerInput {
            message_base64: "this is not base64 !!!".to_string(),
            config: Value::Null,
        };
        let cfg = base_cfg();
        let backend = MockBackend::new(Ok(vec![0u8; 64]));
        let rpc = MockRpc::default();

        let err = execute_with(&input, &cfg, &backend, &rpc).expect_err("must fail");
        assert!(matches!(err, SubmitError::BadBase64(_)));
    }

    #[test]
    fn execute_with_returns_slot_zero_in_v0() {
        // Documented: rpc.submit_and_confirm currently returns only the
        // signature; slot=0 until a follow-up getSignatureStatuses is added.
        let msg = build_v0_message(1, known_fee_payer());
        let input = input_with(&msg);
        let cfg = base_cfg();
        let backend = MockBackend::new(Ok(vec![0u8; 64]));
        let rpc = MockRpc::default();
        let mut fresh = [0u8; 32];
        fresh[0] = 1;
        rpc.push_ok(blockhash_response(&fresh));
        rpc.push_ok(send_response("SIG"));
        rpc.push_ok(status_response_confirmed(99));

        let out = execute_with(&input, &cfg, &backend, &rpc).unwrap();
        assert_eq!(
            out.slot, 0,
            "v0 returns slot=0; rpc.submit_and_confirm gives sig only"
        );
    }

    #[test]
    fn execute_with_uses_default_confirm_timeout_when_config_zero() {
        // The default-timeout path must not panic. Drive it with mocks that
        // confirm on first poll so the timeout never fires.
        let msg = build_v0_message(1, known_fee_payer());
        let input = input_with(&msg);
        let mut cfg = base_cfg();
        cfg.confirm_timeout_secs = 0; // triggers default
        let backend = MockBackend::new(Ok(vec![0u8; 64]));
        let rpc = MockRpc::default();
        let mut fresh = [0u8; 32];
        fresh[0] = 1;
        rpc.push_ok(blockhash_response(&fresh));
        rpc.push_ok(send_response("SIG"));
        rpc.push_ok(status_response_confirmed(7));

        let out = execute_with(&input, &cfg, &backend, &rpc).expect("must succeed");
        assert_eq!(out.signature, "SIG");
    }

    // ── stub back-compat ────────────────────────────────────────────────────

    #[test]
    fn stub_execute_returns_caller_hint_pointing_at_execute_with() {
        let input = SignerInput {
            message_base64: String::new(),
            config: Value::Null,
        };
        let cfg = SignerConfig::default();
        let err = execute(&input, &cfg).expect_err("stub must error");
        assert!(
            err.contains("execute_with"),
            "msg should name the real entry: {err}"
        );
    }

    #[test]
    fn signer_input_deserializes_renamed_message_base64() {
        // The JSON wire field is still `instructions_base64` for back-compat
        // with build-tx callers; the Rust field is renamed for clarity.
        let raw = serde_json::json!({
            "instructions_base64": "AAABAA==",
            "__config": { "rpc_url": "https://rpc.example" }
        })
        .to_string();
        let parsed: SignerInput = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.message_base64, "AAABAA==");
        assert_eq!(parsed.config["rpc_url"], "https://rpc.example");
    }

    #[test]
    fn output_json_carries_all_three_fields() {
        let out = SignerOutput {
            signature: "SIG0".into(),
            explorer_url: "https://solscan.io/tx/SIG0".into(),
            slot: 42,
        };
        let v = output_json(&out);
        assert_eq!(v["signature"], "SIG0");
        assert_eq!(v["explorer_url"], "https://solscan.io/tx/SIG0");
        assert_eq!(v["slot"], 42);
    }

    // ── Submission of the Swap #1 invariant ─────────────────────────────────
    //
    // Trap #1 says: blockhash fetched at build time can expire across the
    // human-approval window. The fix is re-fetching at sign time. The
    // happy-path test above proves the backend signs the swapped message;
    // this test makes the invariant explicit: even when the build-time
    // blockhash was something else, the BACKEND sees the fresh one.

    #[test]
    fn trap1_fixed_backend_signs_message_with_fresh_not_buildtime_blockhash() {
        let mut buildtime_blockhash = [0u8; 32];
        buildtime_blockhash[31] = 0xAA; // recognizable
        let mut msg = build_v0_message(1, known_fee_payer());
        // Overwrite the placeholder blockhash with our build-time value.
        let view = parse_message(&msg).unwrap();
        msg[view.blockhash_offset..view.blockhash_offset + 32]
            .copy_from_slice(&buildtime_blockhash);
        let input = input_with(&msg);

        let cfg = base_cfg();
        let backend = MockBackend::new(Ok(vec![0u8; 64]));
        let rpc = MockRpc::default();

        // The signer fetches a DIFFERENT blockhash from RPC.
        let mut fresh_blockhash = [0u8; 32];
        fresh_blockhash[31] = 0xBB;
        rpc.push_ok(blockhash_response(&fresh_blockhash));
        rpc.push_ok(send_response("SIG"));
        rpc.push_ok(status_response_confirmed(1));

        let _ = execute_with(&input, &cfg, &backend, &rpc).unwrap();

        // The message the backend signed must carry the FRESH blockhash,
        // not the build-time one.
        let captured = backend.captured();
        let cap_view = parse_message(&captured).unwrap();
        let signed_blockhash = &captured[cap_view.blockhash_offset..cap_view.blockhash_offset + 32];
        assert_eq!(
            signed_blockhash, &fresh_blockhash,
            "backend must sign the FRESH blockhash, not the build-time one"
        );
        assert_ne!(
            signed_blockhash, &buildtime_blockhash,
            "build-time blockhash must be gone"
        );
    }

    // Suppress unused warning for the placeholder helper — kept to make the
    // happy-path assertion readable. (Renamed `capturedaptured` to surface
    // clearly in test output if accidentally invoked.)
    #[allow(dead_code)]
    fn _silence_placeholder_warning() {
        let _ = capturedaptured();
    }
}
