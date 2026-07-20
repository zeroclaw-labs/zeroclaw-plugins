//! Instruction encoding: IDL metadata + user args → Solana instruction data.
//!
//! Borsh-encodes primitive Anchor types into the instruction `data` field,
//! prefixed by the 8-byte Anchor discriminator (already resolved by `idl.rs`).
//! Account names from the IDL are resolved to user-provided base58 addresses;
//! the final index assignment happens in message assembly (bean x8rm).
//!
//! # v0 type coverage
//! Primitives only: `u8`/`u16`/`u32`/`u64`, `i8`/`i16`/`i32`/`i64`, `bool`,
//! `string`. `u128`/`i128` are documented as unsupported (serde_json f64
//! intermediary loses precision; v1 will parse from string). Complex Anchor
//! types (`Option`, `Vec`, `defined` structs) deferred to v1 — the two
//! canonical test cases (SPL `transfer`, Tributary `createSubscription`) use
//! only `u64`.

use crate::idl::InstructionRef;

/// One encoded instruction, ready for message assembly. Account addresses are
/// kept as base58 strings; index assignment is the message assembler's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedInstruction {
    /// Base58 program id that owns this instruction.
    pub program_id: String,
    /// Account addresses in IDL declaration order.
    pub accounts: Vec<String>,
    /// Discriminator + borsh-encoded args.
    pub data: Vec<u8>,
}

/// Encode one instruction from IDL metadata + user-supplied args/accounts.
///
/// `args_json` is the `"args"` object from the tool parameters schema.
/// `accounts_json` is the `"accounts"` object — keys must match the IDL's
/// `accounts[].name`.
pub fn encode_instruction(
    ix: &InstructionRef,
    args_json: &serde_json::Value,
    accounts_json: &serde_json::Value,
) -> Result<EncodedInstruction, String> {
    // 1. Resolve named accounts → base58 addresses in IDL order.
    let accounts: Vec<String> = ix
        .accounts
        .iter()
        .map(|a| {
            accounts_json
                .get(&a.name)
                .and_then(|v| v.as_str())
                .map(String::from)
                .ok_or_else(|| format!("missing account: {}", a.name))
        })
        .collect::<Result<_, _>>()?;

    // 2. Data = discriminator + borsh-encoded args in IDL order.
    let mut data = ix.discriminator.clone();
    for arg in &ix.args {
        let val = args_json
            .get(&arg.name)
            .ok_or_else(|| format!("missing arg: {}", arg.name))?;
        borsh_encode_into(&mut data, val, &arg.type_json)?;
    }

    Ok(EncodedInstruction {
        program_id: ix.program_id.clone(),
        accounts,
        data,
    })
}

/// Append the borsh encoding of `val` (typed by `type_json`) into `out`.
/// See module docs for the v0 type coverage.
fn borsh_encode_into(
    out: &mut Vec<u8>,
    val: &serde_json::Value,
    type_json: &serde_json::Value,
) -> Result<(), String> {
    let type_str = type_json
        .as_str()
        .ok_or_else(|| format!("v0 supports only string-typed IDL args, got: {type_json}"))?;

    match type_str {
        "u8" => out.push(val.as_u64().ok_or("expected u8")? as u8),
        "u16" => out.extend_from_slice(&(val.as_u64().ok_or("expected u16")? as u16).to_le_bytes()),
        "u32" => out.extend_from_slice(&(val.as_u64().ok_or("expected u32")? as u32).to_le_bytes()),
        "u64" => out.extend_from_slice(&val.as_u64().ok_or("expected u64")?.to_le_bytes()),
        "i8" => out.push((val.as_i64().ok_or("expected i8")?) as i8 as u8),
        "i16" => out.extend_from_slice(&(val.as_i64().ok_or("expected i16")? as i16).to_le_bytes()),
        "i32" => out.extend_from_slice(&(val.as_i64().ok_or("expected i32")? as i32).to_le_bytes()),
        "i64" => out.extend_from_slice(&val.as_i64().ok_or("expected i64")?.to_le_bytes()),
        "bool" => out.push(if val.as_bool().ok_or("expected bool")? {
            1
        } else {
            0
        }),
        "string" | "pubkey" | "publickey" => {
            let s = val.as_str().ok_or("expected string")?;
            let len = u32::try_from(s.len()).map_err(|_| "string too long")?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        _ => return Err(format!("unsupported type in v0: {type_str}")),
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
//  codec helpers — base58 / base64 / compact-u16
// ═══════════════════════════════════════════════════════════════════════════

pub fn base58_encode(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

pub fn base58_decode(s: &str) -> Result<Vec<u8>, String> {
    bs58::decode(s).into_vec().map_err(|e| e.to_string())
}

pub fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}

/// Solana compact-u16: variable-length integer encoding (7 bits per byte
/// with continuation bit). Used for array lengths in message serialization.
pub fn write_compact_u16(out: &mut Vec<u8>, val: u16) {
    let mut rem = val;
    loop {
        let mut byte = (rem & 0x7F) as u8;
        rem >>= 7;
        if rem != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if rem == 0 {
            break;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Solana V0 versioned message assembly (hand-rolled, no solana-sdk)
// ═══════════════════════════════════════════════════════════════════════════

/// Assemble a Solana V0 versioned message from encoded instructions.
///
/// Layout (little-endian, Solana wire format):
/// ```text
/// [0x80]                          prefix: versioned, version 0
/// [1, 0, 1]                       header: 1 signer (fee-payer),
///                                 0 readonly-signed, 1 readonly-unsigned
/// [compact-u16 N] [N × 32 bytes]  account keys (fee-payer first)
/// [32 bytes]                      recent blockhash
/// [compact-u16 M] [M × ix]        compiled instructions
/// [compact-u16 0]                 address table lookups (empty for v0)
/// ```
///
/// Returns the raw message bytes. The T2 signer wraps these with a signature
/// to form a complete transaction.
pub fn assemble_v0_message(
    instructions: &[EncodedInstruction],
    fee_payer: &str,
    blockhash: &str,
) -> Result<Vec<u8>, String> {
    // 1. Collect unique accounts: fee-payer first (signer, writable),
    //    then program ids (readonly unsigned), then instruction accounts.
    let mut account_keys: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let push_key =
        |keys: &mut Vec<String>, seen: &mut std::collections::HashSet<String>, k: &str| {
            if seen.insert(k.to_string()) {
                keys.push(k.to_string());
            }
        };

    push_key(&mut account_keys, &mut seen, fee_payer);
    // Programs first so they land in readonly-unsigned region (after the
    // first account which is the writable signer).
    for ix in instructions {
        push_key(&mut account_keys, &mut seen, &ix.program_id);
    }
    for ix in instructions {
        for acct in &ix.accounts {
            push_key(&mut account_keys, &mut seen, acct);
        }
    }

    let idx_of = |key: &str| -> Result<u8, String> {
        account_keys
            .iter()
            .position(|k| k == key)
            .map(|i| i as u8)
            .ok_or_else(|| format!("account not in key list: {key}"))
    };

    // 2. Serialize.
    let mut msg = Vec::with_capacity(256);

    // Prefix byte: versioned message, version 0.
    msg.push(0x80);

    // Header.
    msg.push(1); // num_required_signatures (fee-payer)
    msg.push(0); // num_readonly_signed_accounts
    msg.push(1); // num_readonly_unsigned_accounts

    // Account keys.
    write_compact_u16(&mut msg, account_keys.len() as u16);
    for key in &account_keys {
        let bytes = base58_decode(key)?;
        if bytes.len() != 32 {
            return Err(format!("pubkey is not 32 bytes: {key}"));
        }
        msg.extend_from_slice(&bytes);
    }

    // Recent blockhash.
    let bh = base58_decode(blockhash)?;
    if bh.len() != 32 {
        return Err("blockhash is not 32 bytes".into());
    }
    msg.extend_from_slice(&bh);

    // Instructions.
    write_compact_u16(&mut msg, instructions.len() as u16);
    for ix in instructions {
        // program_id_index
        msg.push(idx_of(&ix.program_id)?);

        // accounts (compact-array of u8 indexes)
        let acct_idxs: Vec<u8> = ix
            .accounts
            .iter()
            .map(|a| idx_of(a))
            .collect::<Result<_, _>>()?;
        write_compact_u16(&mut msg, acct_idxs.len() as u16);
        for &i in &acct_idxs {
            msg.push(i);
        }

        // data (compact-array of u8)
        write_compact_u16(&mut msg, ix.data.len() as u16);
        msg.extend_from_slice(&ix.data);
    }

    // Address table lookups (empty for v0 — no ALT support yet).
    write_compact_u16(&mut msg, 0);

    Ok(msg)
}

/// Assemble + base64-encode an unsigned V0 transaction. This is what
/// `build_transaction` returns as `unsigned_tx_base64`.
pub fn assemble_unsigned_tx_b64(
    instructions: &[EncodedInstruction],
    fee_payer: &str,
    blockhash: &str,
) -> Result<String, String> {
    let msg = assemble_v0_message(instructions, fee_payer, blockhash)?;
    Ok(base64_encode(&msg))
}

// ─── self-check ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idl::{AccountIdl, ArgIdl};

    fn ix_ref(name: &str, args: &[(&str, &str)], accounts: &[&str]) -> InstructionRef {
        InstructionRef {
            program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            name: name.to_string(),
            discriminator: vec![3, 1, 2, 3, 4, 5, 6, 7],
            args: args
                .iter()
                .map(|(n, t)| ArgIdl {
                    name: n.to_string(),
                    type_json: serde_json::json!(t),
                })
                .collect(),
            accounts: accounts
                .iter()
                .map(|n| AccountIdl {
                    name: n.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn spl_transfer_encodes_u64_amount() {
        let ix = ix_ref(
            "transfer",
            &[("amount", "u64")],
            &["source", "destination", "authority"],
        );
        let args = serde_json::json!({ "amount": 5_000_000u64 });
        let accounts = serde_json::json!({
            "source": "SrcATA",
            "destination": "DstATA",
            "authority": "Signer"
        });

        let encoded = encode_instruction(&ix, &args, &accounts).unwrap();

        assert_eq!(
            encoded.program_id,
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        );
        assert_eq!(encoded.accounts, vec!["SrcATA", "DstATA", "Signer"]);

        // data = 8-byte discriminator + 8-byte LE u64
        assert_eq!(encoded.data.len(), 16);
        assert_eq!(&encoded.data[..8], &[3, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(&encoded.data[8..], &5_000_000u64.to_le_bytes());
    }

    #[test]
    fn tributary_create_subscription_encodes_two_u64() {
        let ix = ix_ref(
            "create_subscription",
            &[("amount", "u64"), ("frequency", "u64")],
            &["payer", "user_payment"],
        );
        let args = serde_json::json!({ "amount": 5_000_000u64, "frequency": 86_400u64 });
        let accounts = serde_json::json!({
            "payer": "SignerAddr",
            "user_payment": "PdaAddr"
        });

        let encoded = encode_instruction(&ix, &args, &accounts).unwrap();

        // data = 8 discriminator + 8 amount + 8 frequency = 24
        assert_eq!(encoded.data.len(), 24);
        assert_eq!(&encoded.data[8..16], &5_000_000u64.to_le_bytes());
        assert_eq!(&encoded.data[16..24], &86_400u64.to_le_bytes());
    }

    #[test]
    fn missing_account_returns_error() {
        let ix = ix_ref(
            "transfer",
            &[("amount", "u64")],
            &["source", "destination", "authority"],
        );
        let args = serde_json::json!({ "amount": 1u64 });
        let accounts = serde_json::json!({ "source": "A" }); // missing dest + authority

        let err = encode_instruction(&ix, &args, &accounts).unwrap_err();
        assert!(err.contains("missing account"));
    }

    #[test]
    fn missing_arg_returns_error() {
        let ix = ix_ref("transfer", &[("amount", "u64")], &["source"]);
        let args = serde_json::json!({}); // no amount
        let accounts = serde_json::json!({ "source": "A" });

        let err = encode_instruction(&ix, &args, &accounts).unwrap_err();
        assert!(err.contains("missing arg"));
    }

    #[test]
    fn bool_encodes_as_one_byte() {
        let ix = ix_ref("test", &[("flag", "bool")], &[]);
        let encoded = encode_instruction(
            &ix,
            &serde_json::json!({ "flag": true }),
            &serde_json::json!({}),
        )
        .unwrap();
        assert_eq!(encoded.data[8], 1u8);

        let encoded = encode_instruction(
            &ix,
            &serde_json::json!({ "flag": false }),
            &serde_json::json!({}),
        )
        .unwrap();
        assert_eq!(encoded.data[8], 0u8);
    }

    #[test]
    fn string_borsh_encodes_with_length_prefix() {
        let ix = ix_ref("test", &[("memo", "string")], &[]);
        let encoded = encode_instruction(
            &ix,
            &serde_json::json!({ "memo": "hello" }),
            &serde_json::json!({}),
        )
        .unwrap();
        // 8 disc + 4 len + 5 bytes = 17
        assert_eq!(encoded.data.len(), 17);
        assert_eq!(&encoded.data[8..12], &5u32.to_le_bytes());
        assert_eq!(&encoded.data[12..], b"hello");
    }

    #[test]
    fn unsupported_type_rejects() {
        let ix = ix_ref("test", &[("x", "u128")], &[]);
        let err = encode_instruction(
            &ix,
            &serde_json::json!({ "x": 1u64 }),
            &serde_json::json!({}),
        )
        .unwrap_err();
        assert!(err.contains("unsupported type"));
    }

    // ── codec helpers ───────────────────────────────────────────────────────

    #[test]
    fn base58_roundtrips() {
        let original = [0x01u8, 0x02, 0x03, 0xff, 0x00, 0x42];
        let encoded = base58_encode(&original);
        let decoded = base58_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_roundtrips() {
        let original = [0x00u8, 0xff, 0x42, 0x7f, 0x80, 0x01];
        let encoded = base64_encode(&original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn compact_u16_single_byte() {
        let mut out = Vec::new();
        write_compact_u16(&mut out, 0);
        write_compact_u16(&mut out, 42);
        write_compact_u16(&mut out, 127);
        assert_eq!(out, vec![0, 42, 127]);
    }

    #[test]
    fn compact_u16_multi_byte() {
        let mut out = Vec::new();
        write_compact_u16(&mut out, 128);
        // 128 = 0x80: low 7 bits = 0, continuation = 1 → [0x80], then 1 → [0x01]
        assert_eq!(out, vec![0x80, 0x01]);

        out.clear();
        write_compact_u16(&mut out, 300);
        // 300 = 0x12C: low 7 bits = 0x2C, high bits = 0x02
        // byte 0: 0x2C | 0x80 = 0xAC, byte 1: 0x02
        assert_eq!(out, vec![0xAC, 0x02]);
    }

    // ── V0 message assembly ──────────────────────────────────────────────────

    /// A valid 32-byte pubkey for testing (all zeros encodes to "1" in base58).
    const ZERO_PUBKEY: &str = "11111111111111111111111111111111";
    const ZERO_BLOCKHASH: &str = "11111111111111111111111111111111";

    #[test]
    fn v0_message_has_correct_prefix_and_header() {
        let ix = EncodedInstruction {
            program_id: ZERO_PUBKEY.to_string(),
            accounts: vec![],
            data: vec![],
        };
        let msg = assemble_v0_message(&[ix], ZERO_PUBKEY, ZERO_BLOCKHASH).unwrap();

        assert_eq!(msg[0], 0x80, "prefix byte must be 0x80 for V0");
        assert_eq!(msg[1], 1, "num_required_signatures = 1 (fee-payer)");
        assert_eq!(msg[2], 0, "num_readonly_signed = 0");
        assert_eq!(msg[3], 1, "num_readonly_unsigned = 1");
    }

    #[test]
    fn v0_message_deduplicates_accounts() {
        // Same account appears in fee-payer and instruction → only one entry.
        let ix = EncodedInstruction {
            program_id: ZERO_PUBKEY.to_string(),
            accounts: vec![ZERO_PUBKEY.to_string()], // same as program
            data: vec![],
        };
        let msg = assemble_v0_message(&[ix], ZERO_PUBKEY, ZERO_BLOCKHASH).unwrap();

        // Account count is compact-u16 at offset 4 (after prefix + 3 header).
        assert_eq!(msg[4], 1, "only 1 unique account key");
    }

    #[test]
    fn v0_message_includes_blockhash() {
        let msg = assemble_v0_message(&[], ZERO_PUBKEY, ZERO_BLOCKHASH).unwrap();
        // After prefix(1) + header(3) + account_count(1) + 32-byte-key(32)
        // = offset 37, then 32 bytes of blockhash.
        assert_eq!(msg.len(), 37 + 32 + 1 + 1); // + instructions_count(1) + ALT_count(1)
    }

    #[test]
    fn unsigned_tx_b64_is_nonempty() {
        let tx = assemble_unsigned_tx_b64(&[], ZERO_PUBKEY, ZERO_BLOCKHASH).unwrap();
        assert!(!tx.is_empty());
        // Decodes back to valid bytes
        assert!(base64_decode(&tx).is_ok());
    }
}
