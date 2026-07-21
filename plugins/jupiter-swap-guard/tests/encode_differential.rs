//! Differential test: the plugin's pure `encode::serialize_v0` must produce bytes
//! byte-identical to the official Anza `solana-message` serializer, for a REAL
//! mainnet Jupiter route (captured in `tests/fixtures/`). Host-only: the
//! `solana-*` crates are dev-dependencies and never enter the wasm build.
//!
//! This is KT-1 (the encoder kill test) frozen as a regression: if a refactor of
//! the hand-rolled encoder ever diverges from the SDK by a single byte, this
//! fails.

use base64::Engine;
use jupiter_swap_guard::encode::{
    serialize_v0, CompiledInstruction, MessageAddressTableLookup, MessageHeader, V0Message,
};
use serde::Deserialize;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_pubkey::Pubkey;
use std::str::FromStr;

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

#[derive(Deserialize)]
struct JupAcct {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
    #[serde(rename = "isWritable")]
    is_writable: bool,
}
#[derive(Deserialize)]
struct JupIx {
    #[serde(rename = "programId")]
    program_id: String,
    accounts: Vec<JupAcct>,
    data: String,
}
#[derive(Deserialize)]
struct SwapIxs {
    #[serde(rename = "computeBudgetInstructions")]
    compute_budget_instructions: Vec<JupIx>,
    #[serde(rename = "setupInstructions")]
    setup_instructions: Vec<JupIx>,
    #[serde(rename = "swapInstruction")]
    swap_instruction: JupIx,
    #[serde(rename = "cleanupInstruction")]
    cleanup_instruction: Option<JupIx>,
    #[serde(rename = "addressLookupTableAddresses")]
    address_lookup_table_addresses: Vec<String>,
}

fn pk(s: &str) -> Pubkey {
    Pubkey::from_str(s).unwrap()
}

fn to_sdk_ix(j: &JupIx) -> Instruction {
    Instruction {
        program_id: pk(&j.program_id),
        accounts: j
            .accounts
            .iter()
            .map(|a| AccountMeta {
                pubkey: pk(&a.pubkey),
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
            .collect(),
        data: base64::engine::general_purpose::STANDARD
            .decode(&j.data)
            .unwrap(),
    }
}

#[test]
fn hand_rolled_v0_serializer_matches_anza_on_real_jupiter_route() {
    let raw = std::fs::read_to_string(format!("{FX}/swap-instructions.json")).unwrap();
    let s: SwapIxs = serde_json::from_str(&raw).unwrap();
    let payer = pk(std::fs::read_to_string(format!("{FX}/payer_pubkey.txt"))
        .unwrap()
        .trim());

    let mut ixs: Vec<Instruction> = Vec::new();
    for j in &s.compute_budget_instructions {
        ixs.push(to_sdk_ix(j));
    }
    for j in &s.setup_instructions {
        ixs.push(to_sdk_ix(j));
    }
    ixs.push(to_sdk_ix(&s.swap_instruction));
    if let Some(c) = &s.cleanup_instruction {
        ixs.push(to_sdk_ix(c));
    }

    // Build the ALT account from the captured on-chain account data.
    let alt_key = pk(&s.address_lookup_table_addresses[0]);
    let alt_json = std::fs::read_to_string(format!("{FX}/alt_account.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&alt_json).unwrap();
    let data_b64 = v["result"]["value"]["data"][0].as_str().unwrap();
    let alt_data = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .unwrap();
    const META: usize = 56; // LookupTableMeta size; addresses follow.
    let addresses: Vec<Pubkey> = alt_data[META..]
        .chunks_exact(32)
        .map(|c| Pubkey::try_from(c).unwrap())
        .collect();
    let alt = AddressLookupTableAccount {
        key: alt_key,
        addresses,
    };

    let blockhash = Hash::new_from_array([7u8; 32]);

    // GOLDEN: official compile + serialize.
    let compiled = v0::Message::try_compile(&payer, &ixs, &[alt], blockhash).unwrap();
    let golden = VersionedMessage::V0(compiled.clone()).serialize();

    // MINE: translate the compiled structure into the plugin's own types and
    // serialize with the pure hand-rolled encoder.
    let mine_msg = V0Message {
        header: MessageHeader {
            num_required_signatures: compiled.header.num_required_signatures,
            num_readonly_signed_accounts: compiled.header.num_readonly_signed_accounts,
            num_readonly_unsigned_accounts: compiled.header.num_readonly_unsigned_accounts,
        },
        static_keys: compiled.account_keys.iter().map(|k| k.to_bytes()).collect(),
        recent_blockhash: compiled.recent_blockhash.to_bytes(),
        instructions: compiled
            .instructions
            .iter()
            .map(|ix| CompiledInstruction {
                program_id_index: ix.program_id_index,
                accounts: ix.accounts.clone(),
                data: ix.data.clone(),
            })
            .collect(),
        address_table_lookups: compiled
            .address_table_lookups
            .iter()
            .map(|l| MessageAddressTableLookup {
                account_key: l.account_key.to_bytes(),
                writable_indexes: l.writable_indexes.clone(),
                readonly_indexes: l.readonly_indexes.clone(),
            })
            .collect(),
    };
    let mine = serialize_v0(&mine_msg);

    assert_eq!(
        golden.len(),
        mine.len(),
        "length mismatch: golden {} vs mine {}",
        golden.len(),
        mine.len()
    );
    assert_eq!(
        golden, mine,
        "hand-rolled v0 serializer diverged from solana-message on a real Jupiter route"
    );

    // Sanity: the route actually exercises ALT compression (otherwise the test
    // would not cover the lookup section).
    assert!(
        !compiled.address_table_lookups.is_empty(),
        "fixture must use at least one address lookup table"
    );
}
