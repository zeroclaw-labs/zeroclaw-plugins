//! Pure parsing of Jupiter's `/quote` and `/swap-instructions` responses into
//! typed values. No I/O, no wasm dependency: `http` fetches the bytes, this turns
//! them into structs the policy gate can reason over. Tested against a real
//! captured mainnet response in `tests/fixtures/`.

#![forbid(unsafe_code)]

use crate::b58::decode_pubkey;
use crate::instruction::{AccountMeta, Instruction};
use serde::Deserialize;

/// The fields of a `/quote` response the guard depends on. `out_amount` and
/// `other_amount_threshold` are decimal strings of `u64` atoms.
#[derive(Debug, Clone)]
pub struct Quote {
    pub in_amount: u64,
    pub out_amount: u64,
    /// Jupiter's own min-received at the requested slippage; the guard recomputes
    /// its floor independently (`P2`) and never simply trusts this.
    pub other_amount_threshold: u64,
    pub slippage_bps: u16,
    /// The verbatim quote JSON, needed as the body of the `/swap-instructions`
    /// request.
    pub raw: serde_json::Value,
}

/// A Jupiter `/swap-instructions` response, parsed into ordered instructions plus
/// the metadata the gate and encoder need.
#[derive(Debug, Clone)]
pub struct SwapInstructions {
    pub compute_budget: Vec<Instruction>,
    pub setup: Vec<Instruction>,
    pub swap: Instruction,
    pub cleanup: Option<Instruction>,
    pub address_lookup_tables: Vec<[u8; 32]>,
    pub compute_unit_limit: Option<u32>,
}

impl SwapInstructions {
    /// All instructions in canonical execution order (compute budget, setup,
    /// swap, cleanup) — the order they must appear in the built transaction.
    pub fn ordered(&self) -> Vec<Instruction> {
        let mut v = Vec::new();
        v.extend(self.compute_budget.iter().cloned());
        v.extend(self.setup.iter().cloned());
        v.push(self.swap.clone());
        if let Some(c) = &self.cleanup {
            v.push(c.clone());
        }
        v
    }
}

// ---- wire types (serde) ----

#[derive(Deserialize)]
struct WireAccount {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
    #[serde(rename = "isWritable")]
    is_writable: bool,
}

#[derive(Deserialize)]
struct WireIx {
    #[serde(rename = "programId")]
    program_id: String,
    accounts: Vec<WireAccount>,
    data: String,
}

#[derive(Deserialize)]
struct WireSwap {
    #[serde(rename = "computeBudgetInstructions", default)]
    compute_budget_instructions: Vec<WireIx>,
    #[serde(rename = "setupInstructions", default)]
    setup_instructions: Vec<WireIx>,
    #[serde(rename = "swapInstruction")]
    swap_instruction: WireIx,
    #[serde(rename = "cleanupInstruction", default)]
    cleanup_instruction: Option<WireIx>,
    #[serde(rename = "addressLookupTableAddresses", default)]
    address_lookup_table_addresses: Vec<String>,
    #[serde(rename = "computeUnitLimit", default)]
    compute_unit_limit: Option<u32>,
}

fn u64_str(v: &serde_json::Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("quote missing string field `{key}`"))?
        .parse()
        .map_err(|_| format!("quote field `{key}` is not a u64"))
}

/// Parse a `/quote` response body.
pub fn parse_quote(body: &str) -> Result<Quote, String> {
    let raw: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("quote is not JSON: {e}"))?;
    let slippage_bps = raw
        .get("slippageBps")
        .and_then(|x| x.as_u64())
        .ok_or("quote missing slippageBps")? as u16;
    Ok(Quote {
        in_amount: u64_str(&raw, "inAmount")?,
        out_amount: u64_str(&raw, "outAmount")?,
        other_amount_threshold: u64_str(&raw, "otherAmountThreshold")?,
        slippage_bps,
        raw,
    })
}

fn to_ix(w: &WireIx) -> Result<Instruction, String> {
    use base64::Engine;
    let program_id = decode_pubkey(&w.program_id)?;
    let accounts = w
        .accounts
        .iter()
        .map(|a| {
            Ok(AccountMeta {
                pubkey: decode_pubkey(&a.pubkey)?,
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(&w.data)
        .map_err(|e| format!("instruction data is not base64: {e}"))?;
    Ok(Instruction {
        program_id,
        accounts,
        data,
    })
}

/// Parse a `/swap-instructions` response body.
pub fn parse_swap_instructions(body: &str) -> Result<SwapInstructions, String> {
    let w: WireSwap =
        serde_json::from_str(body).map_err(|e| format!("swap-instructions is not JSON: {e}"))?;
    let compute_budget = w
        .compute_budget_instructions
        .iter()
        .map(to_ix)
        .collect::<Result<Vec<_>, _>>()?;
    let setup = w
        .setup_instructions
        .iter()
        .map(to_ix)
        .collect::<Result<Vec<_>, _>>()?;
    let swap = to_ix(&w.swap_instruction)?;
    let cleanup = w.cleanup_instruction.as_ref().map(to_ix).transpose()?;
    let address_lookup_tables = w
        .address_lookup_table_addresses
        .iter()
        .map(|s| decode_pubkey(s))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SwapInstructions {
        compute_budget,
        setup,
        swap,
        cleanup,
        address_lookup_tables,
        compute_unit_limit: w.compute_unit_limit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    #[test]
    fn parses_real_quote() {
        let body = std::fs::read_to_string(format!("{FX}/quote.json")).unwrap();
        let q = parse_quote(&body).unwrap();
        assert_eq!(q.in_amount, 100_000_000); // 0.1 SOL
        assert!(q.out_amount > 0);
        assert!(q.other_amount_threshold <= q.out_amount);
        assert_eq!(q.slippage_bps, 50);
    }

    #[test]
    fn parses_real_swap_instructions() {
        let body = std::fs::read_to_string(format!("{FX}/swap-instructions.json")).unwrap();
        let s = parse_swap_instructions(&body).unwrap();
        // Real route shape: 2 compute-budget ix, a swap on Jupiter v6, 1 ALT.
        assert_eq!(s.compute_budget.len(), 2);
        assert_eq!(
            crate::b58::encode_pubkey(&s.swap.program_id),
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
        );
        assert_eq!(s.address_lookup_tables.len(), 1);
        assert!(!s.ordered().is_empty());
        // Every account decoded to 32 bytes (would have errored otherwise).
        assert!(s.swap.accounts.len() >= 8);
    }
}
