//! Pure core for the `depin-attest` tool plugin: no wasm dependency, so this
//! compiles and tests on the host with a plain `cargo test`. Packages an
//! edge-node sensor/health reading into an unsigned, durable-nonce Solana
//! transaction targeting the well-known SPL Memo program.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use zeroclaw_solana_core::transaction::{
    build_durable_nonce_transaction, AccountMeta, Instruction,
};
use zeroclaw_solana_core::{Blockhash, Pubkey};

pub fn name() -> &'static str {
    "depin_attest"
}

pub fn description() -> &'static str {
    "Packages an edge-node sensor/health reading into an unsigned, durable-nonce Solana \
     transaction targeting the well-known SPL Memo program, so it can be broadcast whenever \
     connectivity allows without racing a ~150-block blockhash expiry window. The durable \
     nonce doubles as the replay guard: advancing it invalidates any stale copy of the same \
     transaction."
}

pub fn parameters_schema() -> &'static str {
    r#"{"type":"object","properties":{
        "nonce_value":{"type":"string","description":"Base58 current stored value of the durable nonce account (required, changes every advance -- read it fresh before each call)"},
        "node_id":{"type":"string","description":"Edge node identifier"},
        "reading":{"type":"string","description":"The sensor/health reading to attest, e.g. \"23.5C\" or \"uptime_ok\""},
        "uptime_seconds":{"type":"integer","description":"Node uptime in seconds since last attestation"}
    },"required":["nonce_value","node_id","reading","uptime_seconds"]}"#
}

/// The well-known SPL Memo v2 program. Verified against the published
/// `spl-memo` crate's own `declare_id!("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")`,
/// not guessed. Targeting the real Memo program (one of the two options the
/// spec names -- "memo or program CPI") means this plugin anchors real data
/// on real Solana today, with no custom on-chain program to deploy or trust.
/// A hardcoded function, not a config key: there is no legitimate reason
/// this plugin would ever target a different program, so it isn't exposed
/// as something even an operator misconfiguration could change.
pub fn memo_program_id() -> Pubkey {
    Pubkey::from_base58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
        .expect("hardcoded memo program address must be valid base58")
}

/// Trusted, host-config-only account identities. Note what's absent: no
/// spend amount, no destination override, nothing an incoming prompt could
/// use to redirect funds or authority -- a memo instruction moves zero
/// lamports, so there is no amount-shaped guardrail to enforce here at all.
/// The actual safety property is structural: [`AttestParams`] (built from
/// `args_json`, i.e. attacker-influenced) has no account-shaped field
/// whatsoever, so there is nothing in the arguments capable of naming a
/// destination in the first place.
#[derive(Debug)]
pub struct AttestConfig {
    pub fee_payer: Pubkey,
    pub nonce_account: Pubkey,
    pub nonce_authority: Pubkey,
}

impl AttestConfig {
    pub fn from_section(cfg: &HashMap<String, String>) -> Result<Self, String> {
        Ok(Self {
            fee_payer: Pubkey::from_base58(trusted(cfg, "fee_payer")?)?,
            nonce_account: Pubkey::from_base58(trusted(cfg, "nonce_account")?)?,
            nonce_authority: Pubkey::from_base58(trusted(cfg, "nonce_authority")?)?,
        })
    }
}

fn trusted<'a>(cfg: &'a HashMap<String, String>, key: &str) -> Result<&'a str, String> {
    cfg.get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required config: {key}"))
}

/// Everything that comes from `args_json` (the LLM-supplied, untrusted
/// side). Deliberately has no field that could name an account.
pub struct AttestParams {
    pub nonce_value: Blockhash,
    pub node_id: String,
    pub reading: String,
    pub uptime_seconds: u64,
}

/// Builds the memo text committed on-chain. A stable, greppable prefix
/// (`zc-attest v1`) so downstream indexers can find these without parsing
/// every memo on the network.
fn build_memo_text(params: &AttestParams) -> String {
    format!(
        "zc-attest v1 node={} reading={} uptime_s={}",
        params.node_id, params.reading, params.uptime_seconds
    )
}

/// Full orchestration: build the memo instruction and wrap it in a durable-
/// nonce transaction. This is what the wasm shim's `execute` calls after
/// parsing `args` and `__config`.
pub fn attest(params: AttestParams, cfg: &AttestConfig) -> Result<String, String> {
    let memo_program = memo_program_id();
    let memo_text = build_memo_text(&params);

    let attest_ix = Instruction {
        program_id: memo_program,
        accounts: vec![AccountMeta::new_readonly(cfg.nonce_authority, true)],
        data: memo_text.clone().into_bytes(),
    };

    let tx = build_durable_nonce_transaction(
        cfg.fee_payer,
        cfg.nonce_account,
        cfg.nonce_authority,
        params.nonce_value,
        vec![attest_ix],
    )?;
    let bytes = borsh::to_vec(&tx).map_err(|e| format!("failed to serialize transaction: {e}"))?;

    Ok(format!(
        "**DePIN Attestation Ready**\n\
         - Node: `{}`\n\
         - Reading: `{}`\n\
         - Uptime: {}s\n\
         - Nonce account: `{}`\n\
         - Target: SPL Memo (`{}`)\n\
         - Memo: `{memo_text}`\n\
         - Unsigned tx (base64): `{}`\n",
        params.node_id,
        params.reading,
        params.uptime_seconds,
        cfg.nonce_account.to_base58(),
        memo_program.to_base58(),
        STANDARD.encode(&bytes)
    ))
}
