//! Pure attestation core. No wit-bindgen or wasm dependency so it compiles and
//! tests on the host with a plain `cargo test`, while the wasm component reuses
//! the exact same logic through `lib.rs`.
//!
//! Slice B: `AttestConfig` (config parsing), `SensorReading` (payload + nonce),
//! `AttestError` (specific + actionable errors).

use std::collections::HashMap;
use std::str::FromStr;

use borsh::BorshSerialize;
use ed25519_dalek::SigningKey;
use palinurus_core::{find_program_address, AccountMeta, CreateAttestationIxData, Instruction, Pubkey};
use sha2::{Digest, Sha256};

use base64::prelude::{BASE64_STANDARD, Engine as _};
use palinurus_core::{
    build_with_durable_nonce, parse_nonce_account, serialize_tx, short_pubkey, NonceState, Rpc,
};

// ── Constants ──

/// Default attestation time-to-live: 90 days in seconds.
const DEFAULT_ATTESTATION_TTL_SECS: i64 = 7_776_000;

/// Reject TTL values that would risk `timestamp + ttl` overflow when the
/// reading timestamp is a reasonable unix time (< year 2100). Anything above
/// ~1000 years is nonsensical for a sensor-reading expiry.
const MAX_ATTESTATION_TTL_SECS: i64 = i64::MAX - 31_622_400;

// ── Errors ──

/// Every error the attestation flow can produce. Specific + actionable — no
/// generic "failed" messages.
#[derive(Debug)]
pub enum AttestError {
    /// Missing or malformed config key. The message names the key + the problem.
    Config(String),
    /// Invalid sensor reading (empty sensor_id, non-finite value, bad timestamp).
    InvalidReading(String),
    /// JSON-RPC failure (transport, parse, or RPC-server error).
    Rpc(palinurus_core::RpcError),
    /// Durable-nonce account problem (not found, uninitialized, authority mismatch).
    NonceAccount(String),
    /// Borsh payload encode/decode failure.
    Borsh(String),
    /// T2 custody guard violation (allowlist, identity, cap). Fail closed.
    Custody(String),
    /// Ed25519 signing failure (T2). Infallible for a valid session key — but
    /// we surface it as a typed error rather than panicking.
    Signing(String),
    /// `sendTransaction` failure (T2).
    Submit(String),
}

// ── Custody mode ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyMode {
    /// Default: the plugin builds an unsigned tx; a human / Squads multisig signs.
    T1,
    /// Opt-in: a scoped session key signs + submits, guarded by program allowlist
    /// + hard caps + identity check + fail-closed injection test.
    T2,
}

// ── Config ──

/// Plugin config resolved from the flat `string -> string` section the host
/// injects via `config_read`. Absent or empty keys fail closed (the plugin
/// cannot attest without an RPC endpoint + SAS PDAs + a nonce account).
pub struct AttestConfig {
    // ── RPC ──
    pub rpc_endpoint: String,
    pub rpc_api_key: Option<String>,

    // ── SAS identity (from one-time sas-setup) ──
    pub credential_pda: Pubkey,
    pub schema_pda: Pubkey,

    // ── Signing identity ──
    /// The Credential's authorized signer. T1: the multisig/session PDA that
    /// will sign. T2: the session key's pubkey.
    pub authority: Pubkey,
    /// Fee payer for the attestation account creation + nonce advance.
    /// Typically == authority.
    pub payer: Pubkey,

    // ── Durable nonce (blockhash-expiry fix) ──
    pub nonce_account: Pubkey,
    pub nonce_authority: Pubkey,

    // ── Behavior ──
    pub custody_mode: CustodyMode,
    pub attestation_ttl_secs: i64,
    pub memo_fallback: bool,
    /// "devnet" or "mainnet-beta" — for the explorer URL in shaped output.
    pub network: String,

    // ── T2 only ──
    /// The scoped session key (Ed25519). None for T1. Never a main wallet key.
    pub session_key: Option<SigningKey>,
    pub max_lamports_per_tx: u64,
    pub max_attestations_per_day: u32,
}

/// Manual `Debug` — the session key is redacted (`[REDACTED]`) so it is never
/// leaked in error messages, logs, or `dbg!` output. This is part of the
/// T2 security posture (injection test attack 3: session key exfiltration).
impl std::fmt::Debug for AttestConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestConfig")
            .field("rpc_endpoint", &self.rpc_endpoint)
            .field("rpc_api_key", &self.rpc_api_key.as_ref().map(|_| "[REDACTED]"))
            .field("credential_pda", &self.credential_pda)
            .field("schema_pda", &self.schema_pda)
            .field("authority", &self.authority)
            .field("payer", &self.payer)
            .field("nonce_account", &self.nonce_account)
            .field("nonce_authority", &self.nonce_authority)
            .field("custody_mode", &self.custody_mode)
            .field("attestation_ttl_secs", &self.attestation_ttl_secs)
            .field("memo_fallback", &self.memo_fallback)
            .field("network", &self.network)
            .field("session_key", &self.session_key.as_ref().map(|_| "[REDACTED]"))
            .field("max_lamports_per_tx", &self.max_lamports_per_tx)
            .field("max_attestations_per_day", &self.max_attestations_per_day)
            .finish()
    }
}

impl AttestConfig {
    /// Build from the flat `string -> string` section the host injects as
    /// `__config`. Fails closed on any missing required key, malformed base58,
    /// or unknown custody mode.
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, AttestError> {
        if section.is_empty() {
            return Err(AttestError::Config(
                "not configured: no config section received (is config_read permission set?)".to_string(),
            ));
        }

        let rpc_endpoint = required(section, "rpc_endpoint")?;
        let rpc_api_key = optional(section, "rpc_api_key");

        let credential_pda = parse_pubkey(section, "credential_pda")?;
        let schema_pda = parse_pubkey(section, "schema_pda")?;
        let authority = parse_pubkey(section, "authority")?;
        let payer = parse_pubkey(section, "payer")?;
        let nonce_account = parse_pubkey(section, "nonce_account")?;
        let nonce_authority = parse_pubkey(section, "nonce_authority")?;

        let custody_mode = match optional(section, "custody_mode").as_deref() {
            None | Some("") | Some("t1") => CustodyMode::T1,
            Some("t2") => CustodyMode::T2,
            Some(other) => {
                return Err(AttestError::Config(format!(
                    "unknown custody_mode: '{other}', expected 't1' or 't2'"
                )))
            }
        };

        let attestation_ttl_secs = parse_i64(section, "attestation_ttl_secs")?
            .unwrap_or(DEFAULT_ATTESTATION_TTL_SECS);
        if attestation_ttl_secs < 0 {
            return Err(AttestError::Config(
                "attestation_ttl_secs must be non-negative".to_string(),
            ));
        }
        if attestation_ttl_secs > MAX_ATTESTATION_TTL_SECS {
            return Err(AttestError::Config(format!(
                "attestation_ttl_secs {attestation_ttl_secs} is too large (max {MAX_ATTESTATION_TTL_SECS}) — would risk expiry overflow"
            )));
        }

        let memo_fallback = parse_bool(section, "memo_fallback", false);
        let network = optional(section, "network").unwrap_or_else(|| "devnet".to_string());

        // ── T2-only fields ──
        let (session_key, max_lamports_per_tx, max_attestations_per_day) = match custody_mode {
            CustodyMode::T1 => (None, 0, 0),
            CustodyMode::T2 => {
                let key_b58 = required(section, "session_key")?;
                let key_bytes = bs58::decode(&key_b58)
                    .into_vec()
                    .map_err(|e| {
                        AttestError::Config(format!("session_key is not valid base58: {e}"))
                    })?;
                if key_bytes.len() != 32 {
                    return Err(AttestError::Config(format!(
                        "session_key must decode to 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key_bytes);
                let sk = SigningKey::from_bytes(&arr);
                (
                    Some(sk),
                    parse_u64(section, "max_lamports_per_tx")?.unwrap_or(10_000),
                    parse_u32(section, "max_attestations_per_day")?.unwrap_or(100),
                )
            }
        };

        Ok(AttestConfig {
            rpc_endpoint,
            rpc_api_key,
            credential_pda,
            schema_pda,
            authority,
            payer,
            nonce_account,
            nonce_authority,
            custody_mode,
            attestation_ttl_secs,
            memo_fallback,
            network,
            session_key,
            max_lamports_per_tx,
            max_attestations_per_day,
        })
    }
}

// ── Sensor reading (the attestation payload + nonce) ──

/// A physical sensor reading, Borsh-encoded into the `data` field of the SAS
/// `create_attestation` instruction. The schema is registered one-time by the
/// `sas-setup` script.
#[derive(BorshSerialize, borsh::BorshDeserialize, Clone, Debug, PartialEq)]
pub struct SensorReading {
    pub sensor_id: String,
    pub value: f64,
    pub unit: String,
    pub timestamp: i64,
}

impl SensorReading {
    /// Borsh-encode the reading into the `data: Vec<u8>` field of
    /// `CreateAttestationIxData`. This is the attestation payload an off-chain
    /// verifier decodes with the Schema's `layout`.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("SensorReading is a fixed-shape struct — encode is infallible")
    }

    /// Derive the attestation nonce: a `Pubkey` (32 bytes) from the SHA-256 of
    /// the reading content. Deterministic, unique per reading, and
    /// cryptographically bound to what is attested.
    ///
    /// `nonce = Pubkey(sha256(sensor_id_utf8 ‖ timestamp_i64_le_8 ‖ value_f64_le_8 ‖ unit_utf8))`
    ///
    /// SAS uses the nonce only as a PDA seed — it does not verify the nonce is
    /// a valid Ed25519 key. A SHA-256 hash is a valid 32-byte seed. Two
    /// readings with identical content produce the same nonce → the second tx
    /// fails with a PDA-already-exists error (natural dedup, not a bug).
    pub fn derive_nonce(&self) -> Pubkey {
        let mut hasher = Sha256::new();
        hasher.update(self.sensor_id.as_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.value.to_le_bytes());
        hasher.update(self.unit.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Pubkey::from_bytes(bytes)
    }
}

// ── Config parsing helpers ──

fn required(section: &HashMap<String, String>, key: &str) -> Result<String, AttestError> {
    section
        .get(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AttestError::Config(format!("missing required key: {key}")))
}

fn optional(section: &HashMap<String, String>, key: &str) -> Option<String> {
    section
        .get(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn parse_pubkey(section: &HashMap<String, String>, key: &str) -> Result<Pubkey, AttestError> {
    let s = required(section, key)?;
    Pubkey::from_str(&s).map_err(|e| AttestError::Config(format!("invalid base58 for {key}: {e}")))
}

fn parse_i64(section: &HashMap<String, String>, key: &str) -> Result<Option<i64>, AttestError> {
    match optional(section, key) {
        None => Ok(None),
        Some(s) => s
            .parse::<i64>()
            .map(Some)
            .map_err(|e| AttestError::Config(format!("invalid i64 for {key}: {e}"))),
    }
}

fn parse_u64(section: &HashMap<String, String>, key: &str) -> Result<Option<u64>, AttestError> {
    match optional(section, key) {
        None => Ok(None),
        Some(s) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|e| AttestError::Config(format!("invalid u64 for {key}: {e}"))),
    }
}

fn parse_u32(section: &HashMap<String, String>, key: &str) -> Result<Option<u32>, AttestError> {
    match optional(section, key) {
        None => Ok(None),
        Some(s) => s
            .parse::<u32>()
            .map(Some)
            .map_err(|e| AttestError::Config(format!("invalid u32 for {key}: {e}"))),
    }
}

fn parse_bool(section: &HashMap<String, String>, key: &str, default: bool) -> bool {
    optional(section, key)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}


// ── Instruction building (slice C) ──

/// The SAS "attestation" PDA seed (verified from sas-lib `ATTESTATION_SEED`).
const ATTESTATION_SEED: &[u8] = b"attestation";

/// Build the SAS `create_attestation` instruction for a sensor reading.
///
/// Returns `(instruction, attestation_pda, expiry)`:
/// - `instruction`: 6 accounts (payer W-signer, authority R-signer, credential R,
///   schema R, attestation W, system_program R) + `CreateAttestationIxData` bytes.
/// - `attestation_pda`: `find_program_address(["attestation", credential, schema, nonce], SAS)`.
/// - `expiry`: `reading.timestamp + cfg.attestation_ttl_secs`.
///
/// Verified against sas-lib@1.0.10 `getCreateAttestationInstruction` +
/// `deriveAttestationPda` (tools/verify-attest-ix.mjs oracle).
pub fn build_attest_ix(
    reading: &SensorReading,
    cfg: &AttestConfig,
) -> Result<(Instruction, Pubkey, i64), AttestError> {
    let nonce = reading.derive_nonce();

    // Derive the attestation PDA: ["attestation", credential, schema, nonce].
    let (attestation_pda, _bump) = find_program_address(
        &[
            ATTESTATION_SEED,
            cfg.credential_pda.as_bytes(),
            cfg.schema_pda.as_bytes(),
            nonce.as_bytes(),
        ],
        &Pubkey::SAS,
    );

    // Expiry = timestamp + ttl (overflow-checked; TTL itself is bounded by config validation).
    let expiry = reading
        .timestamp
        .checked_add(cfg.attestation_ttl_secs)
        .ok_or_else(|| AttestError::InvalidReading("expiry overflow: timestamp + ttl exceeds i64".to_string()))?;

    // Instruction data: [disc=6][nonce 32B][u32 LE len][data bytes][i64 LE expiry].
    let data = CreateAttestationIxData::new(nonce, reading.encode(), expiry).to_ix_bytes();

    // Accounts (6, in order — matches sas-lib Codama layout):
    //   0. payer          — WritableSigner   (pays for attestation account creation)
    //   1. authority      — ReadonlySigner   (Credential's authorized signer)
    //   2. credential     — Readonly         (Credential PDA from sas-setup)
    //   3. schema         — Readonly         (Schema PDA from sas-setup)
    //   4. attestation    — Writable         (the PDA being created)
    //   5. system_program — Readonly         (System program, default 111...111)
    let accounts = vec![
        AccountMeta::signer_writable(cfg.payer),
        AccountMeta::signer_readonly(cfg.authority),
        AccountMeta::readonly(cfg.credential_pda),
        AccountMeta::readonly(cfg.schema_pda),
        AccountMeta::writable(attestation_pda),
        AccountMeta::readonly(Pubkey::SYSTEM),
    ];

    let ix = Instruction {
        program_id: Pubkey::SAS,
        accounts,
        data,
    };

    Ok((ix, attestation_pda, expiry))
}

/// Build a memo instruction (program `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`,
/// data = raw UTF-8, no accounts). The memo program logs the text on-chain;
/// it takes no accounts and performs no state change.
pub fn build_memo_ix(memo: &str) -> Instruction {
    Instruction {
        program_id: Pubkey::MEMO,
        accounts: Vec::new(),
        data: memo.as_bytes().to_vec(),
    }
}

// ── Output + response shaping (slice D) ──

/// The result of an attestation `execute` call. The `summary` field is the
/// ~200-token string that goes into `ToolResult.output`; the structured fields
/// are for the host / tests / future programmatic consumption.
#[derive(Debug)]
pub struct AttestOutput {
    /// The attestation PDA (the on-chain account that will hold the attestation).
    pub attestation_pda: Pubkey,
    /// The serialized versioned tx, base64-encoded. T1: unsigned (0 signatures).
    /// T2: signed. The host / multisig signs and submits this (T1) or the plugin
    /// already signed + submitted it (T2).
    pub tx_b64: String,
    /// The on-chain transaction signature (T2 only, after send_transaction).
    pub signature: Option<String>,
    /// The attestation expiry (unix timestamp).
    pub expiry: i64,
    /// Whether the memo-fallback path was used (no SAS instruction).
    pub used_memo_fallback: bool,
    /// The explorer URL for the attestation PDA (T1) or the tx signature (T2).
    pub explorer_url: String,
    /// The ~200-token shaped summary → `ToolResult.output`.
    pub summary: String,
}

/// Shape the T1 output: attestation PDA + nonce + expiry + truncated tx_b64 +
/// explorer URL + sign-with hint. Target ≤200 tokens, ≤800 chars.
fn shape_t1(
    attestation_pda: &Pubkey,
    nonce: &Pubkey,
    expiry: i64,
    tx_b64: &str,
    cfg: &AttestConfig,
) -> String {
    let cluster = &cfg.network;
    let pda_short = short_pubkey(attestation_pda);
    let nonce_short = short_pubkey(nonce);
    let auth_short = short_pubkey(&cfg.authority);
    // Truncate the tx_b64 preview to 48 chars (enough to identify, not flood context).
    let tx_preview = if tx_b64.len() > 48 {
        format!("{}…", &tx_b64[..48])
    } else {
        tx_b64.to_string()
    };
    format!(
        "✓ attested reading → attestation PDA {pda_short}\n\
         nonce: {nonce_short}  expiry: {expiry}\n\
         tx (unsigned, base64, durable-nonce): {tx_preview}\n\
         explorer: https://explorer.solana.com/address/{pda}?cluster={cluster}\n\
         sign with: multisig approve (authority {auth_short})",
        pda = attestation_pda,
    )
}

/// Shape the memo-fallback output.
#[allow(dead_code)]
fn shape_memo_fallback(
    nonce_account: &Pubkey,
    memo_text: &str,
    tx_b64: &str,
    cfg: &AttestConfig,
) -> String {
    let cluster = &cfg.network;
    let tx_preview = if tx_b64.len() > 48 {
        format!("{}…", &tx_b64[..48])
    } else {
        tx_b64.to_string()
    };
    let memo_preview = if memo_text.len() > 60 {
        format!("{}…", &memo_text[..60])
    } else {
        memo_text.to_string()
    };
    format!(
        "✓ memo attestation (SAS unavailable) → tx (unsigned, base64): {tx_preview}\n\
         memo: \"{memo_preview}\"\n\
         explorer after sign: https://explorer.solana.com/address/{na}?cluster={cluster}",
        na = nonce_account,
    )
}

/// Shape the T2 output (signed + submitted).
#[allow(dead_code)]
fn shape_t2(
    attestation_pda: &Pubkey,
    nonce: &Pubkey,
    expiry: i64,
    signature: &str,
    cfg: &AttestConfig,
) -> String {
    let cluster = &cfg.network;
    let pda_short = short_pubkey(attestation_pda);
    let nonce_short = short_pubkey(nonce);
    let sig_preview = if signature.len() > 32 {
        format!("{}…", &signature[..32])
    } else {
        signature.to_string()
    };
    format!(
        "✓ attested + submitted → attestation PDA {pda_short}\n\
         sig: {sig_preview}  nonce: {nonce_short}  expiry: {expiry}\n\
         explorer: https://explorer.solana.com/tx/{sig}?cluster={cluster}",
        sig = signature,
    )
}

// ── execute_t1 (slice D) ──

/// Execute the T1 attestation flow: build an unsigned durable-nonce versioned
/// transaction containing the SAS `create_attestation` instruction (+ optional
/// memo), ready for a human / Squads multisig to sign.
///
/// The pure core does NOT log (it returns `Result`s); the shim in `lib.rs`
/// wires `log-record` + the actual `WakiRpc`. Host tests use `MockRpc`.
pub fn execute_t1(
    reading: &SensorReading,
    memo: Option<&str>,
    cfg: &AttestConfig,
    rpc: &dyn Rpc,
) -> Result<AttestOutput, AttestError> {
    // 1. Validate the reading.
    validate_reading(reading)?;

    // 2-3. Build the SAS instruction + derive the nonce + PDA + expiry.
    let nonce = reading.derive_nonce();
    let (sas_ix, attestation_pda, expiry) = build_attest_ix(reading, cfg)?;

    // 4. Assemble user instructions (SAS ix + optional memo).
    let mut user_ixs = vec![sas_ix];
    if let Some(m) = memo {
        if !m.is_empty() {
            user_ixs.push(build_memo_ix(m));
        }
    }

    // 5-8. Fetch + parse the nonce account.
    let acct = rpc
        .get_account_info(&cfg.nonce_account)
        .map_err(AttestError::Rpc)?;
    let acct = acct.ok_or_else(|| {
        AttestError::NonceAccount(format!(
            "nonce account not found: {}",
            cfg.nonce_account
        ))
    })?;

    let nonce_acct = parse_nonce_account(&acct.data).map_err(|e| {
        AttestError::NonceAccount(format!("failed to parse nonce account: {e:?}"))
    })?;

    let nonce_data = match nonce_acct.state {
        NonceState::Initialized(d) => d,
        palinurus_core::NonceState::Uninitialized => {
            return Err(AttestError::NonceAccount(
                "nonce account is uninitialized — create + initialize it first".to_string(),
            ));
        }
    };

    // Verify the nonce authority matches config (fail closed if not ours).
    if nonce_data.authority != cfg.nonce_authority {
        return Err(AttestError::NonceAccount(format!(
            "nonce authority mismatch: expected {}, got {}",
            cfg.nonce_authority, nonce_data.authority
        )));
    }

    // 9. Build the unsigned durable-nonce versioned tx.
    let tx = build_with_durable_nonce(
        &user_ixs,
        cfg.payer,
        cfg.nonce_account,
        nonce_data.durable_nonce,
        cfg.nonce_authority,
    );

    // 10-11. Serialize + base64-encode.
    let tx_bytes = serialize_tx(&tx);
    let tx_b64 = BASE64_STANDARD.encode(&tx_bytes);

    // 12-13. Shape the result + build the explorer URL.
    let summary = shape_t1(&attestation_pda, &nonce, expiry, &tx_b64, cfg);
    let explorer_url = format!(
        "https://explorer.solana.com/address/{}?cluster={}",
        attestation_pda, cfg.network
    );

    Ok(AttestOutput {
        attestation_pda,
        tx_b64,
        signature: None,
        expiry,
        used_memo_fallback: false,
        explorer_url,
        summary,
    })
}

/// Validate a sensor reading. Fail closed on empty sensor_id, non-finite value,
/// empty unit, or non-positive timestamp.
fn validate_reading(reading: &SensorReading) -> Result<(), AttestError> {
    if reading.sensor_id.is_empty() {
        return Err(AttestError::InvalidReading("sensor_id is empty".to_string()));
    }
    if !reading.value.is_finite() {
        return Err(AttestError::InvalidReading(format!(
            "value is not finite: {}",
            reading.value
        )));
    }
    if reading.unit.is_empty() {
        return Err(AttestError::InvalidReading("unit is empty".to_string()));
    }
    if reading.timestamp <= 0 {
        return Err(AttestError::InvalidReading(format!(
            "timestamp must be positive, got {}",
            reading.timestamp
        )));
    }
    Ok(())
}
