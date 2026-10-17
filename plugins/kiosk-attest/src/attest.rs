//! Pure attestation core. No wasm dependency — RPC mocked in host tests.
//!
//! Custody: T1. This module holds no key and signs nothing. It builds an
//! UNSIGNED transaction from exactly two instructions — System `AdvanceNonceAccount`
//! (durable nonce) and SPL Memo (the hash-chained attestation record) — and hands
//! back its base64 message for an external operator signer. A transfer is not
//! constructed anywhere, so even a fully compromised model cannot make this
//! plugin emit a spend (proven by `tx_contains_only_memo_and_system_programs`).

use std::collections::HashMap;

use serde_json::{json, Value};

use kiosk_core::msg::Message;
use kiosk_core::rpc::{RpcClient, RpcError, RpcTransport};
use kiosk_core::{b58, chain, memo, nonce, shape};

pub const MEMO_VERSION: u32 = 1;
pub const DEFAULT_FINALITY: &str = "confirmed";

#[derive(Debug)]
pub struct AttestConfig {
    pub rpc_url: String,
    pub device_id: String,
    pub nonce_account: String,
    pub nonce_authority: String,
    /// metric name -> inclusive [min, max] bounds.
    pub allowed_metrics: HashMap<String, (f64, f64)>,
    pub custody_mode: String,
}

impl AttestConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, AttestError> {
        let get_req = |k: &str| {
            section
                .get(k)
                .filter(|v| !v.is_empty())
                .cloned()
                .ok_or_else(|| AttestError::Config(format!("{k} is required")))
        };
        let rpc_url = get_req("rpc_url")?;
        let device_id = get_req("device_id")?;
        let nonce_account = get_req("nonce_account")?;
        let nonce_authority = get_req("nonce_authority")?;
        if b58::decode_pubkey(&nonce_account).is_none() {
            return Err(AttestError::Config(
                "nonce_account is not a valid pubkey".into(),
            ));
        }
        if b58::decode_pubkey(&nonce_authority).is_none() {
            return Err(AttestError::Config(
                "nonce_authority is not a valid pubkey".into(),
            ));
        }
        let mut allowed_metrics = HashMap::new();
        if let Some(raw) = section.get("allowed_metrics") {
            for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                let parts: Vec<&str> = entry.split(':').map(str::trim).collect();
                if parts.len() != 3 {
                    return Err(AttestError::Config(format!(
                        "bad allowed_metrics entry `{entry}` (want name:min:max)"
                    )));
                }
                let min = parts[1]
                    .parse::<f64>()
                    .map_err(|_| AttestError::Config(format!("bad min in `{entry}`")))?;
                let max = parts[2]
                    .parse::<f64>()
                    .map_err(|_| AttestError::Config(format!("bad max in `{entry}`")))?;
                if min > max {
                    return Err(AttestError::Config(format!("min > max in `{entry}`")));
                }
                allowed_metrics.insert(parts[0].to_string(), (min, max));
            }
        }
        let custody_mode = section
            .get("custody_mode")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "t1".to_string());
        Ok(Self {
            rpc_url,
            device_id,
            nonce_account,
            nonce_authority,
            allowed_metrics,
            custody_mode,
        })
    }
}

/// Model-facing arguments. `deny_unknown_fields` makes a smuggled `recipient`,
/// `nonce_authority`, … a hard deserialization error.
#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct AttestArgs {
    /// "reading" (default) or "event".
    pub kind: Option<String>,
    pub metric: Option<String>,
    pub value: Option<f64>,
    pub ts: Option<u64>,
    pub event: Option<String>,
    pub payment_sig: Option<String>,
    pub item: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum AttestError {
    Config(String),
    Args(String),
    /// A caller value failed the operator allowlist/bounds — refuse to attest a lie.
    Rejected(String),
    Rpc(String),
    Decode(String),
}

impl core::fmt::Display for AttestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AttestError::Config(m) => write!(f, "config error: {m}"),
            AttestError::Args(m) => write!(f, "invalid request: {m}"),
            AttestError::Rejected(m) => write!(f, "reading rejected: {m}"),
            AttestError::Rpc(m) => write!(f, "rpc error: {m}"),
            AttestError::Decode(m) => write!(f, "malformed rpc response: {m}"),
        }
    }
}

#[derive(Debug)]
pub struct AttestOutput {
    /// Base64 of the UNSIGNED serialized message (0 signatures attached).
    pub tx_base64: String,
    pub seq: u64,
    pub message: Message,
    pub summary: String,
}

impl AttestOutput {
    /// The unique program ids invoked by the built transaction. The safety
    /// invariant: this is exactly {System, Memo} — no transfer/token program.
    pub fn program_ids(&self) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = self
            .message
            .instructions
            .iter()
            .map(|ci| self.message.account_keys[ci.program_id_index as usize])
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

/// Build the unsigned attestation transaction. Validation happens BEFORE any
/// RPC; any RPC/decode failure returns `Err` (never a "successful" attestation).
pub fn execute_attest<T: RpcTransport>(
    args: &AttestArgs,
    cfg: &AttestConfig,
    transport: T,
    now: u64,
) -> Result<AttestOutput, AttestError> {
    let ts = args.ts.unwrap_or(now);
    let kind = args.kind.as_deref().unwrap_or("reading");

    // 1. Validate the payload against the operator allowlist FIRST (fail closed).
    let (body, detail) = match kind {
        "reading" => {
            let metric = args
                .metric
                .as_deref()
                .ok_or_else(|| AttestError::Args("metric is required for a reading".into()))?;
            let value = args
                .value
                .ok_or_else(|| AttestError::Args("value is required for a reading".into()))?;
            let (min, max) = cfg.allowed_metrics.get(metric).ok_or_else(|| {
                AttestError::Rejected(format!("metric `{metric}` not in allowlist"))
            })?;
            if !value.is_finite() {
                return Err(AttestError::Rejected("value must be finite".into()));
            }
            if value < *min || value > *max {
                return Err(AttestError::Rejected(format!(
                    "value {value} outside [{min}, {max}]"
                )));
            }
            (
                json!({ "metric": metric, "val": value }),
                format!("metric={metric} val={value}"),
            )
        }
        "event" => {
            let event = args
                .event
                .as_deref()
                .ok_or_else(|| AttestError::Args("event is required for an event".into()))?;
            let mut b = json!({ "event": event });
            if let Some(item) = &args.item {
                b["item"] = json!(item);
            }
            if let Some(sig) = &args.payment_sig {
                b["payment_sig"] = json!(sig);
            }
            (b, format!("event={event}"))
        }
        other => return Err(AttestError::Args(format!("unknown kind `{other}`"))),
    };

    let nonce_account = b58::decode_pubkey(&cfg.nonce_account)
        .ok_or_else(|| AttestError::Config("nonce_account invalid".into()))?;
    let nonce_authority = b58::decode_pubkey(&cfg.nonce_authority)
        .ok_or_else(|| AttestError::Config("nonce_authority invalid".into()))?;

    // 2. Recover chain seq/prev in one RPC call (getSignaturesForAddress).
    let state =
        chain::recover(&cfg.nonce_account, &transport, DEFAULT_FINALITY).map_err(|e| match e {
            chain::ChainError::Rpc(m) => AttestError::Rpc(m),
            chain::ChainError::Decode(m) => AttestError::Decode(m),
            chain::ChainError::Gap(m) => AttestError::Rejected(format!("chain gap: {m}")),
        })?;

    // 3. Read the durable nonce's stored blockhash (getAccountInfo).
    let client = RpcClient::new(&transport);
    let info = client
        .call(
            "getAccountInfo",
            json!([cfg.nonce_account, { "encoding": "base64", "commitment": DEFAULT_FINALITY }]),
        )
        .map_err(map_rpc)?;
    let data_b64 = info
        .get("value")
        .and_then(|v| v.get("data"))
        .and_then(|d| d.get(0))
        .and_then(Value::as_str)
        .ok_or_else(|| AttestError::Rpc("nonce account not found or has no data".into()))?;
    let na = nonce::parse_nonce_account(data_b64)
        .ok_or_else(|| AttestError::Decode("account is not a valid durable nonce".into()))?;
    if na.authority != nonce_authority {
        return Err(AttestError::Config(
            "configured nonce_authority does not own the nonce account".into(),
        ));
    }

    // 4. Assemble the hash-chained memo record.
    let mut memo_val =
        json!({ "v": MEMO_VERSION, "dev": cfg.device_id, "seq": state.seq, "ts": ts });
    if let (Value::Object(m), Value::Object(b)) = (&mut memo_val, &body) {
        for (k, v) in b {
            m.insert(k.clone(), v.clone());
        }
    }
    memo_val["prev"] = match &state.prev_signature {
        Some(s) => json!(s),
        None => Value::Null,
    };
    let memo_json = memo_val.to_string();

    // 5. Compile [advance-nonce, memo] into an UNSIGNED message on the durable nonce.
    let advance = nonce::build_advance_nonce_ix(nonce_account, nonce_authority);
    let memo_ix = memo::build_memo_ix(&memo_json);
    let message = Message::compile(&[advance, memo_ix], nonce_authority, na.blockhash);
    let tx_base64 = message.to_base64();

    // 6. Summary: status only, no secrets, no rpc_url.
    let summary = shape::clamp(
        &format!(
            "ATTESTED {kind} seq={} {detail} ts={ts} — unsigned durable-nonce tx built ({} bytes), ready for the operator signer.",
            state.seq,
            message.serialize().len()
        ),
        shape::DEFAULT_BUDGET_TOKENS,
    );

    Ok(AttestOutput {
        tx_base64,
        seq: state.seq,
        message,
        summary,
    })
}

fn map_rpc(e: RpcError) -> AttestError {
    match e {
        RpcError::Transport(m) => AttestError::Rpc(m),
        RpcError::Rpc { code, message } => AttestError::Rpc(format!("{code}: {message}")),
        RpcError::Decode(m) => AttestError::Decode(m),
    }
}
