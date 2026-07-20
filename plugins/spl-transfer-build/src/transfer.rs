//! Pure SPL transfer builder core (T1).
//! Builds an **unsigned** legacy Solana transaction (wire format, base64).
//! No keys, no signing, no submit. HTTP via [`HttpPost`].

use std::collections::HashMap;
use std::fmt::Write as _;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};

use crate::codec::{
    blockhash_from_base58, compile_legacy_unsigned_tx, derive_ata, ix_advance_nonce,
    ix_create_ata_idempotent, ix_memo, ix_transfer_checked, looks_like_pubkey,
    mint_decimals_from_data, nonce_blockhash_from_data, ui_to_raw, Pubkey, TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const USDC_MINT_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

#[derive(Debug, Clone)]
pub struct TransferConfig {
    pub rpc_url: String,
    pub rpc_api_key: Option<String>,
    pub rpc_api_key_header: String,
    pub rpc_api_key_bearer: bool,
    pub commitment: String,
    pub max_amount: Option<f64>,
    pub allowed_mints: Vec<String>,
    /// Prefer Token-2022 program id when true (still overrideable per request).
    pub token_2022: bool,
}

impl TransferConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let rpc_url = section
            .get("rpc_url")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        let rpc_api_key = section
            .get("rpc_api_key")
            .filter(|v| !v.is_empty())
            .cloned();
        let rpc_api_key_header = section
            .get("rpc_api_key_header")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "Authorization".to_string());
        let rpc_api_key_bearer = section
            .get("rpc_api_key_bearer")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let commitment = section
            .get("commitment")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "confirmed".to_string());
        let max_amount = section
            .get("max_amount")
            .filter(|v| !v.is_empty())
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|n| n.is_finite() && *n > 0.0);
        let allowed_mints = section
            .get("allowed_mints")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let token_2022 = section
            .get("token_2022")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            rpc_url,
            rpc_api_key,
            rpc_api_key_header,
            rpc_api_key_bearer,
            commitment,
            max_amount,
            allowed_mints,
            token_2022,
        }
    }

    pub fn rpc_headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        if let Some(key) = &self.rpc_api_key {
            let value = if self.rpc_api_key_bearer && !key.starts_with("Bearer ") {
                format!("Bearer {key}")
            } else {
                key.clone()
            };
            headers.push((self.rpc_api_key_header.clone(), value));
        }
        headers
    }
}

#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Source token owner (also default fee payer / signer).
    pub from: String,
    /// Destination wallet owner (ATA derived unless destination_ata set).
    pub to: String,
    pub amount: f64,
    pub mint: String,
    pub decimals: Option<u8>,
    pub memo: Option<String>,
    pub fee_payer: Option<String>,
    /// Force Token-2022 program.
    pub token_2022: Option<bool>,
    /// Optional durable nonce account (base58). Solves blockhash expiry for approval queues.
    pub nonce_account: Option<String>,
    pub nonce_authority: Option<String>,
    /// Skip CreateIdempotent for dest ATA even if missing (fail instead).
    pub require_dest_ata: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransferBuild {
    pub unsigned_tx_base64: String,
    pub summary: String,
    pub custody_tier: &'static str,
    pub fee_payer: String,
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub mint: String,
    pub amount_raw: u64,
    pub decimals: u8,
    pub source_ata: String,
    pub destination_ata: String,
    pub create_dest_ata: bool,
    pub memo: Option<String>,
    pub recent_blockhash: String,
    pub last_valid_block_height: Option<u64>,
    pub durable_nonce: bool,
    pub signers_required: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    MissingField(&'static str),
    InvalidAddress(String),
    InvalidAmount(String),
    AmountExceedsMax { amount: String, max: String },
    MintNotAllowed(String),
    SecretsNotAccepted,
    Rpc(String),
    BadRpcResponse(String),
    Build(String),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::MissingField(k) => write!(f, "missing required field: {k}"),
            TransferError::InvalidAddress(a) => write!(f, "invalid address: {a}"),
            TransferError::InvalidAmount(a) => write!(f, "invalid amount: {a}"),
            TransferError::AmountExceedsMax { amount, max } => write!(
                f,
                "amount {amount} exceeds configured max_amount {max} — request refused"
            ),
            TransferError::MintNotAllowed(m) => {
                write!(f, "mint {m} is not on the operator allowlist — request refused")
            }
            TransferError::SecretsNotAccepted => write!(
                f,
                "this tool never accepts private keys or seed phrases — custody tier T1 (build only)"
            ),
            TransferError::Rpc(e) => write!(f, "rpc error: {e}"),
            TransferError::BadRpcResponse(e) => write!(f, "bad rpc response: {e}"),
            TransferError::Build(e) => write!(f, "build error: {e}"),
        }
    }
}

pub trait HttpPost {
    fn post_json(
        &self,
        url: &str,
        body: &str,
        headers: &[(String, String)],
    ) -> Result<String, String>;
}

/// Build an unsigned SPL transfer transaction.
pub fn build_spl_transfer<H: HttpPost>(
    http: &H,
    cfg: &TransferConfig,
    req: &TransferRequest,
) -> Result<TransferBuild, TransferError> {
    validate(req, cfg)?;

    let from = Pubkey::from_base58(&req.from).map_err(TransferError::InvalidAddress)?;
    let to = Pubkey::from_base58(&req.to).map_err(TransferError::InvalidAddress)?;
    let mint = Pubkey::from_base58(&req.mint).map_err(TransferError::InvalidAddress)?;
    let fee_payer_str = req
        .fee_payer
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(req.from.trim());
    let fee_payer =
        Pubkey::from_base58(fee_payer_str).map_err(TransferError::InvalidAddress)?;

    let use_2022 = req.token_2022.unwrap_or(cfg.token_2022);
    let token_program = if use_2022 {
        Pubkey::from_base58(TOKEN_2022_PROGRAM).map_err(TransferError::InvalidAddress)?
    } else {
        Pubkey::from_base58(TOKEN_PROGRAM).map_err(TransferError::InvalidAddress)?
    };

    let decimals = match req.decimals {
        Some(d) => d,
        None => fetch_mint_decimals(http, cfg, &mint)?,
    };
    let amount_raw =
        ui_to_raw(req.amount, decimals).map_err(TransferError::InvalidAmount)?;

    let source_ata = derive_ata(&from, &mint, &token_program).map_err(TransferError::Build)?;
    let dest_ata = derive_ata(&to, &mint, &token_program).map_err(TransferError::Build)?;

    // Source ATA must exist (we don't fund/create source here).
    if !account_exists(http, cfg, &source_ata)? {
        return Err(TransferError::Build(format!(
            "source ATA {} does not exist for owner {}",
            source_ata.to_base58(),
            from.to_base58()
        )));
    }

    let dest_exists = account_exists(http, cfg, &dest_ata)?;
    if !dest_exists && req.require_dest_ata {
        return Err(TransferError::Build(format!(
            "destination ATA {} missing and require_dest_ata=true",
            dest_ata.to_base58()
        )));
    }
    let create_dest_ata = !dest_exists;

    let (recent_blockhash, last_valid_block_height, durable_nonce, mut instructions) =
        if let Some(nonce_acc) = req
            .nonce_account
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let nonce_pk =
                Pubkey::from_base58(nonce_acc).map_err(TransferError::InvalidAddress)?;
            let authority_str = req
                .nonce_authority
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(fee_payer_str);
            let authority =
                Pubkey::from_base58(authority_str).map_err(TransferError::InvalidAddress)?;
            let data = get_account_data(http, cfg, &nonce_pk)?
                .ok_or_else(|| TransferError::Build("nonce account not found".into()))?;
            let bh = nonce_blockhash_from_data(&data).map_err(TransferError::Build)?;
            let ixs = vec![ix_advance_nonce(nonce_pk, authority)];
            (bh, None, true, ixs)
        } else {
            let (bh_b58, height) = get_latest_blockhash(http, cfg)?;
            let bh = blockhash_from_base58(&bh_b58).map_err(TransferError::Build)?;
            (bh, height, false, Vec::new())
        };

    if create_dest_ata {
        instructions.push(ix_create_ata_idempotent(
            fee_payer,
            dest_ata,
            to,
            mint,
            token_program,
        ));
    }

    instructions.push(ix_transfer_checked(
        source_ata,
        mint,
        dest_ata,
        from,
        amount_raw,
        decimals,
        token_program,
    ));

    if let Some(memo) = req.memo.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        instructions.push(ix_memo(memo));
    }

    let wire = compile_legacy_unsigned_tx(&fee_payer, &recent_blockhash, &instructions)
        .map_err(TransferError::Build)?;
    let unsigned_tx_base64 = B64.encode(&wire);

    let mut signers = vec![fee_payer.to_base58()];
    if from != fee_payer {
        signers.push(from.to_base58());
    }
    if durable_nonce {
        if let Some(auth) = req.nonce_authority.as_deref() {
            let a = auth.trim();
            if !a.is_empty() && !signers.iter().any(|s| s == a) {
                signers.push(a.to_string());
            }
        }
    }

    let bh_b58 = bs58::encode(recent_blockhash).into_string();
    let summary = format_summary(
        req.amount,
        &mint.to_base58(),
        &from.to_base58(),
        &to.to_base58(),
        create_dest_ata,
        req.memo.as_deref(),
        durable_nonce,
        &bh_b58,
    );

    Ok(TransferBuild {
        unsigned_tx_base64,
        summary,
        custody_tier: "T1",
        fee_payer: fee_payer.to_base58(),
        from: from.to_base58(),
        to: to.to_base58(),
        amount: req.amount,
        mint: mint.to_base58(),
        amount_raw,
        decimals,
        source_ata: source_ata.to_base58(),
        destination_ata: dest_ata.to_base58(),
        create_dest_ata,
        memo: req.memo.clone(),
        recent_blockhash: bh_b58,
        last_valid_block_height,
        durable_nonce,
        signers_required: signers,
    })
}

pub fn build_to_json(b: &TransferBuild) -> String {
    json!({
        "custody_tier": b.custody_tier,
        "unsigned_tx_base64": b.unsigned_tx_base64,
        "summary": b.summary,
        "fee_payer": b.fee_payer,
        "from": b.from,
        "to": b.to,
        "amount": b.amount,
        "amount_raw": b.amount_raw,
        "decimals": b.decimals,
        "mint": b.mint,
        "source_ata": b.source_ata,
        "destination_ata": b.destination_ata,
        "create_dest_ata": b.create_dest_ata,
        "memo": b.memo,
        "recent_blockhash": b.recent_blockhash,
        "last_valid_block_height": b.last_valid_block_height,
        "durable_nonce": b.durable_nonce,
        "signers_required": b.signers_required,
        "note": "Unsigned. A human or host approval gate must sign and submit. Agent holds no keys."
    })
    .to_string()
}

fn validate(req: &TransferRequest, cfg: &TransferConfig) -> Result<(), TransferError> {
    for f in [
        req.from.as_str(),
        req.to.as_str(),
        req.mint.as_str(),
        req.memo.as_deref().unwrap_or(""),
        req.fee_payer.as_deref().unwrap_or(""),
    ] {
        if looks_like_secret(f) {
            return Err(TransferError::SecretsNotAccepted);
        }
    }
    if req.from.trim().is_empty() {
        return Err(TransferError::MissingField("from"));
    }
    if req.to.trim().is_empty() {
        return Err(TransferError::MissingField("to"));
    }
    if req.mint.trim().is_empty() {
        return Err(TransferError::MissingField("mint"));
    }
    for (label, v) in [
        ("from", req.from.as_str()),
        ("to", req.to.as_str()),
        ("mint", req.mint.as_str()),
    ] {
        if !looks_like_pubkey(v) {
            return Err(TransferError::InvalidAddress(format!("{label}: {v}")));
        }
    }
    if !req.amount.is_finite() || req.amount <= 0.0 {
        return Err(TransferError::InvalidAmount(req.amount.to_string()));
    }
    if let Some(max) = cfg.max_amount {
        if req.amount > max {
            return Err(TransferError::AmountExceedsMax {
                amount: format_amount(req.amount),
                max: format_amount(max),
            });
        }
    }
    if !cfg.allowed_mints.is_empty()
        && !cfg.allowed_mints.iter().any(|m| m == &req.mint)
    {
        return Err(TransferError::MintNotAllowed(req.mint.clone()));
    }
    Ok(())
}

fn looks_like_secret(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower.contains("private key")
        || lower.contains("secret key")
        || lower.contains("seed phrase")
        || lower.contains("mnemonic")
    {
        return true;
    }
    let words: Vec<&str> = s.split_whitespace().collect();
    (words.len() == 12 || words.len() == 24)
        && words
            .iter()
            .all(|w| w.len() >= 3 && w.len() <= 8 && w.chars().all(|c| c.is_ascii_lowercase()))
}

fn format_amount(amount: f64) -> String {
    let mut s = format!("{amount:.9}");
    if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    s
}

fn format_summary(
    amount: f64,
    mint: &str,
    from: &str,
    to: &str,
    create_ata: bool,
    memo: Option<&str>,
    durable_nonce: bool,
    blockhash: &str,
) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "Unsigned SPL transfer (T1 — do not auto-sign). Send {} of mint {} from {} to {}",
        format_amount(amount),
        short(mint),
        short(from),
        short(to)
    );
    if create_ata {
        let _ = write!(s, " [will create destination ATA]");
    }
    if let Some(m) = memo {
        let _ = write!(s, ". Memo: {m}");
    }
    if durable_nonce {
        let _ = write!(s, ". Durable nonce (approval-queue safe)");
    } else {
        let _ = write!(
            s,
            ". Blockhash {}… — sign promptly or use nonce_account",
            &blockhash[..8.min(blockhash.len())]
        );
    }
    let _ = write!(s, ". No keys held; host/human must sign + submit.");
    s
}

fn short(s: &str) -> String {
    if s.len() <= 12 {
        return s.to_string();
    }
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}

// ─── RPC ────────────────────────────────────────────────────────────────────

fn rpc_call<H: HttpPost>(
    http: &H,
    cfg: &TransferConfig,
    method: &str,
    params: Value,
) -> Result<Value, TransferError> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let headers = cfg.rpc_headers();
    let raw = http
        .post_json(&cfg.rpc_url, &body, &headers)
        .map_err(TransferError::Rpc)?;
    let v: Value =
        serde_json::from_str(&raw).map_err(|e| TransferError::BadRpcResponse(e.to_string()))?;
    if let Some(err) = v.get("error") {
        return Err(TransferError::Rpc(err.to_string()));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

fn get_latest_blockhash<H: HttpPost>(
    http: &H,
    cfg: &TransferConfig,
) -> Result<(String, Option<u64>), TransferError> {
    let result = rpc_call(
        http,
        cfg,
        "getLatestBlockhash",
        json!([{ "commitment": cfg.commitment }]),
    )?;
    let blockhash = result
        .pointer("/value/blockhash")
        .and_then(|b| b.as_str())
        .ok_or_else(|| TransferError::BadRpcResponse("missing blockhash".into()))?
        .to_string();
    let height = result
        .pointer("/value/lastValidBlockHeight")
        .and_then(|h| h.as_u64());
    Ok((blockhash, height))
}

fn get_account_data<H: HttpPost>(
    http: &H,
    cfg: &TransferConfig,
    pubkey: &Pubkey,
) -> Result<Option<Vec<u8>>, TransferError> {
    let result = rpc_call(
        http,
        cfg,
        "getAccountInfo",
        json!([
            pubkey.to_base58(),
            { "encoding": "base64", "commitment": cfg.commitment }
        ]),
    )?;
    if result.is_null() {
        return Ok(None);
    }
    let value = result.get("value");
    if value.map(|v| v.is_null()).unwrap_or(true) {
        return Ok(None);
    }
    let b64 = value
        .and_then(|v| v.pointer("/data/0"))
        .and_then(|d| d.as_str())
        .ok_or_else(|| TransferError::BadRpcResponse("account data missing".into()))?;
    let bytes = B64
        .decode(b64)
        .map_err(|e| TransferError::BadRpcResponse(format!("account b64: {e}")))?;
    Ok(Some(bytes))
}

fn account_exists<H: HttpPost>(
    http: &H,
    cfg: &TransferConfig,
    pubkey: &Pubkey,
) -> Result<bool, TransferError> {
    Ok(get_account_data(http, cfg, pubkey)?.is_some())
}

fn fetch_mint_decimals<H: HttpPost>(
    http: &H,
    cfg: &TransferConfig,
    mint: &Pubkey,
) -> Result<u8, TransferError> {
    let data = get_account_data(http, cfg, mint)?
        .ok_or_else(|| TransferError::Build(format!("mint account not found: {}", mint.to_base58())))?;
    mint_decimals_from_data(&data).map_err(TransferError::Build)
}
