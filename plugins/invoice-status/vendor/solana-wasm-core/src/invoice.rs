//! High-level pure API for dual-rail BRL/USDC invoices.

use crate::amount::{brl_to_usdc, parse_decimal, within_cap};
use crate::pix::{build_pix_payload, PixParams};
use crate::reference::derive_reference;
use crate::shape::short_label;
use crate::solana_pay::{build_solana_pay_url, is_valid_base58_pubkey, SolanaPayParams, USDC_MINT};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Merchant / plugin configuration for invoice issuance.
#[derive(Debug, Clone)]
pub struct InvoiceConfig {
    pub pix_key: String,
    pub pix_name: String,
    pub pix_city: String,
    pub merchant_solana: String,
    pub usdc_mint: String,
    pub max_amount_brl: String,
    pub max_amount_usdc: String,
    /// BRL per 1 USDC (offline default 5.5).
    pub brl_per_usdc: String,
    /// When true, merchant recipient always comes from config (ignore overrides).
    pub recipient_locked: bool,
    /// Comma-separated allowlist of mint addresses; empty = only mainnet USDC.
    pub allowed_mints: Vec<String>,
}

impl Default for InvoiceConfig {
    fn default() -> Self {
        Self {
            pix_key: String::new(),
            pix_name: String::new(),
            pix_city: String::new(),
            merchant_solana: String::new(),
            usdc_mint: USDC_MINT.to_string(),
            max_amount_brl: "10000".to_string(),
            max_amount_usdc: "2000".to_string(),
            brl_per_usdc: "5.5".to_string(),
            recipient_locked: true,
            allowed_mints: vec![USDC_MINT.to_string()],
        }
    }
}

impl InvoiceConfig {
    /// Build config from a string map (plugin `__config` style) with defaults.
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        let mut cfg = Self::default();

        if let Some(v) = map.get("pix_key") {
            cfg.pix_key = v.clone();
        }
        if let Some(v) = map.get("pix_name") {
            cfg.pix_name = v.clone();
        }
        if let Some(v) = map.get("pix_city") {
            cfg.pix_city = v.clone();
        }
        if let Some(v) = map.get("merchant_solana") {
            cfg.merchant_solana = v.clone();
        }
        if let Some(v) = map.get("usdc_mint") {
            cfg.usdc_mint = v.clone();
        }
        if let Some(v) = map.get("max_amount_brl") {
            cfg.max_amount_brl = v.clone();
        }
        if let Some(v) = map.get("max_amount_usdc") {
            cfg.max_amount_usdc = v.clone();
        }
        if let Some(v) = map.get("brl_per_usdc") {
            cfg.brl_per_usdc = v.clone();
        }
        if let Some(v) = map.get("recipient_locked") {
            cfg.recipient_locked = parse_bool(v);
        }
        if let Some(v) = map.get("allowed_mints") {
            cfg.allowed_mints = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if cfg.allowed_mints.is_empty() {
                cfg.allowed_mints = vec![USDC_MINT.to_string()];
            }
        }
        cfg
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Invoice issuance request from the agent / tool call.
#[derive(Debug, Clone)]
pub struct InvoiceRequest {
    pub amount_brl: String,
    pub invoice_id: String,
    pub description: Option<String>,
    pub payer_name: Option<String>,
    /// Optional explicit USDC amount; otherwise derived from BRL / rate.
    pub usdc_amount: Option<String>,
    /// Optional merchant override — ignored when `recipient_locked`.
    pub merchant_override: Option<String>,
    /// Optional mint override — must be in `allowed_mints`.
    pub mint_override: Option<String>,
}

impl InvoiceRequest {
    pub fn new(amount_brl: impl Into<String>, invoice_id: impl Into<String>) -> Self {
        Self {
            amount_brl: amount_brl.into(),
            invoice_id: invoice_id.into(),
            description: None,
            payer_name: None,
            usdc_amount: None,
            merchant_override: None,
            mint_override: None,
        }
    }
}

/// Result of a successful invoice build.
#[derive(Debug, Clone)]
pub struct InvoiceResult {
    pub pix_payload: String,
    pub solana_pay_url: String,
    pub reference: String,
    pub memo: String,
    pub amount_brl: String,
    pub amount_usdc: String,
    pub summary: String,
}

/// Build dual-rail invoice payloads with caps and allowlists enforced.
///
/// `issued_at_unix_ms` is the moment of issuance, in unix milliseconds. The
/// core reads no clock — the caller (the plugin's wasm shim) supplies it — and
/// it is used for exactly one thing: salting the **auto-generated** invoice id
/// so two identical charges issued at different moments never collide. See
/// [`auto_invoice_id`]. An `invoice_id` supplied by the caller is used
/// verbatim and the timestamp does not touch it, so the reference of an
/// explicit id stays reproducible from the id alone.
pub fn build_invoice(
    req: &InvoiceRequest,
    cfg: &InvoiceConfig,
    issued_at_unix_ms: i64,
) -> Result<InvoiceResult, String> {
    // --- Validate required config ---
    if cfg.pix_key.trim().is_empty() {
        return Err("pix_key is required in config".into());
    }
    if cfg.pix_name.trim().is_empty() {
        return Err("pix_name is required in config".into());
    }
    if cfg.pix_city.trim().is_empty() {
        return Err("pix_city is required in config".into());
    }
    if cfg.merchant_solana.trim().is_empty() {
        return Err("merchant_solana is required in config".into());
    }

    // --- Amount BRL ---
    let amount_brl = req.amount_brl.trim();
    parse_decimal(amount_brl, 2).map_err(|e| format!("invalid amount_brl: {e}"))?;
    // Normalize display to 2 dp
    let amount_brl_fmt = crate::amount::format_brl(
        &parse_decimal(amount_brl, 2).map_err(|e| format!("invalid amount_brl: {e}"))?,
    );

    let under_brl = within_cap(amount_brl, &cfg.max_amount_brl, 2)
        .map_err(|e| format!("max_amount_brl invalid: {e}"))?;
    if !under_brl {
        return Err(format!(
            "amount_brl {amount_brl_fmt} exceeds max_amount_brl {}",
            cfg.max_amount_brl
        ));
    }

    // --- Recipient (merchant) ---
    let merchant = if cfg.recipient_locked {
        cfg.merchant_solana.clone()
    } else if let Some(ref ov) = req.merchant_override {
        if !ov.trim().is_empty() {
            ov.trim().to_string()
        } else {
            cfg.merchant_solana.clone()
        }
    } else {
        cfg.merchant_solana.clone()
    };

    if !is_valid_base58_pubkey(&merchant) {
        return Err(format!("invalid merchant_solana pubkey: {merchant}"));
    }

    // --- Invoice id (explicit, or auto INV-XXXXXXXX salted with issuance time) ---
    let invoice_id = if req.invoice_id.trim().is_empty() {
        // The salt is the only thing separating two identical charges. Without
        // a usable clock it is not there, and minting an id anyway would
        // silently restore the collision this parameter exists to prevent —
        // so fail closed and say what the caller has to do instead.
        if issued_at_unix_ms < MIN_ISSUED_AT_UNIX_MS {
            return Err(NO_CLOCK_ERROR.into());
        }
        auto_invoice_id(
            &amount_brl_fmt,
            req.description.as_deref(),
            &merchant,
            issued_at_unix_ms,
        )
    } else {
        req.invoice_id.trim().to_string()
    };

    // --- Mint allowlist (alias USDC → mainnet mint) ---
    let mint = if let Some(ref ov) = req.mint_override {
        if !ov.trim().is_empty() {
            resolve_mint_alias(ov.trim())
        } else {
            cfg.usdc_mint.clone()
        }
    } else {
        cfg.usdc_mint.clone()
    };

    let mint_allowed = cfg
        .allowed_mints
        .iter()
        .any(|m| m == &mint || resolve_mint_alias(m) == mint);
    if !mint_allowed {
        return Err(format!(
            "mint {mint} is not in allowed_mints {:?}",
            cfg.allowed_mints
        ));
    }

    // --- USDC amount ---
    let amount_usdc = if let Some(ref u) = req.usdc_amount {
        let u = u.trim();
        parse_decimal(u, 6).map_err(|e| format!("invalid usdc_amount: {e}"))?;
        crate::amount::format_usdc(&parse_decimal(u, 6).unwrap())
    } else {
        brl_to_usdc(&amount_brl_fmt, &cfg.brl_per_usdc)
            .map_err(|e| format!("failed to convert BRL→USDC: {e}"))?
    };

    let under_usdc = within_cap(&amount_usdc, &cfg.max_amount_usdc, 6)
        .map_err(|e| format!("max_amount_usdc invalid: {e}"))?;
    if !under_usdc {
        return Err(format!(
            "amount_usdc {amount_usdc} exceeds max_amount_usdc {}",
            cfg.max_amount_usdc
        ));
    }

    // --- Memo ---
    let short = req
        .description
        .as_deref()
        .map(|d| short_label(d, 24))
        .filter(|s| !s.is_empty())
        .or_else(|| {
            req.payer_name
                .as_deref()
                .map(|p| short_label(p, 24))
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "invoice".to_string());

    let memo = format!("PIX|BRL|{invoice_id}|{short}");

    // --- Reference ---
    let reference = derive_reference(&invoice_id, &merchant);

    // --- PIX ---
    let pix_payload = build_pix_payload(&PixParams {
        pix_key: cfg.pix_key.trim(),
        merchant_name: cfg.pix_name.trim(),
        merchant_city: cfg.pix_city.trim(),
        amount: Some(&amount_brl_fmt),
        txid: &invoice_id,
    });

    // --- Solana Pay ---
    let label = Some(cfg.pix_name.trim());
    let message = Some(invoice_id.as_str());
    let solana_pay_url = build_solana_pay_url(&SolanaPayParams {
        recipient: &merchant,
        amount: &amount_usdc,
        spl_token: &mint,
        reference: &reference,
        label,
        message,
        memo: Some(&memo),
    })?;

    let summary = format!(
        "INVOICE #{invoice_id} · R$ {amount_brl_fmt} ≈ {amount_usdc} USDC · recipient_locked={}",
        cfg.recipient_locked
    );

    Ok(InvoiceResult {
        pix_payload,
        solana_pay_url,
        reference,
        memo,
        amount_brl: amount_brl_fmt,
        amount_usdc,
        summary,
    })
}

/// Resolve mint aliases used by agents (`USDC` → mainnet mint).
pub fn resolve_mint_alias(raw: &str) -> String {
    match raw.trim().to_ascii_uppercase().as_str() {
        "USDC" => USDC_MINT.to_string(),
        _ => raw.trim().to_string(),
    }
}

/// Earliest issuance instant accepted when minting an automatic invoice id:
/// 2020-01-01T00:00:00Z in unix milliseconds.
///
/// A clock that reads `0` (or anything before this) is a broken clock, not an
/// old invoice. Accepting it would mean every auto id for that host collapses
/// to the same value again.
const MIN_ISSUED_AT_UNIX_MS: i64 = 1_577_836_800_000;

/// Returned instead of minting an automatic id without a usable clock.
const NO_CLOCK_ERROR: &str = "cannot mint a unique invoice_id: no usable clock \
    (issued_at_unix_ms is not a plausible timestamp). \
    Pass an explicit, unique invoice_id.";

/// Auto-generated invoice id, salted with the issuance instant.
///
/// `sha256("zc-auto-inv-v2" | amount | "|" | description | "|" | merchant |
/// "|" | issued_at_unix_ms)`, first 4 bytes as hex.
///
/// **Why the timestamp.** Without it the id was a pure function of the charge:
/// two "R$ 10, no description" invoices raised on different days produced the
/// same `INV-XXXXXXXX`, hence the same reference, hence yesterday's payment
/// marking today's invoice `PAID ✅` with a receipt issued. No attacker
/// required — charging the same amount twice was enough. The instant of
/// issuance is the one thing that always differs between two sales, so it is
/// what the id is salted with.
///
/// Milliseconds, not seconds: two identical charges a second apart is an
/// ordinary thing for a merchant to do, and the shim can read a millisecond
/// clock just as cheaply. Two identical charges within the *same millisecond*
/// still collide — for that volume, pass an explicit unique `invoice_id`.
///
/// The digest is truncated to 4 bytes to keep the `INV-XXXXXXXX` shape the
/// merchant reads aloud and types back. That is 2³² ids, so a merchant issuing
/// tens of thousands of *automatic* invoices should expect a birthday
/// collision eventually and use explicit ids; the salt removes the systematic
/// collision, not the probabilistic one.
///
/// The version tag moved to `v2` because the derivation changed; ids minted by
/// the old scheme are not reproducible here, which is the point.
fn auto_invoice_id(
    amount_brl: &str,
    description: Option<&str>,
    merchant: &str,
    issued_at_unix_ms: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zc-auto-inv-v2");
    hasher.update(amount_brl.as_bytes());
    hasher.update(b"|");
    hasher.update(description.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(merchant.as_bytes());
    hasher.update(b"|");
    hasher.update(issued_at_unix_ms.to_be_bytes());
    let dig = hasher.finalize();
    // 4 bytes → 8 hex chars
    format!(
        "INV-{:02X}{:02X}{:02X}{:02X}",
        dig[0], dig[1], dig[2], dig[3]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const MERCHANT: &str = "11111111111111111111111111111112";
    /// Fixed issuance instant so every id-independent test stays deterministic.
    const T0: i64 = 1_700_000_000_000;

    fn test_cfg() -> InvoiceConfig {
        let mut map = HashMap::new();
        map.insert("pix_key".into(), "merchant@example.com".into());
        map.insert("pix_name".into(), "Loja Demo".into());
        map.insert("pix_city".into(), "Sao Paulo".into());
        map.insert("merchant_solana".into(), MERCHANT.into());
        map.insert("max_amount_brl".into(), "1000".into());
        map.insert("max_amount_usdc".into(), "200".into());
        map.insert("recipient_locked".into(), "true".into());
        map.insert("brl_per_usdc".into(), "5.5".into());
        InvoiceConfig::from_map(&map)
    }

    #[test]
    fn build_invoice_happy_path() {
        let cfg = test_cfg();
        let req = InvoiceRequest {
            amount_brl: "150.00".into(),
            invoice_id: "inv-001".into(),
            description: Some("Pedido teste".into()),
            payer_name: None,
            usdc_amount: None,
            merchant_override: None,
            mint_override: None,
        };
        let result = build_invoice(&req, &cfg, T0).unwrap();
        assert!(result.pix_payload.starts_with("000201"));
        assert!(result.pix_payload.contains("6304"));
        let crc = &result.pix_payload[result.pix_payload.len() - 4..];
        assert!(crc.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')));

        assert!(result
            .solana_pay_url
            .starts_with(&format!("solana:{MERCHANT}?")));
        assert!(result.solana_pay_url.contains("amount=27.272727"));
        assert!(result.solana_pay_url.contains(USDC_MINT));
        assert!(result
            .solana_pay_url
            .contains(&format!("reference={}", result.reference)));
        assert_eq!(result.memo, "PIX|BRL|inv-001|Pedido teste");
        assert_eq!(result.amount_brl, "150.00");
        assert_eq!(result.amount_usdc, "27.272727");
        assert!(result.summary.contains("INVOICE #inv-001"));
    }

    #[test]
    fn auto_invoice_id_when_empty() {
        let cfg = test_cfg();
        let mut req = InvoiceRequest::new("10.00", "");
        req.description = Some("x".into());
        let result = build_invoice(&req, &cfg, T0).unwrap();
        assert!(result.memo.starts_with("PIX|BRL|INV-"));
        assert!(result.summary.contains("INVOICE #INV-"));
    }

    /// Extract the id the builder used, from the memo `PIX|BRL|<id>|<label>`.
    fn id_of(r: &InvoiceResult) -> String {
        r.memo.split('|').nth(2).unwrap().to_string()
    }

    /// FURO B: the same charge raised at two different moments must be two
    /// different invoices. Before the salt, "cobra R$ 10" twice produced one
    /// id, one reference, and yesterday's payment settled today's invoice.
    #[test]
    fn auto_invoice_id_differs_across_issuance_instants() {
        let cfg = test_cfg();
        let req = InvoiceRequest::new("10.00", ""); // no description, worst case

        let today = build_invoice(&req, &cfg, T0).unwrap();
        let tomorrow = build_invoice(&req, &cfg, T0 + 86_400_000).unwrap();

        assert_ne!(id_of(&today), id_of(&tomorrow), "auto ids must not collide");
        assert_ne!(
            today.reference, tomorrow.reference,
            "distinct ids must give distinct references, or the payment for one \
             settles the other"
        );

        // One millisecond apart is already enough.
        let a = build_invoice(&req, &cfg, T0).unwrap();
        let b = build_invoice(&req, &cfg, T0 + 1).unwrap();
        assert_ne!(id_of(&a), id_of(&b));
    }

    /// The salt is only entropy, not a source of nondeterminism: the same
    /// inputs *and* the same instant still reproduce the same invoice.
    #[test]
    fn auto_invoice_id_is_deterministic_for_a_fixed_instant() {
        let cfg = test_cfg();
        let mut req = InvoiceRequest::new("10.00", "");
        req.description = Some("cafe".into());
        let a = build_invoice(&req, &cfg, T0).unwrap();
        let b = build_invoice(&req, &cfg, T0).unwrap();
        assert_eq!(id_of(&a), id_of(&b));
        assert_eq!(a.reference, b.reference);
    }

    /// An explicit id is the merchant's business: used verbatim, never salted,
    /// so its reference stays reproducible from the id alone — which is what
    /// `invoice_status` recomputes when the merchant types the id back.
    #[test]
    fn explicit_invoice_id_ignores_the_issuance_instant() {
        let cfg = test_cfg();
        let req = InvoiceRequest::new("10.00", "inv-explicit");

        let a = build_invoice(&req, &cfg, T0).unwrap();
        let b = build_invoice(&req, &cfg, T0 + 999_999_999).unwrap();

        assert_eq!(id_of(&a), "inv-explicit");
        assert_eq!(id_of(&b), "inv-explicit");
        assert_eq!(a.reference, b.reference);
        assert_eq!(a.reference, derive_reference("inv-explicit", MERCHANT));
    }

    /// Without a usable clock there is no salt, and an unsalted auto id is the
    /// bug. Fail the call with an actionable message instead of minting it.
    #[test]
    fn auto_invoice_id_refuses_a_broken_clock() {
        let cfg = test_cfg();
        let req = InvoiceRequest::new("10.00", "");
        for bad in [0, -1, 1_699_999i64] {
            let err = build_invoice(&req, &cfg, bad).unwrap_err();
            assert!(err.contains("unique invoice_id"), "{bad}: {err}");
            assert!(err.contains("explicit"), "{bad}: {err}");
        }
        // An explicit id needs no clock at all.
        let ok = build_invoice(&InvoiceRequest::new("10.00", "inv-x"), &cfg, 0).unwrap();
        assert_eq!(id_of(&ok), "inv-x");
    }

    /// The reference derivation itself is untouched by this fix: it is still a
    /// pure function of (invoice_id, merchant), which the video demo and
    /// `invoice_status` both depend on.
    #[test]
    fn reference_derivation_unchanged_and_reproducible_from_id() {
        let cfg = test_cfg();
        let auto = build_invoice(&InvoiceRequest::new("10.00", ""), &cfg, T0).unwrap();
        // Even for an auto id, once you know the id you can re-derive the ref.
        assert_eq!(auto.reference, derive_reference(&id_of(&auto), MERCHANT));
    }

    #[test]
    fn mint_alias_usdc() {
        let cfg = test_cfg();
        let mut req = InvoiceRequest::new("10.00", "inv-alias");
        req.mint_override = Some("USDC".into());
        let result = build_invoice(&req, &cfg, T0).unwrap();
        assert!(result.solana_pay_url.contains(USDC_MINT));
    }

    #[test]
    fn rejects_over_max_amount_brl() {
        let cfg = test_cfg();
        let req = InvoiceRequest::new("1000.01", "inv-big");
        let err = build_invoice(&req, &cfg, T0).unwrap_err();
        assert!(
            err.contains("exceeds max_amount_brl"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn recipient_locked_ignores_override() {
        let cfg = test_cfg();
        assert!(cfg.recipient_locked);

        // A different valid-looking base58 32-byte key (Token Program).
        let other = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let mut req = InvoiceRequest::new("10.00", "inv-lock");
        req.merchant_override = Some(other.into());

        let result = build_invoice(&req, &cfg, T0).unwrap();
        assert!(
            result
                .solana_pay_url
                .starts_with(&format!("solana:{MERCHANT}?")),
            "locked recipient should stay config merchant, got {}",
            result.solana_pay_url
        );
        assert!(!result.solana_pay_url.contains(other));

        // Reference must also use locked merchant
        let expected_ref = derive_reference("inv-lock", MERCHANT);
        assert_eq!(result.reference, expected_ref);
    }

    #[test]
    fn rejects_disallowed_mint() {
        let cfg = test_cfg();
        let mut req = InvoiceRequest::new("10.00", "inv-mint");
        req.mint_override = Some("So11111111111111111111111111111111111111112".into());
        let err = build_invoice(&req, &cfg, T0).unwrap_err();
        assert!(err.contains("not in allowed_mints"), "got {err}");
    }

    #[test]
    fn explicit_usdc_amount() {
        let cfg = test_cfg();
        let mut req = InvoiceRequest::new("55.00", "inv-u");
        req.usdc_amount = Some("10".into());
        let result = build_invoice(&req, &cfg, T0).unwrap();
        assert_eq!(result.amount_usdc, "10");
        assert!(result.solana_pay_url.contains("amount=10"));
    }
}
