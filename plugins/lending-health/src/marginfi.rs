//! MarginFi data path: `getProgramAccounts` request construction and raw
//! account decoding at fixed byte offsets.
//!
//! Offsets derive from the marginfi-v2 type crate (commit d4c70c8) and were
//! sanity-checked on 2026-07-18 by decoding a live mainnet account and
//! cross-checking the group and authority fields against a second RPC read.
//! `tests/fixtures/marginfi_gpa_response.json` is that live capture; the
//! `_maint_synthetic` fixture beside it is hand-built, not captured.

use base64::Engine;
use serde_json::Value;

use crate::health::{short_account, Liquidation, Position, Protocol};

pub const MARGINFI_PROGRAM: &str = "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA";

/// First 8 bytes of every MarginfiAccount: sha256("account:MarginfiAccount")
/// truncated, base58-encoded for the memcmp filter.
pub const ACCOUNT_DISCRIMINATOR_B58: &str = "CKkRR4La3xu";

/// On-chain size of a MarginfiAccount: 8-byte discriminator + 2304 struct.
pub const ACCOUNT_SIZE: u64 = 2312;

const OFFSET_AUTHORITY: usize = 40;
const OFFSET_ASSET_VALUE: usize = 1840;
const OFFSET_LIABILITY_VALUE: usize = 1856;
const OFFSET_ASSET_VALUE_MAINT: usize = 1872;
const OFFSET_LIABILITY_VALUE_MAINT: usize = 1888;
const OFFSET_FLAGS: usize = 1944;

/// The risk engine's own verdict on the account.
const FLAG_HEALTHY: u32 = 1;
/// Set when the engine's last risk check ran through, so the rest of the
/// cache and the verdict above it were written by that run.
const FLAG_ENGINE_STATUS_OK: u32 = 2;
/// Set when every oracle the account depends on priced within its age limit.
const FLAG_ORACLE_OK: u32 = 4;

/// JSON-RPC body for `getProgramAccounts` filtered down to the marginfi
/// accounts owned by one authority. The filters mirror the live-verified
/// query: exact size, account discriminator, authority at offset 40.
pub fn gpa_request_body(authority_pubkey: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getProgramAccounts",
        "params": [
            MARGINFI_PROGRAM,
            {
                "encoding": "base64",
                "filters": [
                    { "dataSize": ACCOUNT_SIZE },
                    { "memcmp": { "offset": 0, "bytes": ACCOUNT_DISCRIMINATOR_B58 } },
                    { "memcmp": { "offset": OFFSET_AUTHORITY, "bytes": authority_pubkey } }
                ]
            }
        ]
    })
    .to_string()
}

/// The 8-byte Anchor discriminator of a MarginfiAccount, decoded once from the
/// base58 form the request filter uses.
fn discriminator_matches(data: &[u8]) -> bool {
    let mut expected = [0u8; 8];
    match bs58::decode(ACCOUNT_DISCRIMINATOR_B58).onto(&mut expected) {
        Ok(8) => data[..8] == expected,
        // An unparseable constant is a build-time mistake rather than a hostile
        // reply, and refusing every account would be worse than not checking.
        _ => true,
    }
}

/// Longest upstream error text the report will carry.
const MAX_UPSTREAM_MSG: usize = 160;

/// Renders a message chosen by the RPC endpoint as an explicit quotation.
///
/// The `error.message` field of a JSON-RPC reply is written by whoever runs that
/// endpoint, and it lands in text an LLM reads. An endpoint that is hostile,
/// compromised, or sitting behind an interception proxy can put a sentence there
/// and have it relayed into the agent's context verbatim. Marking the text as a
/// quotation, stripping control characters that would break the report's line
/// structure, and capping the length leaves the diagnostic value intact while
/// denying the foothold.
fn quote_upstream(msg: &str) -> String {
    // The double quote is folded to a single one: the text is wrapped in
    // quotation marks, and a quote inside it would close that wrapper early and
    // let the rest of an upstream-chosen sentence read as our own words.
    // `is_control` covers the Cc category only. U+2028 and U+2029 are Zl and Zp,
    // they break a line in most renderers, and this text lands in a
    // line-structured report where one smuggled break forges a row.
    let cleaned: String = msg
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{2028}' | '\u{2029}'))
        .map(|c| if c == '"' { '\'' } else { c })
        .take(MAX_UPSTREAM_MSG)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "upstream sent an empty message".to_string()
    } else {
        format!("upstream said: \"{trimmed}\"")
    }
}

/// Parses a `getProgramAccounts` response into normalized positions, one per
/// marginfi account. Accounts with no value on either side are skipped.
pub fn parse_gpa_response(body: &str, wallet_label: &str) -> Result<Vec<Position>, String> {
    let root: Value =
        serde_json::from_str(body).map_err(|e| format!("marginfi RPC reply is not JSON: {e}"))?;
    // A null `error` beside a valid result is the JSON-RPC 1.0 success
    // convention, and proxies in front of a Solana endpoint still emit it.
    // `get` returns `Some(Value::Null)` there, so the bare presence check used
    // to read that null as a failure and throw away a perfectly good result,
    // reporting an upstream error nobody sent. The null is filtered out, the
    // same way this file already treats an absent value.
    if let Some(err) = root.get("error").filter(|e| !e.is_null()) {
        let msg = err.get("message").and_then(Value::as_str).unwrap_or("?");
        return Err(format!("marginfi RPC error, {}", quote_upstream(msg)));
    }
    let Some(rows) = root.get("result").and_then(Value::as_array) else {
        return Err("marginfi RPC reply has no result array".to_string());
    };

    let mut out = Vec::new();
    for row in rows {
        let pubkey = row.get("pubkey").and_then(Value::as_str).unwrap_or("?");
        let Some(b64) = row
            .get("account")
            .and_then(|a| a.get("data"))
            .and_then(Value::as_array)
            .and_then(|d| d.first())
            .and_then(Value::as_str)
        else {
            continue;
        };
        let data = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("marginfi account data is not base64: {e}"))?;
        if let Some(p) = decode_account(&data, pubkey, wallet_label) {
            out.push(p);
        }
    }
    Ok(out)
}

/// Decodes one raw MarginfiAccount using the health cache the program itself
/// maintains: maintenance-weighted asset and liability values plus status
/// flags. No interest math is re-derived on our side.
pub fn decode_account(data: &[u8], pubkey: &str, wallet_label: &str) -> Option<Position> {
    if data.len() < ACCOUNT_SIZE as usize {
        return None;
    }
    // The request carries a dataSize filter and two memcmp filters, and until
    // now the decoder trusted the endpoint to have honoured them. A caching
    // proxy that drops a filter, or a provider that answers a different query,
    // would get any 2312-byte account decoded and reported under the operator's
    // wallet label. Both facts sit in the bytes already in hand, so they are
    // cheap to re-check here. This is defence against an endpoint that
    // malfunctions; one that lies can forge these fields too, which is why the
    // allowlist guarantee lives at request construction rather than here.
    if !discriminator_matches(data) {
        return None;
    }
    let asset = i80f48_at(data, OFFSET_ASSET_VALUE)?;
    let liability = i80f48_at(data, OFFSET_LIABILITY_VALUE)?;
    let asset_maint = i80f48_at(data, OFFSET_ASSET_VALUE_MAINT)?;
    let liability_maint = i80f48_at(data, OFFSET_LIABILITY_VALUE_MAINT)?;
    let flags = u32::from_le_bytes(data[OFFSET_FLAGS..OFFSET_FLAGS + 4].try_into().ok()?);

    if asset == 0.0 && liability == 0.0 && asset_maint == 0.0 && liability_maint == 0.0 {
        return None;
    }

    let healthy = flags & FLAG_HEALTHY != 0;
    let engine_ok = flags & FLAG_ENGINE_STATUS_OK != 0;
    let oracle_ok = flags & FLAG_ORACLE_OK != 0;

    // ENGINE_STATUS_OK gates the HEALTHY reading. Without it the flag word is
    // whatever stood there before the last risk check, down to the all-zero
    // word of an account never checked, so a clear HEALTHY bit is no verdict.
    let condemned = engine_ok && !healthy;

    // Liquidation begins when maintenance-weighted liabilities reach
    // maintenance-weighted assets, so their ratio is an LTV with its threshold
    // at 1.0. The engine zeroes that pair when it cannot price the account, and
    // the init-weight pair measures against a different line, so a zeroed pair
    // yields no LTV figure at all. `flagged_unhealthy` carries the verdict
    // beside the ratio, needing no basis of its own.
    let (liquidation, stale_hint) = if !engine_ok {
        (None, Some("engine status unset".to_string()))
    } else if asset_maint > 0.0 {
        let mut hints: Vec<&str> = Vec::new();
        if !oracle_ok {
            hints.push("oracle flag unset");
        }
        if condemned {
            hints.push("flagged unhealthy");
        }
        (
            Some(Liquidation {
                ltv: liability_maint / asset_maint,
                liquidation_ltv: 1.0,
            }),
            (!hints.is_empty()).then(|| hints.join("; ")),
        )
    } else {
        let mut hint = "maint basis unavailable".to_string();
        if condemned {
            hint.push_str("; flagged unhealthy");
        }
        (None, Some(hint))
    };

    Some(Position {
        wallet_label: wallet_label.to_string(),
        protocol: Protocol::Marginfi,
        market: "acct".to_string(),
        account: short_account(pubkey),
        deposit_usd: asset,
        borrow_usd: liability,
        // The health cache is decoded at fixed offsets, so the liability is
        // either read or the whole account is rejected; there is no substituted
        // zero on this path.
        borrow_measured: true,
        liquidation,
        flagged_unhealthy: condemned,
        stale_hint,
    })
}

/// Reads a `WrappedI80F48` (16 bytes, little-endian i128 with 48 fractional
/// bits) and converts it to `f64`.
fn i80f48_at(data: &[u8], offset: usize) -> Option<f64> {
    let raw: [u8; 16] = data.get(offset..offset + 16)?.try_into().ok()?;
    let fixed = i128::from_le_bytes(raw);
    Some(fixed as f64 / (1u64 << 48) as f64)
}
