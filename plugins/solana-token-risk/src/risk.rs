//! Pure, deterministic Solana token risk scoring — no wasm, no network here.
//!
//! Input is the *parsed* on-chain state of a mint (as returned by a Solana RPC
//! `getAccountInfo`/`getTokenLargestAccounts`/`getTokenSupply` with
//! `encoding: "jsonParsed"`). Output is a structured EVIDENCE report: every flag
//! names the raw on-chain fact that triggered it and what that fact *enables*, so
//! an agent (or a human) can act on it. It is deterministic — the same chain
//! state always yields the same verdict — so a prompt cannot argue a token safe.
//!
//! This is evidence, not financial advice. Holder concentration in particular can
//! reflect a liquidity pool or an exchange, not a malicious whale; the report says so.

use crate::metadata::MetadataInfo;
use serde_json::Value;

/// The SPL burn incinerator — tokens here are provably out of circulation, so we
/// exclude it from "whale concentration".
const INCINERATOR: &str = "1nc1nerator11111111111111111111111111111111";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Flag {
    pub code: String,
    pub severity: Severity,
    /// What is wrong, in one line.
    pub title: String,
    /// The raw on-chain fact that triggered it.
    pub evidence: String,
    /// Points contributed to the 0-100 risk score.
    pub points: u32,
}

/// Normalized on-chain facts about a mint.
#[derive(Debug, Clone, Default)]
pub struct TokenFacts {
    pub mint: String,
    pub program: String, // "spl-token" | "spl-token-2022"
    pub is_initialized: bool,
    pub decimals: u8,
    pub raw_supply: u128,
    pub ui_supply: f64,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    /// Token-2022 extensions, by their RPC `extension` name.
    pub extensions: Vec<Extension>,
    /// Largest token accounts, sorted desc by amount.
    pub top_holders: Vec<Holder>,
    pub holders_source_ok: bool,
    /// Metaplex metadata mutability, once fetched.
    pub metadata: Option<MetadataInfo>,
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub name: String,
    pub state: Value,
}

/// What kind of account owns a top token balance. The distinction matters: a
/// liquidity pool or protocol vault holding most of the supply is expected
/// (that's the liquidity), whereas one keypair wallet holding it is dump risk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerKind {
    /// The burn incinerator — provably out of circulation.
    Burn,
    /// Owner is OFF the ed25519 curve → a program-derived account (AMM/LP,
    /// protocol vault, escrow). No single keypair controls it.
    Protocol,
    /// Owner is a valid curve point → a real keypair wallet (a person/CEX).
    Wallet,
    /// Owner not resolved yet — treated conservatively as a possible wallet.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Holder {
    /// The token account address (from getTokenLargestAccounts).
    pub account: String,
    pub ui_amount: f64,
    /// The wallet/PDA that owns the token account, once resolved.
    pub owner: Option<String>,
    pub kind: OwnerKind,
}

impl TokenFacts {
    fn ext(&self, name: &str) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.name == name)
    }

    /// Attach a resolved owner to a top holder and reclassify it.
    pub fn set_owner(&mut self, account: &str, owner: &str) {
        if let Some(h) = self.top_holders.iter_mut().find(|h| h.account == account) {
            h.owner = Some(owner.to_string());
            h.kind = classify_owner(owner);
        }
    }
}

/// Is a base58 pubkey a valid ed25519 curve point? `Some(true)` = on-curve
/// (a keypair wallet); `Some(false)` = off-curve (a program-derived account);
/// `None` = not a decodable 32-byte pubkey.
pub fn is_on_curve(pubkey_b58: &str) -> Option<bool> {
    let bytes = bs58::decode(pubkey_b58).into_vec().ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(curve25519_dalek::edwards::CompressedEdwardsY(arr).decompress().is_some())
}

/// Classify a token account's OWNER into an [`OwnerKind`].
pub fn classify_owner(owner: &str) -> OwnerKind {
    if owner == INCINERATOR {
        return OwnerKind::Burn;
    }
    match is_on_curve(owner) {
        Some(true) => OwnerKind::Wallet,    // a real keypair
        Some(false) => OwnerKind::Protocol, // off-curve → PDA/program (LP, protocol)
        None => OwnerKind::Unknown,
    }
}

/// Parse a `getAccountInfo` (jsonParsed) response for a *token account* and return
/// its `owner` (the wallet/PDA that controls the balance).
pub fn parse_token_account_owner(account_info: &Value) -> Option<String> {
    let result = unwrap_result(account_info);
    let value = result.get("value").unwrap_or(result);
    value
        .get("data")?
        .get("parsed")?
        .get("info")?
        .get("owner")?
        .as_str()
        .map(|s| s.to_string())
}

// ── parsing RPC jsonParsed responses ───────────────────────────────────────

/// Accept either a full JSON-RPC envelope (`{"result": {...}}`) or the inner
/// value directly, and return the `result` (or the value itself).
fn unwrap_result(v: &Value) -> &Value {
    v.get("result").unwrap_or(v)
}

/// Parse a `getAccountInfo` (jsonParsed) response for a mint into TokenFacts.
pub fn parse_mint(mint: &str, account_info: &Value) -> Result<TokenFacts, String> {
    let result = unwrap_result(account_info);
    let value = result.get("value").unwrap_or(result);
    if value.is_null() {
        return Err("mint account not found on this RPC (null value) — wrong address or network?".into());
    }
    let data = value.get("data").ok_or("account has no `data` — is this a token mint?")?;
    let parsed = data
        .get("parsed")
        .ok_or("account data is not jsonParsed — call getAccountInfo with encoding:jsonParsed")?;
    let typ = parsed.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if typ != "mint" {
        return Err(format!("account is a `{typ}`, not a token `mint`"));
    }
    let program = data
        .get("program")
        .and_then(|p| p.as_str())
        .unwrap_or("spl-token")
        .to_string();
    let info = parsed.get("info").ok_or("mint has no `info`")?;

    let decimals = info.get("decimals").and_then(|d| d.as_u64()).unwrap_or(0) as u8;
    let raw_supply: u128 = info
        .get("supply")
        .and_then(|s| s.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let ui_supply = raw_supply as f64 / 10f64.powi(decimals as i32);
    let is_initialized = info.get("isInitialized").and_then(|b| b.as_bool()).unwrap_or(true);

    // mintAuthority / freezeAuthority: a JSON `null` means renounced (good).
    let auth = |k: &str| -> Option<String> {
        match info.get(k) {
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    };

    let mut extensions = Vec::new();
    if let Some(exts) = info.get("extensions").and_then(|e| e.as_array()) {
        for e in exts {
            if let Some(name) = e.get("extension").and_then(|n| n.as_str()) {
                extensions.push(Extension {
                    name: name.to_string(),
                    state: e.get("state").cloned().unwrap_or(Value::Null),
                });
            }
        }
    }

    Ok(TokenFacts {
        mint: mint.to_string(),
        program,
        is_initialized,
        decimals,
        raw_supply,
        ui_supply,
        mint_authority: auth("mintAuthority"),
        freeze_authority: auth("freezeAuthority"),
        extensions,
        top_holders: Vec::new(),
        holders_source_ok: false,
        metadata: None,
    })
}

/// Fold a `getTokenLargestAccounts` response into the facts (top holders).
pub fn apply_largest(facts: &mut TokenFacts, largest: &Value) {
    let result = unwrap_result(largest);
    let arr = match result.get("value").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return,
    };
    let mut holders: Vec<Holder> = Vec::new();
    for a in arr {
        let addr = a.get("address").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let ui = a
            .get("uiAmount")
            .and_then(|x| x.as_f64())
            .or_else(|| a.get("uiAmountString").and_then(|x| x.as_str()).and_then(|s| s.parse().ok()))
            .unwrap_or(0.0);
        if !addr.is_empty() {
            // Owner is resolved in a later pass; a token account that IS the
            // incinerator counts as burn even before owner resolution.
            let kind = if addr == INCINERATOR { OwnerKind::Burn } else { OwnerKind::Unknown };
            holders.push(Holder { account: addr, ui_amount: ui, owner: None, kind });
        }
    }
    holders.sort_by(|a, b| b.ui_amount.partial_cmp(&a.ui_amount).unwrap_or(std::cmp::Ordering::Equal));
    facts.top_holders = holders;
    facts.holders_source_ok = true;
}

// ── scoring ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RiskReport {
    pub flags: Vec<Flag>,
    pub score: u32, // 0-100
    pub band: &'static str,
    pub notes: Vec<String>,
}

fn band_for(score: u32, max_sev: Severity) -> &'static str {
    // Score sets the floor; a single critical/high fact raises it so a lone but
    // fatal flag can't be averaged away.
    let by_score = match score {
        s if s >= 60 => "CRITICAL",
        s if s >= 35 => "HIGH",
        s if s >= 15 => "MEDIUM",
        s if s >= 1 => "LOW",
        _ => "MINIMAL",
    };
    let by_sev = match max_sev {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "MINIMAL",
    };
    // Return the more severe of the two.
    let rank = |b: &str| match b {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    };
    if rank(by_sev) >= rank(by_score) { by_sev } else { by_score }
}

/// Assess a mint from its normalized facts. Deterministic.
pub fn assess(f: &TokenFacts) -> RiskReport {
    let mut flags: Vec<Flag> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    if !f.is_initialized {
        flags.push(Flag {
            code: "mint_uninitialized".into(),
            severity: Severity::High,
            title: "Mint is not initialized".into(),
            evidence: "isInitialized = false".into(),
            points: 20,
        });
    }

    // Authorities.
    if let Some(a) = &f.mint_authority {
        flags.push(Flag {
            code: "mint_authority_present".into(),
            severity: Severity::Critical,
            title: "Mint authority is live — supply can be inflated at will".into(),
            evidence: format!("mintAuthority = {a} (not null). New tokens can be minted, diluting holders."),
            points: 35,
        });
    } else {
        notes.push("Mint authority is renounced (null) — supply is fixed.".into());
    }
    if let Some(a) = &f.freeze_authority {
        flags.push(Flag {
            code: "freeze_authority_present".into(),
            severity: Severity::High,
            title: "Freeze authority is live — accounts can be frozen (sell can be blocked)".into(),
            evidence: format!("freezeAuthority = {a} (not null). Holder token accounts can be frozen, a classic honeypot."),
            points: 25,
        });
    } else {
        notes.push("Freeze authority is renounced (null) — accounts cannot be frozen.".into());
    }

    // Metaplex metadata mutability.
    if let Some(m) = &f.metadata {
        if m.is_mutable {
            flags.push(Flag {
                code: "metadata_mutable".into(),
                severity: Severity::Medium,
                title: "Token metadata is mutable — name, symbol and image can be changed".into(),
                evidence: format!(
                    "Metaplex metadata is_mutable = true; update authority {} can rewrite the token's identity after you buy (a bait-and-switch vector).",
                    m.update_authority
                ),
                points: 15,
            });
        } else {
            notes.push("Token metadata is immutable — name, symbol and image are frozen.".into());
        }
    }

    // Token-2022 dangerous extensions.
    if f.program == "spl-token-2022" {
        if f.ext("transferHook").is_some() {
            flags.push(Flag {
                code: "transfer_hook".into(),
                severity: Severity::Critical,
                title: "Transfer hook — arbitrary program runs on every transfer".into(),
                evidence: "Token-2022 `transferHook` extension is set. The hook can revert transfers (block sells) or add logic on each move.".into(),
                points: 40,
            });
        }
        if f.ext("permanentDelegate").is_some() {
            flags.push(Flag {
                code: "permanent_delegate".into(),
                severity: Severity::Critical,
                title: "Permanent delegate — an authority can move or burn anyone's tokens".into(),
                evidence: "Token-2022 `permanentDelegate` extension is set. The delegate can transfer/burn tokens from any holder without consent.".into(),
                points: 40,
            });
        }
        if f.ext("nonTransferable").is_some() {
            flags.push(Flag {
                code: "non_transferable".into(),
                severity: Severity::Critical,
                title: "Non-transferable — tokens cannot be sold or moved at all".into(),
                evidence: "Token-2022 `nonTransferable` extension is set. Holders can never transfer; a total honeypot.".into(),
                points: 45,
            });
        }
        if let Some(e) = f.ext("transferFeeConfig") {
            let (bps, authority_can_raise) = transfer_fee(&e.state);
            let pct = bps as f64 / 100.0;
            let (sev, pts) = match bps {
                0..=100 => (Severity::Low, 8),
                101..=500 => (Severity::Medium, 18),
                _ => (Severity::High, 30),
            };
            flags.push(Flag {
                code: "transfer_fee".into(),
                severity: sev,
                title: format!("Transfer fee of {pct:.2}% on every trade"),
                evidence: format!(
                    "Token-2022 `transferFeeConfig`: {bps} bps current fee{}.",
                    if authority_can_raise { ", with a live fee authority that can raise it (up to 100%)" } else { "" }
                ),
                points: if authority_can_raise { pts + 10 } else { pts },
            });
        }
        if let Some(e) = f.ext("defaultAccountState") {
            let frozen = e.state.get("accountState").and_then(|s| s.as_str()) == Some("frozen");
            if frozen {
                flags.push(Flag {
                    code: "default_account_state_frozen".into(),
                    severity: Severity::High,
                    title: "New accounts default to FROZEN — you can't move tokens until an authority thaws you".into(),
                    evidence: "Token-2022 `defaultAccountState` = frozen. Every new holder is frozen by default; the authority decides who may transfer.".into(),
                    points: 28,
                });
            }
        }
        if f.ext("mintCloseAuthority").is_some() {
            flags.push(Flag {
                code: "mint_close_authority".into(),
                severity: Severity::Medium,
                title: "Mint can be closed by an authority".into(),
                evidence: "Token-2022 `mintCloseAuthority` is set — the mint account can be closed.".into(),
                points: 12,
            });
        }
    }

    // Holder concentration — the whale risk is a keypair WALLET holding a large
    // share. An off-curve protocol/LP vault holding the supply is liquidity, not a
    // whale, so it is separated out (and only counted when owners are resolved).
    if f.holders_source_ok && f.ui_supply > 0.0 && !f.top_holders.is_empty() {
        let mut whale: Option<&Holder> = None;
        let mut top5_wallet = 0.0f64;
        let mut wallets_counted = 0;
        let mut lp_amt = 0.0f64;
        let mut lp_ref: Option<&Holder> = None;
        for h in &f.top_holders {
            match h.kind {
                OwnerKind::Burn => continue,
                OwnerKind::Protocol => {
                    if h.ui_amount > lp_amt {
                        lp_amt = h.ui_amount;
                        lp_ref = Some(h);
                    }
                }
                OwnerKind::Wallet | OwnerKind::Unknown => {
                    if whale.is_none() {
                        whale = Some(h);
                    }
                    if wallets_counted < 5 {
                        top5_wallet += h.ui_amount;
                        wallets_counted += 1;
                    }
                }
            }
        }

        if let Some(w) = whale {
            let whale_pct = 100.0 * w.ui_amount / f.ui_supply;
            let top5_pct = 100.0 * top5_wallet / f.ui_supply;
            let (sev, pts) = match whale_pct {
                p if p >= 90.0 => (Severity::High, 30),
                p if p >= 50.0 => (Severity::Medium, 20),
                p if p >= 30.0 => (Severity::Low, 10),
                _ => (Severity::Info, 0),
            };
            if pts > 0 {
                let who = w.owner.clone().unwrap_or_else(|| w.account.clone());
                let qual = if w.kind == OwnerKind::Wallet {
                    "keypair wallet"
                } else {
                    "holder (owner unresolved)"
                };
                flags.push(Flag {
                    code: "holder_concentration".into(),
                    severity: sev,
                    title: format!("A single {qual} holds {whale_pct:.1}% of supply"),
                    evidence: format!(
                        "Largest non-liquidity holder {who} holds {whale_pct:.1}%; top-5 wallets hold {top5_pct:.1}%. A single sell can crater the price."
                    ),
                    points: pts,
                });
            }
        }

        if let Some(lp) = lp_ref {
            let lp_pct = 100.0 * lp.ui_amount / f.ui_supply;
            let who = lp.owner.clone().unwrap_or_else(|| lp.account.clone());
            notes.push(format!(
                "Largest holder is an off-curve protocol/LP account (owner {who}) holding {lp_pct:.1}% — this is liquidity, not a wallet, and is not counted as whale concentration."
            ));
        }
        if f.top_holders.iter().all(|h| matches!(h.kind, OwnerKind::Unknown | OwnerKind::Burn)) {
            notes.push("Holder owners were not resolved, so liquidity pools could not be told apart from wallets; concentration is a conservative upper bound.".into());
        } else {
            notes.push("Wallet vs protocol/LP is distinguished by an on-curve check on each owner; a CEX hot wallet is on-curve and may still appear as a 'wallet'.".into());
        }
    } else {
        notes.push("Holder concentration not evaluated: getTokenLargestAccounts returned no data. Most public RPC endpoints throttle or block that method — point rpc_url at an RPC that permits it to get whale/LP analysis.".into());
    }

    let score = flags.iter().map(|f| f.points).sum::<u32>().min(100);
    let max_sev = flags.iter().map(|f| f.severity).max().unwrap_or(Severity::Info);
    let band = band_for(score, max_sev);

    RiskReport { flags, score, band, notes }
}

/// Read the current transfer-fee bps and whether a fee authority can still raise it.
fn transfer_fee(state: &Value) -> (u64, bool) {
    let bps = state
        .get("newerTransferFee")
        .and_then(|n| n.get("transferFeeBasisPoints"))
        .and_then(|b| b.as_u64())
        .or_else(|| state.get("transferFeeBasisPoints").and_then(|b| b.as_u64()))
        .unwrap_or(0);
    let authority_can_raise = matches!(
        state.get("transferFeeConfigAuthority"),
        Some(Value::String(s)) if !s.is_empty()
    );
    (bps, authority_can_raise)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mint_resp(program: &str, mint_auth: Value, freeze_auth: Value, exts: Value) -> Value {
        json!({"result":{"value":{"data":{"parsed":{"info":{
            "decimals":6,"isInitialized":true,"supply":"1000000000000",
            "mintAuthority":mint_auth,"freezeAuthority":freeze_auth,"extensions":exts
        },"type":"mint"},"program":program},"owner":"x"}}})
    }

    #[test]
    fn clean_renounced_token_is_minimal_risk() {
        let resp = mint_resp("spl-token", Value::Null, Value::Null, Value::Null);
        let f = parse_mint("Mint111", &resp).unwrap();
        let r = assess(&f);
        assert_eq!(r.band, "MINIMAL");
        assert_eq!(r.score, 0);
        assert!(r.flags.is_empty());
        assert!(r.notes.iter().any(|n| n.contains("Mint authority is renounced")));
    }

    #[test]
    fn live_mint_authority_is_critical() {
        let resp = mint_resp("spl-token", json!("Boss1111"), Value::Null, Value::Null);
        let f = parse_mint("Mint111", &resp).unwrap();
        let r = assess(&f);
        assert_eq!(r.band, "CRITICAL");
        assert!(r.flags.iter().any(|fl| fl.code == "mint_authority_present" && fl.severity == Severity::Critical));
    }

    #[test]
    fn freeze_authority_flagged_high() {
        let resp = mint_resp("spl-token", Value::Null, json!("Freezer1"), Value::Null);
        let f = parse_mint("Mint111", &resp).unwrap();
        let r = assess(&f);
        assert!(r.flags.iter().any(|fl| fl.code == "freeze_authority_present"));
        assert_eq!(r.band, "HIGH");
    }

    #[test]
    fn token2022_transfer_hook_and_permanent_delegate_critical() {
        let exts = json!([
            {"extension":"transferHook","state":{"authority":"a","programId":"p"}},
            {"extension":"permanentDelegate","state":{"delegate":"d"}}
        ]);
        let resp = mint_resp("spl-token-2022", Value::Null, Value::Null, exts);
        let f = parse_mint("Mint111", &resp).unwrap();
        let r = assess(&f);
        assert!(r.flags.iter().any(|fl| fl.code == "transfer_hook"));
        assert!(r.flags.iter().any(|fl| fl.code == "permanent_delegate"));
        assert_eq!(r.band, "CRITICAL");
    }

    #[test]
    fn transfer_fee_reads_bps_and_authority() {
        let exts = json!([{"extension":"transferFeeConfig","state":{
            "newerTransferFee":{"transferFeeBasisPoints":800},
            "transferFeeConfigAuthority":"FeeBoss"
        }}]);
        let resp = mint_resp("spl-token-2022", Value::Null, Value::Null, exts);
        let f = parse_mint("Mint111", &resp).unwrap();
        let r = assess(&f);
        let fee = r.flags.iter().find(|fl| fl.code == "transfer_fee").unwrap();
        assert_eq!(fee.severity, Severity::High); // 800 bps
        assert!(fee.evidence.contains("800 bps"));
        assert!(fee.evidence.contains("can raise it"));
    }

    #[test]
    fn holder_concentration_excludes_burn_and_flags_whale() {
        let mut resp = mint_resp("spl-token", Value::Null, Value::Null, Value::Null);
        // supply is 1,000,000 ui (1e12 raw / 1e6)
        let _ = &mut resp;
        let largest = json!({"result":{"value":[
            {"address": INCINERATOR, "uiAmount": 400000.0},
            {"address":"Whale1","uiAmount":550000.0},
            {"address":"Small1","uiAmount":50000.0}
        ]}});
        let mut f = parse_mint("Mint111", &resp).unwrap();
        apply_largest(&mut f, &largest);
        let r = assess(&f);
        let conc = r.flags.iter().find(|fl| fl.code == "holder_concentration").unwrap();
        // Whale holds 550k of 1,000k = 55% (burn excluded), MEDIUM band.
        assert!(conc.evidence.contains("55.0%"));
        assert_eq!(conc.severity, Severity::Medium);
    }

    #[test]
    fn protocol_lp_owner_is_not_counted_as_a_whale() {
        // Largest holder (80%) is an off-curve protocol/LP vault; the only wallet
        // is small. No whale flag should fire, and a liquidity note should appear.
        let resp = mint_resp("spl-token", Value::Null, Value::Null, Value::Null);
        let mut f = parse_mint("Mint111", &resp).unwrap();
        f.holders_source_ok = true;
        f.top_holders = vec![
            Holder { account: "LpAcct".into(), ui_amount: 800000.0, owner: Some("LpVault".into()), kind: OwnerKind::Protocol },
            Holder { account: "WAcct".into(), ui_amount: 100000.0, owner: Some("W".into()), kind: OwnerKind::Wallet },
        ];
        let r = assess(&f);
        assert!(r.flags.iter().find(|fl| fl.code == "holder_concentration").is_none(),
            "10% wallet must not trip a whale flag when the 80% holder is an LP");
        assert!(r.notes.iter().any(|n| n.contains("liquidity, not a wallet")));
    }

    #[test]
    fn on_curve_wallet_holding_the_supply_is_flagged() {
        let resp = mint_resp("spl-token", Value::Null, Value::Null, Value::Null);
        let mut f = parse_mint("Mint111", &resp).unwrap();
        f.holders_source_ok = true;
        f.top_holders = vec![
            Holder { account: "WAcct".into(), ui_amount: 700000.0, owner: Some("BigWallet".into()), kind: OwnerKind::Wallet },
        ];
        let r = assess(&f);
        let conc = r.flags.iter().find(|fl| fl.code == "holder_concentration").expect("whale flag");
        assert_eq!(conc.severity, Severity::Medium); // 70%
        assert!(conc.evidence.contains("BigWallet"));
        assert!(conc.title.contains("keypair wallet"));
    }

    #[test]
    fn parse_token_account_owner_reads_owner() {
        let resp = json!({"result":{"value":{"data":{"parsed":{"type":"account",
            "info":{"owner":"OwnerWallet","mint":"m","tokenAmount":{}}},"program":"spl-token"}}}});
        assert_eq!(parse_token_account_owner(&resp).as_deref(), Some("OwnerWallet"));
    }

    #[test]
    fn classify_burn_and_curve() {
        assert_eq!(classify_owner(INCINERATOR), OwnerKind::Burn);
        // A valid 32-byte base58 pubkey decodes and classifies as Wallet or Protocol
        // (on- vs off-curve), never Unknown.
        let k = classify_owner("So11111111111111111111111111111111111111112");
        assert!(k == OwnerKind::Wallet || k == OwnerKind::Protocol);
        // Garbage that is not a 32-byte base58 pubkey is Unknown, not a panic.
        assert_eq!(classify_owner("not-a-key"), OwnerKind::Unknown);
        // is_on_curve returns None for undecodable input.
        assert_eq!(is_on_curve("not-a-key"), None);
    }

    #[test]
    fn parse_rejects_non_mint() {
        let resp = json!({"result":{"value":{"data":{"parsed":{"type":"account","info":{}},"program":"spl-token"}}}});
        assert!(parse_mint("x", &resp).is_err());
    }

    #[test]
    fn parse_rejects_missing_account() {
        let resp = json!({"result":{"value":null}});
        assert!(parse_mint("x", &resp).is_err());
    }
}
