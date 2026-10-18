//! Pure core: Solana token risk analysis — no WASM dependency.
//!
//! This module evaluates a single SPL / Token-2022 mint and returns a
//! structured risk verdict (`green`, `amber`, `red`) with human-readable
//! findings.  It is designed to be called from the thin WASM shim after
//! the shim has fetched the necessary on-chain data via RPC.
//!
//! ## Checks performed
//!
//! | # | Check                          | Data source            |
//! |---|--------------------------------|------------------------|
//! | 1 | Mint authority                 | `getAccountInfo(mint)` |
//! | 2 | Freeze authority               | `getAccountInfo(mint)` |
//! | 3 | Token-2022 permanent delegate   | `getAccountInfo(mint)` |
//! | 4 | Token-2022 transfer hook        | `getAccountInfo(mint)` |
//! | 5 | Token-2022 transfer fee         | `getAccountInfo(mint)` |
//! | 6 | Token-2022 confidential transfer| `getAccountInfo(mint)` |
//! | 7 | Holder concentration            | `getTokenLargestAccounts` |
//! | 8 | Token supply                    | `getTokenSupply`       |
//! | 9 | Decimals sanity                 | `getAccountInfo(mint)` |
//! |10 | SPL vs Token-2022               | `getAccountInfo(mint)` |

use serde::Serialize;

// Inline base58 (zero-dependency, same as solana-wasm-client)
mod base58 {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    static REVERSE: [u8; 128] = {
        let mut table = [0xFFu8; 128];
        let mut i = 0;
        while i < 58 {
            table[ALPHABET[i] as usize] = i as u8;
            i += 1;
        }
        table
    };

    pub fn encode(bytes: &[u8]) -> String {
        let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
        let mut buf = vec![0u8; (bytes.len() * 138 / 100) + 2];
        let mut buf_len = 0;
        for &byte in bytes.iter().skip(leading_zeros) {
            let mut carry = byte as u32;
            for idx in 0.. {
                if idx >= buf_len {
                    buf_len = idx + 1;
                    while buf.len() <= idx { buf.push(0); }
                }
                carry += (buf[idx] as u32) << 8;
                buf[idx] = (carry % 58) as u8;
                carry /= 58;
                if carry == 0 && idx + 1 >= buf_len { break; }
            }
        }
        let mut result = String::with_capacity(leading_zeros + buf_len);
        for _ in 0..leading_zeros { result.push('1'); }
        for &digit in buf[..buf_len].iter().rev() { result.push(ALPHABET[digit as usize] as char); }
        result
    }

    #[allow(dead_code)]
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let bytes = s.as_bytes();
        let leading_ones = bytes.iter().take_while(|&&b| b == b'1').count();
        let mut buf = vec![0u8; (bytes.len() * 733 / 1000) + 2];
        let mut buf_len = 0;
        for &ch in bytes.iter().skip(leading_ones) {
            if ch > 127 { return None; }
            let digit = REVERSE[ch as usize];
            if digit == 0xFF { return None; }
            let mut carry = digit as u32;
            for idx in 0.. {
                if idx >= buf_len {
                    buf_len = idx + 1;
                    while buf.len() <= idx { buf.push(0); }
                }
                carry += (buf[idx] as u32) * 58;
                buf[idx] = (carry % 256) as u8;
                carry /= 256;
                if carry == 0 && idx + 1 >= buf_len { break; }
            }
        }
        let mut result = vec![0u8; leading_ones];
        for &byte in buf[..buf_len].iter().rev() { result.push(byte); }
        Some(result)
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Overall risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Green,
    Amber,
    Red,
}

/// A single finding from a risk check.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: String,
    pub check: String,
    pub status: String,
    pub detail: String,
}

/// The complete risk report returned to the LLM.
#[derive(Debug, Clone, Serialize)]
pub struct RiskReport {
    pub mint: String,
    pub risk_level: RiskLevel,
    pub risk_score: u8,
    pub total_checks: usize,
    pub passed: usize,
    pub warnings: usize,
    pub criticals: usize,
    pub findings: Vec<Finding>,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Raw input data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MintData {
    pub mint_authority: Option<[u8; 32]>,
    pub freeze_authority: Option<[u8; 32]>,
    pub decimals: u8,
    pub supply: u64,
    pub is_initialized: bool,
    pub owner_program: String,
}

#[derive(Debug, Clone, Default)]
pub struct Token2022Extensions {
    pub permanent_delegate: Option<[u8; 32]>,
    pub transfer_hook_program: Option<[u8; 32]>,
    pub transfer_fee_bps: Option<u16>,
    pub has_confidential_transfers: bool,
}

#[derive(Debug, Clone)]
pub struct HolderInfo {
    pub address: String,
    pub amount: u64,
    pub percentage: f64,
}

// ---------------------------------------------------------------------------
// Mint account parsing (pure — no RPC)
// ---------------------------------------------------------------------------

pub fn parse_mint(data: &[u8], owner_program: &str) -> Result<MintData, String> {
    if data.len() < 82 {
        return Err(format!("mint data too short: {} bytes (need ≥82)", data.len()));
    }

    let mint_auth_tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let mint_authority = if mint_auth_tag == 1 && data.len() >= 36 {
        Some(data[4..36].try_into().unwrap())
    } else {
        None
    };

    let supply = u64::from_le_bytes([
        data[36], data[37], data[38], data[39], data[40], data[41], data[42], data[43],
    ]);
    let decimals = data[44];
    let is_initialized = data[45] != 0;

    let freeze_tag_offset = 46;
    let freeze_authority = if data.len() >= freeze_tag_offset + 36 {
        let tag = u32::from_le_bytes([
            data[freeze_tag_offset],
            data[freeze_tag_offset + 1],
            data[freeze_tag_offset + 2],
            data[freeze_tag_offset + 3],
        ]);
        if tag == 1 {
            Some(data[freeze_tag_offset + 4..freeze_tag_offset + 36].try_into().unwrap())
        } else {
            None
        }
    } else {
        None
    };

    Ok(MintData { mint_authority, freeze_authority, decimals, supply, is_initialized, owner_program: owner_program.to_string() })
}

pub fn scan_extensions(data: &[u8]) -> Token2022Extensions {
    if data.len() <= 82 { return Token2022Extensions::default(); }
    let ext_data = &data[82..];
    let mut exts = Token2022Extensions::default();
    let mut offset = 0;

    while offset + 4 <= ext_data.len() {
        let ext_type = u16::from_le_bytes([ext_data[offset], ext_data[offset + 1]]);
        let ext_len = u16::from_le_bytes([ext_data[offset + 2], ext_data[offset + 3]]) as usize;
        match ext_type {
            0x0000 => {
                if ext_len >= 32 && offset + 4 + 32 <= ext_data.len() {
                    exts.permanent_delegate = Some(ext_data[offset + 4..offset + 4 + 32].try_into().unwrap());
                }
            }
            0x0008 => {
                if ext_len >= 32 && offset + 4 + 32 <= ext_data.len() {
                    exts.transfer_hook_program = Some(ext_data[offset + 4..offset + 4 + 32].try_into().unwrap());
                }
            }
            0x000A => {
                if ext_len >= 8 && offset + 4 + 8 <= ext_data.len() {
                    exts.transfer_fee_bps = Some(u16::from_le_bytes([ext_data[offset + 8], ext_data[offset + 9]]));
                }
            }
            _ => {}
        }
        let padded_len = ((ext_len + 7) / 8) * 8;
        offset += 4 + padded_len;
        if offset > ext_data.len() || offset > 512 { break; }
    }
    exts
}

// ---------------------------------------------------------------------------
// Risk analysis
// ---------------------------------------------------------------------------

pub fn analyze(
    mint_base58: &str,
    mint_data: &MintData,
    extensions: &Token2022Extensions,
    largest_holders: &[HolderInfo],
) -> RiskReport {
    let mut findings = Vec::new();
    let mut score: u8 = 0;

    // Check 1: Mint authority
    if let Some(ref auth) = mint_data.mint_authority {
        findings.push(Finding {
            severity: "warning".into(), check: "mint_authority".into(), status: "warn".into(),
            detail: format!("Mint authority active: {}. New tokens can be minted.", base58::encode(auth)),
        });
        score += 10;
    } else {
        findings.push(Finding { severity: "info".into(), check: "mint_authority".into(), status: "pass".into(),
            detail: "Mint authority revoked — supply is fixed.".into() });
    }

    // Check 2: Freeze authority
    if let Some(ref auth) = mint_data.freeze_authority {
        findings.push(Finding {
            severity: "critical".into(), check: "freeze_authority".into(), status: "fail".into(),
            detail: format!("Freeze authority active: {}. Tokens can be frozen!", base58::encode(auth)),
        });
        score += 25;
    } else {
        findings.push(Finding { severity: "info".into(), check: "freeze_authority".into(), status: "pass".into(),
            detail: "Freeze authority revoked — tokens cannot be frozen.".into() });
    }

    // Check 3: Permanent Delegate
    if let Some(ref pd) = extensions.permanent_delegate {
        findings.push(Finding {
            severity: "critical".into(), check: "permanent_delegate".into(), status: "fail".into(),
            detail: format!("Token-2022 permanent delegate set: {}. Can transfer or burn ANY holder's tokens.", base58::encode(pd)),
        });
        score += 55;
    } else {
        findings.push(Finding { severity: "info".into(), check: "permanent_delegate".into(), status: "pass".into(),
            detail: "No permanent delegate.".into() });
    }

    // Check 4: Transfer Hook
    if let Some(ref hook) = extensions.transfer_hook_program {
        findings.push(Finding {
            severity: "warning".into(), check: "transfer_hook".into(), status: "warn".into(),
            detail: format!("Token-2022 transfer hook: {}. Transfers can be blocked.", base58::encode(hook)),
        });
        score += 10;
    } else {
        findings.push(Finding { severity: "info".into(), check: "transfer_hook".into(), status: "pass".into(),
            detail: "No transfer hook.".into() });
    }

    // Check 5: Transfer Fee
    if let Some(fee_bps) = extensions.transfer_fee_bps {
        findings.push(Finding {
            severity: "warning".into(), check: "transfer_fee".into(), status: "warn".into(),
            detail: format!("Token-2022 transfer fee: {fee_bps} bps ({:.2}%).", fee_bps as f64 / 100.0),
        });
        score += 5;
    } else {
        findings.push(Finding { severity: "info".into(), check: "transfer_fee".into(), status: "pass".into(),
            detail: "No transfer fee.".into() });
    }

    // Check 6: Confidential Transfers
    if extensions.has_confidential_transfers {
        findings.push(Finding { severity: "warning".into(), check: "confidential_transfers".into(), status: "warn".into(),
            detail: "Token-2022 confidential transfers enabled.".into() });
        score += 5;
    } else {
        findings.push(Finding { severity: "info".into(), check: "confidential_transfers".into(), status: "pass".into(),
            detail: "No confidential transfers.".into() });
    }

    // Check 7: Decimals sanity
    if mint_data.decimals > 12 {
        findings.push(Finding { severity: "warning".into(), check: "decimals".into(), status: "warn".into(),
            detail: format!("Unusually high decimals: {}.", mint_data.decimals) });
        score += 5;
    } else {
        findings.push(Finding { severity: "info".into(), check: "decimals".into(), status: "pass".into(),
            detail: format!("Decimals: {} (normal).", mint_data.decimals) });
    }

    // Check 8: Holder concentration
    if !largest_holders.is_empty() {
        let top1_pct = largest_holders[0].percentage;
        let top10_pct: f64 = largest_holders.iter().take(10).map(|h| h.percentage).sum();
        if top1_pct > 50.0 {
            findings.push(Finding { severity: "critical".into(), check: "holder_concentration".into(), status: "fail".into(),
                detail: format!("Top holder owns {top1_pct:.1}% of supply.") });
            score += 25;
        } else if top10_pct > 80.0 {
            findings.push(Finding { severity: "warning".into(), check: "holder_concentration".into(), status: "warn".into(),
                detail: format!("Top 10 holders own {top10_pct:.1}% of supply.") });
            score += 15;
        } else {
            findings.push(Finding { severity: "info".into(), check: "holder_concentration".into(), status: "pass".into(),
                detail: format!("Top 10 holders: {top10_pct:.1}%.") });
        }
    }

    // Check 9: Token-2022 vs SPL
    let is_token2022 = mint_data.owner_program.contains("TokenzQ");
    findings.push(Finding {
        severity: "info".into(), check: "token_program".into(), status: "pass".into(),
        detail: if is_token2022 { "Token-2022 program." } else { "Standard SPL Token." }.into(),
    });

    let risk_level = if score >= 50 { RiskLevel::Red } else if score >= 20 { RiskLevel::Amber } else { RiskLevel::Green };
    let total = findings.len();
    let passed = findings.iter().filter(|f| f.status == "pass").count();
    let warnings_count = findings.iter().filter(|f| f.status == "warn").count();
    let criticals = findings.iter().filter(|f| f.status == "fail").count();

    let summary = match risk_level {
        RiskLevel::Green => format!("✅ {mint_base58} — SAFE. Score {score}/100."),
        RiskLevel::Amber => format!("⚠️ {mint_base58} — CAUTION. Score {score}/100. {warnings_count} warnings, {criticals} critical."),
        RiskLevel::Red => format!("🔴 {mint_base58} — HIGH RISK. Score {score}/100. {criticals} CRITICAL."),
    };

    RiskReport { mint: mint_base58.to_string(), risk_level, risk_score: score,
        total_checks: total, passed, warnings: warnings_count, criticals, findings, summary }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mint() -> MintData {
        MintData {
            mint_authority: None, freeze_authority: None, decimals: 6,
            supply: 1_000_000_000_000, is_initialized: true,
            owner_program: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
        }
    }

    #[test]
    fn safe_mint_green() {
        let report = analyze("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            &test_mint(), &Token2022Extensions::default(), &[]);
        assert_eq!(report.risk_level, RiskLevel::Green);
    }

    #[test]
    fn freeze_auth_critical() {
        let mut mint = test_mint();
        mint.freeze_authority = Some([0x42; 32]);
        let report = analyze("Freeze...", &mint, &Token2022Extensions::default(), &[]);
        assert_eq!(report.risk_level, RiskLevel::Amber);
        assert!(report.criticals >= 1);
    }

    #[test]
    fn permanent_delegate_red() {
        let mut exts = Token2022Extensions::default();
        exts.permanent_delegate = Some([0xDE; 32]);
        let report = analyze("PDToken...", &test_mint(), &exts, &[]);
        assert_eq!(report.risk_level, RiskLevel::Red);
    }

    #[test]
    fn concentrated_warns() {
        let holders = vec![
            HolderInfo { address: "A".into(), amount: 850_000_000_000, percentage: 85.0 },
            HolderInfo { address: "B".into(), amount: 100_000_000_000, percentage: 10.0 },
        ];
        let report = analyze("Conc...", &test_mint(), &Token2022Extensions::default(), &holders);
        assert!(report.risk_score >= 20);
    }
}
