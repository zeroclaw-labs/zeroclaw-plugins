//! Mint account interpretation: jsonParsed when the node provides it, raw
//! byte-layout parsing as the fallback so the plugin works against nodes
//! whose parsers predate newer Token-2022 extensions.
//!
//! Raw layouts follow the SPL specs:
//! - Legacy mint: 82 bytes — COption<Pubkey> mint_authority, u64 supply,
//!   u8 decimals, u8 is_initialized, COption<Pubkey> freeze_authority.
//! - Token-2022: same 82 bytes, zero padding to 165, account-type byte at
//!   offset 165 (1 = Mint), then TLV entries (u16 type, u16 len, value).

use serde_json::Value;

use crate::rpc::{AccountInfo, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};

/// Which token program owns the mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenProgram {
    Legacy,
    Token2022,
}

/// A single observed extension, reduced to what risk scoring needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// Worst-case fee across older/newer config, in basis points.
    TransferFee {
        max_bps: u16,
    },
    /// A transfer-hook program is set and will run on every transfer.
    TransferHook {
        program: Option<String>,
    },
    /// Delegate that can move/burn any holder's tokens.
    PermanentDelegate {
        delegate: String,
    },
    /// New token accounts start frozen.
    DefaultStateFrozen,
    MintCloseAuthority,
    NonTransferable,
    InterestBearing,
    ConfidentialTransfers,
    /// Authority can pause all transfers.
    Pausable,
    /// Displayed balances can be rescaled by an authority.
    ScaledUiAmount,
    MetadataPointer,
    /// On-chain metadata; update authority present ⇒ mutable.
    TokenMetadata {
        name: String,
        symbol: String,
        mutable: bool,
    },
    /// Extension we do not recognize (forward-compat: flag, don't guess).
    Unknown {
        label: String,
    },
}

/// Everything risk scoring needs to know about a mint.
#[derive(Debug, Clone)]
pub struct MintFacts {
    pub program: TokenProgram,
    pub supply: u128,
    pub decimals: u8,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub extensions: Vec<Extension>,
}

pub fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}

/// Entry point: interpret a fetched account as a mint, whichever encoding the
/// node returned.
pub fn mint_facts(account: &AccountInfo) -> Result<MintFacts, String> {
    let program = match account.owner.as_str() {
        TOKEN_PROGRAM => TokenProgram::Legacy,
        TOKEN_2022_PROGRAM => TokenProgram::Token2022,
        other => {
            return Err(format!(
                "account is not an SPL token mint (owned by {other})"
            ))
        }
    };
    if let Some(parsed) = &account.parsed {
        return from_json_parsed(parsed, program);
    }
    if let Some(raw) = &account.raw {
        return from_raw(raw, program);
    }
    Err("account data missing from RPC response".to_string())
}

// ── jsonParsed path ─────────────────────────────────────────────────────────

fn from_json_parsed(parsed: &Value, program: TokenProgram) -> Result<MintFacts, String> {
    if parsed.get("type").and_then(Value::as_str) != Some("mint") {
        return Err("account is a token account, not a mint".to_string());
    }
    let info = parsed.get("info").ok_or("malformed parsed mint: no info")?;
    let supply = info
        .get("supply")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u128>().ok())
        .ok_or("malformed parsed mint: no supply")?;
    let decimals = info.get("decimals").and_then(Value::as_u64).unwrap_or(0) as u8;
    let mint_authority = info
        .get("mintAuthority")
        .and_then(Value::as_str)
        .map(str::to_string);
    let freeze_authority = info
        .get("freezeAuthority")
        .and_then(Value::as_str)
        .map(str::to_string);

    let mut extensions = Vec::new();
    if let Some(rows) = info.get("extensions").and_then(Value::as_array) {
        for row in rows {
            let kind = row.get("extension").and_then(Value::as_str).unwrap_or("");
            let state = row.get("state").cloned().unwrap_or(Value::Null);
            if let Some(ext) = parsed_extension(kind, &state) {
                extensions.push(ext);
            }
        }
    }

    Ok(MintFacts {
        program,
        supply,
        decimals,
        mint_authority,
        freeze_authority,
        extensions,
    })
}

fn parsed_extension(kind: &str, state: &Value) -> Option<Extension> {
    match kind {
        "transferFeeConfig" => {
            let newer = state
                .pointer("/newerTransferFee/transferFeeBasisPoints")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let older = state
                .pointer("/olderTransferFee/transferFeeBasisPoints")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            Some(Extension::TransferFee {
                max_bps: newer.max(older).min(u16::MAX as u64) as u16,
            })
        }
        "transferHook" => {
            let program = state
                .get("programId")
                .and_then(Value::as_str)
                .map(str::to_string);
            // A hook config with no program set is dormant; still worth noting,
            // so keep the extension either way and let scoring decide.
            Some(Extension::TransferHook { program })
        }
        "permanentDelegate" => {
            state
                .get("delegate")
                .and_then(Value::as_str)
                .map(|d| Extension::PermanentDelegate {
                    delegate: d.to_string(),
                })
        }
        "defaultAccountState" => match state.get("accountState").and_then(Value::as_str) {
            Some("frozen") => Some(Extension::DefaultStateFrozen),
            _ => None,
        },
        "mintCloseAuthority" => Some(Extension::MintCloseAuthority),
        "nonTransferable" => Some(Extension::NonTransferable),
        "interestBearingConfig" => Some(Extension::InterestBearing),
        "confidentialTransferMint" => Some(Extension::ConfidentialTransfers),
        "pausableConfig" => Some(Extension::Pausable),
        "scaledUiAmountConfig" => Some(Extension::ScaledUiAmount),
        "metadataPointer" => Some(Extension::MetadataPointer),
        "tokenMetadata" => {
            let name = state.get("name").and_then(Value::as_str).unwrap_or("");
            let symbol = state.get("symbol").and_then(Value::as_str).unwrap_or("");
            let mutable = state
                .get("updateAuthority")
                .and_then(Value::as_str)
                .is_some();
            Some(Extension::TokenMetadata {
                name: name.to_string(),
                symbol: symbol.to_string(),
                mutable,
            })
        }
        // Account-level or purely informational entries we deliberately skip.
        "transferFeeAmount"
        | "immutableOwner"
        | "memoTransfer"
        | "cpiGuard"
        | "transferHookAccount"
        | "confidentialTransferFeeConfig"
        | "confidentialTransferAccount"
        | "groupPointer"
        | "groupMemberPointer"
        | "tokenGroup"
        | "tokenGroupMember" => None,
        // Surface unrecognized parser output as unknown rather than silently
        // ignoring a possibly dangerous new extension.
        other => Some(Extension::Unknown {
            label: other.to_string(),
        }),
    }
}

// ── raw byte path ───────────────────────────────────────────────────────────

const LEGACY_MINT_LEN: usize = 82;
const ACCOUNT_TYPE_OFFSET: usize = 165;

fn from_raw(data: &[u8], program: TokenProgram) -> Result<MintFacts, String> {
    if data.len() < LEGACY_MINT_LEN {
        return Err("account data too short to be a mint".to_string());
    }
    let mint_authority = read_coption_pubkey(&data[0..36])?;
    let supply =
        u64::from_le_bytes(data[36..44].try_into().map_err(|_| "short supply field")?) as u128;
    let decimals = data[44];
    let is_initialized = data[45] == 1;
    if !is_initialized {
        return Err("mint account is not initialized".to_string());
    }
    let freeze_authority = read_coption_pubkey(&data[46..82])?;

    let mut extensions = Vec::new();
    if program == TokenProgram::Token2022 && data.len() > ACCOUNT_TYPE_OFFSET {
        if data[ACCOUNT_TYPE_OFFSET] != 1 {
            return Err("token-2022 account is not a mint".to_string());
        }
        extensions = parse_tlv(&data[ACCOUNT_TYPE_OFFSET + 1..]);
    }

    Ok(MintFacts {
        program,
        supply,
        decimals,
        mint_authority,
        freeze_authority,
        extensions,
    })
}

fn read_coption_pubkey(slice: &[u8]) -> Result<Option<String>, String> {
    if slice.len() < 36 {
        return Err("short COption<Pubkey> field".to_string());
    }
    let tag = u32::from_le_bytes(slice[0..4].try_into().unwrap());
    match tag {
        0 => Ok(None),
        1 => Ok(Some(bs58::encode(&slice[4..36]).into_string())),
        _ => Err("invalid COption tag in mint layout".to_string()),
    }
}

/// TLV ids from the spl-token-2022 `ExtensionType` enum.
fn parse_tlv(mut data: &[u8]) -> Vec<Extension> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let ty = u16::from_le_bytes([data[0], data[1]]);
        let len = u16::from_le_bytes([data[2], data[3]]) as usize;
        data = &data[4..];
        if data.len() < len {
            break; // truncated TLV: stop rather than misread
        }
        let value = &data[..len];
        data = &data[len..];
        if ty == 0 {
            continue; // Uninitialized padding
        }
        if let Some(ext) = tlv_extension(ty, value) {
            out.push(ext);
        }
    }
    out
}

fn tlv_extension(ty: u16, value: &[u8]) -> Option<Extension> {
    match ty {
        1 => {
            // TransferFeeConfig: 32 auth + 32 withdraw + 8 withheld +
            // TransferFee older (8+8+2) + TransferFee newer (8+8+2).
            let older = read_u16_at(value, 72 + 16);
            let newer = read_u16_at(value, 90 + 16);
            Some(Extension::TransferFee {
                max_bps: older.max(newer),
            })
        }
        3 => Some(Extension::MintCloseAuthority),
        4 => Some(Extension::ConfidentialTransfers),
        6 => match value.first() {
            Some(2) => Some(Extension::DefaultStateFrozen), // AccountState::Frozen
            _ => None,
        },
        9 => Some(Extension::NonTransferable),
        10 => Some(Extension::InterestBearing),
        12 => nonzero_pubkey(value, 0).map(|delegate| Extension::PermanentDelegate { delegate }),
        14 => Some(Extension::TransferHook {
            // authority (32) then program_id (32); all-zero program = dormant.
            program: nonzero_pubkey(value, 32),
        }),
        18 => Some(Extension::MetadataPointer),
        19 => Some(Extension::TokenMetadata {
            // Variable borsh payload; raw path reports presence only and
            // treats metadata as mutable (conservative default).
            name: String::new(),
            symbol: String::new(),
            mutable: true,
        }),
        24 => Some(Extension::ScaledUiAmount),
        25 => Some(Extension::Pausable),
        // Account-level extensions that can never appear on a mint, plus
        // group/pointer bookkeeping we don't score.
        2 | 5 | 7 | 8 | 11 | 13 | 15 | 16 | 17 | 20 | 21 | 22 | 23 => None,
        other => Some(Extension::Unknown {
            label: format!("id {other}"),
        }),
    }
}

fn read_u16_at(value: &[u8], offset: usize) -> u16 {
    value
        .get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn nonzero_pubkey(value: &[u8], offset: usize) -> Option<String> {
    let bytes = value.get(offset..offset + 32)?;
    if bytes.iter().all(|&b| b == 0) {
        None
    } else {
        Some(bs58::encode(bytes).into_string())
    }
}
