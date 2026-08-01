//! Human-readable narration of decoded Solana transactions.

use crate::core::programs::{
    bpf_upgradeable_loader, is_token_family, program_label, system_program, token_2022_program,
};
use crate::core::pubkey::Pubkey;
use crate::core::tx::{CompiledInstruction, DecodedTransaction, TxVersion};

/// Produce a multi-line narration of what a transaction does.
pub fn narrate_transaction(tx: &DecodedTransaction) -> String {
    let mut lines = Vec::new();
    let ver = match tx.version {
        TxVersion::Legacy => "legacy",
        TxVersion::V0 => "v0",
    };
    lines.push(format!(
        "Solana {} transaction · {} account key(s) · {} instruction(s) · {} signature slot(s)",
        ver,
        tx.message.account_keys.len(),
        tx.message.instructions.len(),
        tx.signatures.len()
    ));

    if !tx.message.address_table_lookups.is_empty() {
        lines.push(format!(
            "Uses {} address-lookup table(s) — some accounts are resolved at runtime",
            tx.message.address_table_lookups.len()
        ));
    }

    for (i, ix) in tx.message.instructions.iter().enumerate() {
        lines.push(format!("{}. {}", i + 1, narrate_instruction(tx, ix)));
    }

    lines.join("\n")
}

fn narrate_instruction(tx: &DecodedTransaction, ix: &CompiledInstruction) -> String {
    let Some(program) = tx.program_id_for(ix) else {
        return format!(
            "Unknown program index {} (out of range)",
            ix.program_id_index
        );
    };

    let label = program_label(program).unwrap_or("Unknown program");
    let detail = decode_ix_detail(tx, program, ix);
    format!("[{label}] {detail}  (program {})", short_pk(program))
}

fn decode_ix_detail(tx: &DecodedTransaction, program: &Pubkey, ix: &CompiledInstruction) -> String {
    if *program == system_program() {
        return narrate_system(tx, ix);
    }
    if is_token_family(program) {
        return narrate_token(tx, ix, *program == token_2022_program());
    }
    if *program == bpf_upgradeable_loader() {
        return narrate_bpf_loader(ix);
    }
    if program_label(program) == Some("Compute Budget") {
        return narrate_compute_budget(ix);
    }

    format!(
        "invokes with {} account(s), {} byte(s) of data",
        ix.accounts.len(),
        ix.data.len()
    )
}

fn narrate_system(tx: &DecodedTransaction, ix: &CompiledInstruction) -> String {
    let disc = ix.data.first().copied().unwrap_or(255);
    match disc {
        0 => "CreateAccount".into(),
        1 => "Assign — changes account owner".into(),
        2 => {
            let lamports = read_u64_le(ix.data.get(4..12).unwrap_or(&[]));
            let from = ix
                .accounts
                .first()
                .and_then(|i| tx.account_at(*i))
                .map(short_pk)
                .unwrap_or_else(|| "?".into());
            let to = ix
                .accounts
                .get(1)
                .and_then(|i| tx.account_at(*i))
                .map(short_pk)
                .unwrap_or_else(|| "?".into());
            match lamports {
                Some(l) => format!(
                    "Transfer {:.9} SOL from {from} → {to}",
                    l as f64 / 1_000_000_000.0
                ),
                None => format!("Transfer (lamports unreadable) from {from} → {to}"),
            }
        }
        3 => "CreateAccountWithSeed".into(),
        4 => "AdvanceNonceAccount".into(),
        5 => "WithdrawNonceAccount".into(),
        6 => "InitializeNonceAccount".into(),
        7 => "AuthorizeNonceAccount — durable nonce authority change".into(),
        8 => "Allocate".into(),
        9 => "AllocateWithSeed".into(),
        10 => "AssignWithSeed".into(),
        11 => {
            let lamports = read_u64_le(ix.data.get(4..12).unwrap_or(&[]));
            match lamports {
                Some(l) => format!("TransferWithSeed {:.9} SOL", l as f64 / 1_000_000_000.0),
                None => "TransferWithSeed".into(),
            }
        }
        _ => format!("System instruction discriminant {disc}"),
    }
}

fn narrate_token(tx: &DecodedTransaction, ix: &CompiledInstruction, is_token_2022: bool) -> String {
    let disc = ix.data.first().copied().unwrap_or(255);
    match disc {
        3 => {
            let amount = read_u64_le(ix.data.get(1..9).unwrap_or(&[]));
            let src = account_short(tx, ix, 0);
            let dst = account_short(tx, ix, 1);
            match amount {
                Some(a) => format!("Transfer {a} token units {src} → {dst}"),
                None => format!("Transfer {src} → {dst}"),
            }
        }
        4 => {
            let amount = read_u64_le(ix.data.get(1..9).unwrap_or(&[]));
            let delegate = account_short(tx, ix, 1);
            match amount {
                Some(a) if a == u64::MAX => {
                    format!("Approve MAX (unlimited) delegate → {delegate}")
                }
                Some(a) => format!("Approve {a} token units to delegate {delegate}"),
                None => format!("Approve delegate {delegate}"),
            }
        }
        6 => {
            let auth_type = ix.data.get(1).copied();
            let new_auth = if ix.data.get(2).copied() == Some(1) {
                // COption::Some — next 32 bytes are pubkey; account index varies
                "new authority present".to_string()
            } else {
                "CLEAR authority (set to None)".to_string()
            };
            let kind = match auth_type {
                Some(0) => "MintTokens",
                Some(1) => "FreezeAccount",
                Some(2) => "AccountOwner",
                Some(3) => "CloseAccount",
                _ => "Unknown",
            };
            format!("SetAuthority ({kind}) — {new_auth}")
        }
        7 => {
            let amount = read_u64_le(ix.data.get(1..9).unwrap_or(&[]));
            match amount {
                Some(a) => format!("MintTo {a} token units"),
                None => "MintTo".into(),
            }
        }
        8 => "Burn tokens — permanently destroys token units".into(),
        9 => "CloseAccount — reclaim rent, destination receives lamports".into(),
        10 => "FreezeAccount — blocks transfers from a token account".into(),
        11 => "ThawAccount — restores transfers from a frozen token account".into(),
        12 => {
            let amount = read_u64_le(ix.data.get(1..9).unwrap_or(&[]));
            let decimals = ix.data.get(9).copied();
            let src = account_short(tx, ix, 0);
            let dst = account_short(tx, ix, 2);
            match (amount, decimals) {
                (Some(a), Some(d)) => {
                    format!("TransferChecked {a} (decimals={d}) {src} → {dst}")
                }
                _ => format!("TransferChecked {src} → {dst}"),
            }
        }
        13 => "ApproveChecked".into(),
        14 => "MintToChecked".into(),
        15 => "BurnChecked — permanently destroys token units".into(),
        17 => "SyncNative".into(),
        18 => "InitializeAccount3".into(),
        21 => "GetAccountDataSize".into(),
        32 if is_token_2022 => "InitializeNonTransferableMint".into(),
        35 if is_token_2022 => {
            let delegate = ix
                .data
                .get(1..33)
                .and_then(|bytes| Pubkey::from_slice(bytes).ok())
                .map(|pk| short_pk(&pk))
                .unwrap_or_else(|| "?".into());
            format!(
                "InitializePermanentDelegate — {delegate} can transfer or burn any holder's tokens"
            )
        }
        36 if is_token_2022 => match ix.data.get(1).copied() {
            Some(0) => "InitializeTransferHook — external program runs on every transfer".into(),
            Some(1) => "UpdateTransferHook — changes the program run on every transfer".into(),
            Some(subdisc) => format!("TransferHook extension instruction {subdisc}"),
            None => "TransferHook extension (malformed)".into(),
        },
        _ => format!("Token instruction discriminant {disc}"),
    }
}

fn narrate_bpf_loader(ix: &CompiledInstruction) -> String {
    let disc = read_u32_le(ix.data.get(..4).unwrap_or(&[]));
    match disc {
        Some(1) => "Write program data".into(),
        Some(2) => "DeployWithMaxDataLen".into(),
        Some(3) => "Upgrade — replaces on-chain program bytecode".into(),
        Some(4) => "SetAuthority — changes upgrade authority".into(),
        Some(5) => "Close program/buffer account".into(),
        Some(6) => "ExtendProgram".into(),
        _ => format!("BPF loader instruction {disc:?}"),
    }
}

fn narrate_compute_budget(ix: &CompiledInstruction) -> String {
    match ix.data.first().copied() {
        Some(0) => "RequestUnitsDeprecated".into(),
        Some(1) => "RequestHeapFrame".into(),
        Some(2) => {
            let units = read_u32_le(ix.data.get(1..5).unwrap_or(&[]));
            match units {
                Some(u) => format!("SetComputeUnitLimit {u}"),
                None => "SetComputeUnitLimit".into(),
            }
        }
        Some(3) => {
            let price = read_u64_le(ix.data.get(1..9).unwrap_or(&[]));
            match price {
                Some(p) => format!("SetComputeUnitPrice {p} µ-lamports"),
                None => "SetComputeUnitPrice".into(),
            }
        }
        Some(4) => "SetLoadedAccountsDataSizeLimit".into(),
        _ => "Compute budget instruction".into(),
    }
}

fn account_short(tx: &DecodedTransaction, ix: &CompiledInstruction, idx: usize) -> String {
    ix.accounts
        .get(idx)
        .and_then(|i| tx.account_at(*i))
        .map(short_pk)
        .unwrap_or_else(|| "?".into())
}

fn short_pk(pk: &Pubkey) -> String {
    let s = pk.to_base58();
    if s.len() <= 12 {
        s
    } else {
        format!("{}…{}", &s[..4], &s[s.len() - 4..])
    }
}

fn read_u64_le(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[..8]);
    Some(u64::from_le_bytes(arr))
}

fn read_u32_le(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[..4]);
    Some(u32::from_le_bytes(arr))
}
