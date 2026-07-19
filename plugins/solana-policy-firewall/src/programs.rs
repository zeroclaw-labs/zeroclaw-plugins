//! Deterministic interpretation of the small set of Solana instructions the
//! firewall can prove safe. Anything outside this set is deliberately opaque
//! and therefore denied by the policy engine.

use std::collections::BTreeMap;

use crate::rpc::RpcClient;
use crate::transaction::{AccountMetaView, ParsedInstruction, ParsedTransaction};

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
pub const MEMO_V1_PROGRAM: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";
pub const RECENT_BLOCKHASHES_SYSVAR: &str = "SysvarRecentB1ockHashes11111111111111111111";
pub const TOKEN_ACCOUNT_DATA_LEN: usize = 165;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    SolTransfer {
        source: String,
        recipient: String,
        lamports: u64,
    },
    TokenTransfer {
        source_account: String,
        destination_account: String,
        recipient_owner: String,
        authority: String,
        mint: String,
        amount: u64,
        decimals: Option<u8>,
    },
    CreateAssociatedTokenAccount {
        account: String,
        recipient_owner: String,
        mint: String,
    },
    AdvanceNonce {
        nonce_account: String,
        authority: String,
        durable_nonce: String,
        lamports_per_signature: u64,
    },
    ComputeUnitLimit(u32),
    ComputeUnitPrice(u64),
    Memo,
    Dangerous {
        code: &'static str,
        detail: String,
    },
    Opaque {
        program_id: String,
        detail: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TokenAccountInfo {
    mint: String,
    owner: String,
}

pub fn analyze_instructions(
    transaction: &ParsedTransaction,
    rpc: &mut dyn RpcClient,
) -> Result<Vec<Operation>, String> {
    let mut transient_token_accounts = BTreeMap::new();
    for instruction in &transaction.instructions {
        if instruction.program_id == ASSOCIATED_TOKEN_PROGRAM {
            if let Some(info) = associated_token_account_info(instruction) {
                transient_token_accounts.insert(info.0, info.1);
            }
        }
    }

    let mut token_account_cache = BTreeMap::new();
    transaction
        .instructions
        .iter()
        .enumerate()
        .map(|(instruction_index, instruction)| {
            analyze_instruction(
                transaction,
                instruction_index,
                instruction,
                rpc,
                &transient_token_accounts,
                &mut token_account_cache,
            )
        })
        .collect()
}

fn analyze_instruction(
    transaction: &ParsedTransaction,
    instruction_index: usize,
    instruction: &ParsedInstruction,
    rpc: &mut dyn RpcClient,
    transient: &BTreeMap<String, TokenAccountInfo>,
    cache: &mut BTreeMap<String, TokenAccountInfo>,
) -> Result<Operation, String> {
    match instruction.program_id.as_str() {
        SYSTEM_PROGRAM => analyze_system(transaction, instruction_index, instruction, rpc),
        TOKEN_PROGRAM => analyze_token(instruction, rpc, transient, cache),
        TOKEN_2022_PROGRAM => Ok(Operation::Dangerous {
            code: "token_2022_extensions_not_supported",
            detail: "Token-2022 transfer hooks, permanent delegates, fees, and other extensions require separate proof and are denied".to_string(),
        }),
        ASSOCIATED_TOKEN_PROGRAM => analyze_associated_token(instruction),
        COMPUTE_BUDGET_PROGRAM => analyze_compute_budget(instruction),
        MEMO_PROGRAM | MEMO_V1_PROGRAM => analyze_memo(instruction),
        _ => Ok(Operation::Opaque {
            program_id: instruction.program_id.clone(),
            detail: "program semantics are not proven by this firewall".to_string(),
        }),
    }
}

fn analyze_system(
    transaction: &ParsedTransaction,
    instruction_index: usize,
    instruction: &ParsedInstruction,
    rpc: &mut dyn RpcClient,
) -> Result<Operation, String> {
    let tag = read_u32(&instruction.data, 0, "system instruction tag")?;
    if tag == 2 {
        require_exact_len(&instruction.data, 12, "system transfer")?;
        require_accounts(instruction, 2, "system transfer")?;
        return Ok(Operation::SolTransfer {
            source: instruction.accounts[0].clone(),
            recipient: instruction.accounts[1].clone(),
            lamports: read_u64(&instruction.data, 4, "system transfer lamports")?,
        });
    }
    if tag == 4 {
        return analyze_advance_nonce(transaction, instruction_index, instruction, rpc);
    }

    let code = match tag {
        0 | 3 => "system_account_creation",
        1 | 10 => "system_owner_assignment",
        5 | 6 | 7 | 12 => "nonce_authority_operation",
        8 | 9 => "system_allocation",
        11 => "transfer_with_seed_not_supported",
        _ => "unknown_system_instruction",
    };
    Ok(Operation::Dangerous {
        code,
        detail: format!("System Program instruction {tag} is outside the transfer-only policy"),
    })
}

fn analyze_advance_nonce(
    transaction: &ParsedTransaction,
    instruction_index: usize,
    instruction: &ParsedInstruction,
    rpc: &mut dyn RpcClient,
) -> Result<Operation, String> {
    require_exact_len(&instruction.data, 4, "AdvanceNonceAccount")?;
    require_exact_accounts(instruction, 3, "AdvanceNonceAccount")?;
    if instruction_index != 0 {
        return Ok(Operation::Dangerous {
            code: "nonce_advance_not_first",
            detail: "AdvanceNonceAccount must be the first transaction instruction".to_string(),
        });
    }
    if instruction.accounts[1] != RECENT_BLOCKHASHES_SYSVAR {
        return Ok(Operation::Dangerous {
            code: "nonce_sysvar_mismatch",
            detail: "AdvanceNonceAccount must use the recent-blockhashes sysvar".to_string(),
        });
    }

    let nonce_account = unique_account(transaction, &instruction.accounts[0])?;
    let authority = unique_account(transaction, &instruction.accounts[2])?;
    if !nonce_account.writable {
        return Ok(Operation::Dangerous {
            code: "nonce_account_not_writable",
            detail: "durable nonce account must be writable".to_string(),
        });
    }
    if !authority.signer {
        return Ok(Operation::Dangerous {
            code: "nonce_authority_not_signer",
            detail: "durable nonce authority must be a required signer".to_string(),
        });
    }

    let account = rpc
        .get_account(&instruction.accounts[0])?
        .ok_or_else(|| format!("nonce account {} does not exist", instruction.accounts[0]))?;
    if account.owner != SYSTEM_PROGRAM {
        return Err(format!(
            "nonce account {} is owned by {} instead of System Program",
            instruction.accounts[0], account.owner
        ));
    }
    let state = parse_nonce_account(&account.data)?;
    if state.authority != instruction.accounts[2] {
        return Ok(Operation::Dangerous {
            code: "nonce_authority_mismatch",
            detail: format!(
                "nonce authority {} does not match instruction authority {}",
                state.authority, instruction.accounts[2]
            ),
        });
    }
    if state.durable_nonce != transaction.recent_blockhash {
        return Ok(Operation::Dangerous {
            code: "durable_nonce_mismatch",
            detail: "transaction recent blockhash does not match current nonce account state"
                .to_string(),
        });
    }

    Ok(Operation::AdvanceNonce {
        nonce_account: instruction.accounts[0].clone(),
        authority: state.authority,
        durable_nonce: state.durable_nonce,
        lamports_per_signature: state.lamports_per_signature,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NonceAccountState {
    authority: String,
    durable_nonce: String,
    lamports_per_signature: u64,
}

fn parse_nonce_account(data: &[u8]) -> Result<NonceAccountState, String> {
    if data.len() != 80 {
        return Err(format!(
            "nonce account has {} bytes; expected canonical 80-byte state",
            data.len()
        ));
    }
    let version = read_u32(data, 0, "nonce version")?;
    if version != 1 {
        return Err("nonce account is not the current durable-nonce version".to_string());
    }
    let state = read_u32(data, 4, "nonce state")?;
    if state != 1 {
        return Err("nonce account is not initialized".to_string());
    }
    Ok(NonceAccountState {
        authority: bs58::encode(&data[8..40]).into_string(),
        durable_nonce: bs58::encode(&data[40..72]).into_string(),
        lamports_per_signature: read_u64(data, 72, "nonce fee calculator")?,
    })
}

fn unique_account<'a>(
    transaction: &'a ParsedTransaction,
    address: &str,
) -> Result<&'a AccountMetaView, String> {
    let mut matches = transaction
        .accounts
        .iter()
        .filter(|account| account.address == address);
    let account = matches
        .next()
        .ok_or_else(|| format!("instruction account {address} is not in the transaction"))?;
    if matches.next().is_some() {
        return Err(format!(
            "transaction repeats account {address}; nonce metadata is ambiguous"
        ));
    }
    Ok(account)
}

fn analyze_token(
    instruction: &ParsedInstruction,
    rpc: &mut dyn RpcClient,
    transient: &BTreeMap<String, TokenAccountInfo>,
    cache: &mut BTreeMap<String, TokenAccountInfo>,
) -> Result<Operation, String> {
    let tag = *instruction
        .data
        .first()
        .ok_or_else(|| "token instruction has no discriminator".to_string())?;
    match tag {
        3 => {
            require_exact_len(&instruction.data, 9, "SPL Transfer")?;
            require_accounts(instruction, 3, "SPL Transfer")?;
            let source = token_account_info(
                &instruction.accounts[0],
                &instruction.program_id,
                rpc,
                transient,
                cache,
            )?;
            let destination = token_account_info(
                &instruction.accounts[1],
                &instruction.program_id,
                rpc,
                transient,
                cache,
            )?;
            if source.mint != destination.mint {
                return Err("SPL Transfer source and destination mints differ".to_string());
            }
            Ok(Operation::TokenTransfer {
                source_account: instruction.accounts[0].clone(),
                destination_account: instruction.accounts[1].clone(),
                recipient_owner: destination.owner,
                authority: instruction.accounts[2].clone(),
                mint: source.mint,
                amount: read_u64(&instruction.data, 1, "SPL Transfer amount")?,
                decimals: None,
            })
        }
        12 => {
            require_exact_len(&instruction.data, 10, "SPL TransferChecked")?;
            require_accounts(instruction, 4, "SPL TransferChecked")?;
            let source = token_account_info(
                &instruction.accounts[0],
                &instruction.program_id,
                rpc,
                transient,
                cache,
            )?;
            let destination = token_account_info(
                &instruction.accounts[2],
                &instruction.program_id,
                rpc,
                transient,
                cache,
            )?;
            let mint = &instruction.accounts[1];
            if source.mint != *mint || destination.mint != *mint {
                return Err(
                    "SPL TransferChecked mint does not match token-account state".to_string(),
                );
            }
            Ok(Operation::TokenTransfer {
                source_account: instruction.accounts[0].clone(),
                destination_account: instruction.accounts[2].clone(),
                recipient_owner: destination.owner,
                authority: instruction.accounts[3].clone(),
                mint: mint.clone(),
                amount: read_u64(&instruction.data, 1, "SPL TransferChecked amount")?,
                decimals: Some(instruction.data[9]),
            })
        }
        4 | 13 => Ok(dangerous_token(
            "token_delegate_approval",
            "token approval can grant a third party spending power",
        )),
        5 => Ok(dangerous_token(
            "token_delegate_change",
            "token delegate state changes are not payment instructions",
        )),
        6 => Ok(dangerous_token(
            "token_authority_change",
            "SetAuthority can permanently transfer asset control",
        )),
        7 | 14 => Ok(dangerous_token(
            "token_mint",
            "minting tokens is outside the payment-only policy",
        )),
        8 | 15 => Ok(dangerous_token(
            "token_burn",
            "burning tokens is irreversible",
        )),
        9 => Ok(dangerous_token(
            "token_account_close",
            "closing a token account redirects its rent balance",
        )),
        10 | 11 => Ok(dangerous_token(
            "token_freeze_change",
            "freezing or thawing token accounts changes control state",
        )),
        _ => Ok(dangerous_token(
            "token_instruction_not_supported",
            &format!("SPL Token instruction {tag} is not proven safe"),
        )),
    }
}

fn dangerous_token(code: &'static str, detail: &str) -> Operation {
    Operation::Dangerous {
        code,
        detail: detail.to_string(),
    }
}

fn analyze_associated_token(instruction: &ParsedInstruction) -> Result<Operation, String> {
    let supported = instruction.data.is_empty()
        || instruction.data.as_slice() == [0]
        || instruction.data.as_slice() == [1];
    if !supported {
        return Ok(Operation::Dangerous {
            code: "associated_token_instruction_not_supported",
            detail: "only create and create-idempotent ATA instructions are supported".to_string(),
        });
    }
    require_accounts(instruction, 6, "associated token account creation")?;
    if instruction.accounts[5] != TOKEN_PROGRAM {
        return Ok(Operation::Dangerous {
            code: "ata_token_program_not_supported",
            detail: "only classic SPL Token associated accounts are proven safe".to_string(),
        });
    }
    Ok(Operation::CreateAssociatedTokenAccount {
        account: instruction.accounts[1].clone(),
        recipient_owner: instruction.accounts[2].clone(),
        mint: instruction.accounts[3].clone(),
    })
}

fn associated_token_account_info(
    instruction: &ParsedInstruction,
) -> Option<(String, TokenAccountInfo)> {
    let supported = instruction.data.is_empty()
        || instruction.data.as_slice() == [0]
        || instruction.data.as_slice() == [1];
    if !supported || instruction.accounts.len() < 6 || instruction.accounts[5] != TOKEN_PROGRAM {
        return None;
    }
    Some((
        instruction.accounts[1].clone(),
        TokenAccountInfo {
            owner: instruction.accounts[2].clone(),
            mint: instruction.accounts[3].clone(),
        },
    ))
}

fn analyze_compute_budget(instruction: &ParsedInstruction) -> Result<Operation, String> {
    let tag = *instruction
        .data
        .first()
        .ok_or_else(|| "compute-budget instruction has no discriminator".to_string())?;
    match tag {
        2 => {
            require_exact_len(&instruction.data, 5, "SetComputeUnitLimit")?;
            Ok(Operation::ComputeUnitLimit(read_u32(
                &instruction.data,
                1,
                "compute unit limit",
            )?))
        }
        3 => {
            require_exact_len(&instruction.data, 9, "SetComputeUnitPrice")?;
            Ok(Operation::ComputeUnitPrice(read_u64(
                &instruction.data,
                1,
                "compute unit price",
            )?))
        }
        _ => Ok(Operation::Dangerous {
            code: "compute_budget_instruction_not_supported",
            detail: format!("Compute Budget instruction {tag} is not supported"),
        }),
    }
}

fn analyze_memo(instruction: &ParsedInstruction) -> Result<Operation, String> {
    if instruction.data.len() > 128 {
        return Ok(Operation::Dangerous {
            code: "memo_too_large",
            detail: "memo exceeds the 128-byte policy limit".to_string(),
        });
    }
    std::str::from_utf8(&instruction.data).map_err(|_| "memo is not valid UTF-8".to_string())?;
    Ok(Operation::Memo)
}

fn token_account_info(
    address: &str,
    token_program: &str,
    rpc: &mut dyn RpcClient,
    transient: &BTreeMap<String, TokenAccountInfo>,
    cache: &mut BTreeMap<String, TokenAccountInfo>,
) -> Result<TokenAccountInfo, String> {
    if let Some(info) = transient.get(address) {
        return Ok(info.clone());
    }
    if let Some(info) = cache.get(address) {
        return Ok(info.clone());
    }
    let account = rpc
        .get_account(address)?
        .ok_or_else(|| format!("token account {address} does not exist"))?;
    if account.owner != token_program {
        return Err(format!(
            "token account {address} is owned by {} instead of {token_program}",
            account.owner
        ));
    }
    if account.data.len() < 64 {
        return Err(format!("token account {address} data is too short"));
    }
    let info = TokenAccountInfo {
        mint: bs58::encode(&account.data[0..32]).into_string(),
        owner: bs58::encode(&account.data[32..64]).into_string(),
    };
    cache.insert(address.to_string(), info.clone());
    Ok(info)
}

fn require_accounts(
    instruction: &ParsedInstruction,
    count: usize,
    label: &str,
) -> Result<(), String> {
    if instruction.accounts.len() < count {
        return Err(format!(
            "{label} has {} accounts; expected at least {count}",
            instruction.accounts.len()
        ));
    }
    Ok(())
}

fn require_exact_accounts(
    instruction: &ParsedInstruction,
    count: usize,
    label: &str,
) -> Result<(), String> {
    if instruction.accounts.len() != count {
        return Err(format!(
            "{label} has {} accounts; expected exactly {count}",
            instruction.accounts.len()
        ));
    }
    Ok(())
}

fn require_exact_len(data: &[u8], expected: usize, label: &str) -> Result<(), String> {
    if data.len() != expected {
        return Err(format!(
            "{label} has {} data bytes; expected {expected}",
            data.len()
        ));
    }
    Ok(())
}

fn read_u32(data: &[u8], offset: usize, label: &str) -> Result<u32, String> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| format!("{label} is truncated"))?
        .try_into()
        .map_err(|_| format!("{label} is malformed"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize, label: &str) -> Result<u64, String> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or_else(|| format!("{label} is truncated"))?
        .try_into()
        .map_err(|_| format!("{label} is malformed"))?;
    Ok(u64::from_le_bytes(bytes))
}
