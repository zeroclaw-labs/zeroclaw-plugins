//! Risk classification — danger primitives → findings + severity.

use crate::core::programs::{
    bpf_upgradeable_loader, is_token_family, program_label, system_program, token_2022_program,
};
use crate::core::tx::DecodedTransaction;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub instruction_index: usize,
    pub message: String,
}

/// Assess a decoded transaction and return ordered findings (highest severity first).
pub fn assess(tx: &DecodedTransaction) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !tx.message.address_table_lookups.is_empty() {
        findings.push(Finding {
            code: "ALT_USED".into(),
            severity: Severity::High,
            instruction_index: 0,
            message: format!(
                "Transaction uses {} address-lookup table(s); unresolved accounts can hide counterparties",
                tx.message.address_table_lookups.len()
            ),
        });
    }

    for (i, ix) in tx.message.instructions.iter().enumerate() {
        let Some(program) = tx.program_id_for(ix) else {
            findings.push(Finding {
                code: "BAD_PROGRAM_INDEX".into(),
                severity: Severity::High,
                instruction_index: i,
                message: "Instruction program_id_index is out of range".into(),
            });
            continue;
        };

        if *program == system_program() {
            assess_system(i, ix.data.first().copied(), &mut findings);
        } else if is_token_family(program) {
            assess_token(
                i,
                ix.data.first().copied(),
                &ix.data,
                *program == token_2022_program(),
                &mut findings,
            );
        } else if *program == bpf_upgradeable_loader() {
            assess_bpf(i, &ix.data, &mut findings);
        } else if program_label(program).is_none() {
            // Unknown program with any writable-looking account list → caution
            findings.push(Finding {
                code: "UNKNOWN_PROGRAM".into(),
                severity: Severity::High,
                instruction_index: i,
                message: format!(
                    "Invokes unrecognized program {} with {} account(s)",
                    program.to_base58(),
                    ix.accounts.len()
                ),
            });
        }
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

fn assess_system(i: usize, disc: Option<u8>, findings: &mut Vec<Finding>) {
    match disc {
        Some(1) | Some(10) => findings.push(Finding {
            code: "SYSTEM_ASSIGN".into(),
            severity: Severity::Critical,
            instruction_index: i,
            message: "System Assign changes account owner — classic takeover primitive".into(),
        }),
        Some(7) => findings.push(Finding {
            code: "NONCE_AUTHORIZE".into(),
            severity: Severity::High,
            instruction_index: i,
            message: "AuthorizeNonceAccount changes durable-nonce authority".into(),
        }),
        Some(2) | Some(11) => findings.push(Finding {
            code: "SOL_TRANSFER".into(),
            severity: Severity::Low,
            instruction_index: i,
            message: "Native SOL transfer".into(),
        }),
        _ => {}
    }
}

fn assess_token(
    i: usize,
    disc: Option<u8>,
    data: &[u8],
    is_token_2022: bool,
    findings: &mut Vec<Finding>,
) {
    match disc {
        Some(4) | Some(13) => {
            let unlimited = data
                .get(1..9)
                .map(|b| {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(b);
                    u64::from_le_bytes(arr)
                })
                .is_some_and(|a| a == u64::MAX);
            findings.push(Finding {
                code: if unlimited {
                    "TOKEN_APPROVE_MAX".into()
                } else {
                    "TOKEN_APPROVE".into()
                },
                severity: if unlimited {
                    Severity::Critical
                } else {
                    Severity::High
                },
                instruction_index: i,
                message: if unlimited {
                    "Approve with u64::MAX — unlimited spending delegate".into()
                } else {
                    "Token Approve grants a spending delegate".into()
                },
            });
        }
        Some(6) => {
            let auth_type = data.get(1).copied();
            let clearing = data.get(2).copied() == Some(0);
            let (code, sev, msg) = match (auth_type, clearing) {
                (Some(0), true) => (
                    "MINT_AUTHORITY_CLEARED",
                    Severity::High,
                    "Mint authority cleared (irreversible if intentional)",
                ),
                (Some(0), _) => (
                    "MINT_AUTHORITY_CHANGE",
                    Severity::Critical,
                    "SetAuthority MintTokens — mint control is transferring",
                ),
                (Some(1), _) => (
                    "FREEZE_AUTHORITY_CHANGE",
                    Severity::Critical,
                    "SetAuthority FreezeAccount — freeze control is transferring",
                ),
                (Some(2), _) => (
                    "TOKEN_OWNER_CHANGE",
                    Severity::Critical,
                    "SetAuthority AccountOwner — token account ownership change",
                ),
                _ => ("TOKEN_SET_AUTHORITY", Severity::High, "Token SetAuthority"),
            };
            findings.push(Finding {
                code: code.into(),
                severity: sev,
                instruction_index: i,
                message: msg.into(),
            });
        }
        Some(7) | Some(14) => findings.push(Finding {
            code: "TOKEN_MINT_TO".into(),
            severity: Severity::High,
            instruction_index: i,
            message: "MintTo creates new token supply".into(),
        }),
        Some(8) | Some(15) => findings.push(Finding {
            code: "TOKEN_BURN".into(),
            severity: Severity::High,
            instruction_index: i,
            message: "Burn permanently destroys token units".into(),
        }),
        Some(9) => findings.push(Finding {
            code: "TOKEN_CLOSE_ACCOUNT".into(),
            severity: Severity::Medium,
            instruction_index: i,
            message: "CloseAccount — token account closed, lamports sent elsewhere".into(),
        }),
        Some(10) => findings.push(Finding {
            code: "TOKEN_FREEZE_ACCOUNT".into(),
            severity: Severity::High,
            instruction_index: i,
            message: "FreezeAccount blocks transfers from a token account".into(),
        }),
        Some(11) => findings.push(Finding {
            code: "TOKEN_THAW_ACCOUNT".into(),
            severity: Severity::Medium,
            instruction_index: i,
            message: "ThawAccount restores transfers from a frozen token account".into(),
        }),
        Some(3) | Some(12) => findings.push(Finding {
            code: "TOKEN_TRANSFER".into(),
            severity: Severity::Low,
            instruction_index: i,
            message: "SPL token transfer".into(),
        }),
        Some(32) if is_token_2022 => findings.push(Finding {
            code: "TOKEN_2022_NON_TRANSFERABLE".into(),
            severity: Severity::Medium,
            instruction_index: i,
            message: "Token-2022 mint is being made non-transferable".into(),
        }),
        Some(35) if is_token_2022 => findings.push(Finding {
            code: "TOKEN_2022_PERMANENT_DELEGATE".into(),
            severity: Severity::Critical,
            instruction_index: i,
            message: "Permanent delegate can transfer or burn tokens from any holder account"
                .into(),
        }),
        Some(36) if is_token_2022 => {
            let (code, message) = match data.get(1).copied() {
                Some(0) => (
                    "TOKEN_2022_TRANSFER_HOOK_INIT",
                    "Transfer hook adds an external program call to every token transfer",
                ),
                Some(1) => (
                    "TOKEN_2022_TRANSFER_HOOK_UPDATE",
                    "Transfer hook program is being changed",
                ),
                _ => (
                    "TOKEN_2022_TRANSFER_HOOK",
                    "Token-2022 transfer-hook instruction requires review",
                ),
            };
            findings.push(Finding {
                code: code.into(),
                severity: Severity::High,
                instruction_index: i,
                message: message.into(),
            });
        }
        _ => {}
    }
}

fn assess_bpf(i: usize, data: &[u8], findings: &mut Vec<Finding>) {
    let disc = data.get(..4).map(|b| {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(b);
        u32::from_le_bytes(arr)
    });
    match disc {
        Some(3) => findings.push(Finding {
            code: "PROGRAM_UPGRADE".into(),
            severity: Severity::Critical,
            instruction_index: i,
            message: "Upgradeable loader Upgrade — on-chain program bytecode will change".into(),
        }),
        Some(4) => findings.push(Finding {
            code: "UPGRADE_AUTHORITY_CHANGE".into(),
            severity: Severity::Critical,
            instruction_index: i,
            message: "Upgradeable loader SetAuthority — upgrade authority transferring".into(),
        }),
        Some(5) => findings.push(Finding {
            code: "PROGRAM_CLOSE".into(),
            severity: Severity::High,
            instruction_index: i,
            message: "Upgradeable loader Close".into(),
        }),
        _ => {}
    }
}

/// Highest severity among findings, if any.
pub fn max_severity(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}
