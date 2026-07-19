//! SPL Token transfer + ATA create + memo instruction builders (no solana-sdk).

use crate::encode::Writer;
use crate::pubkey::{
    associated_token_program, get_associated_token_address, memo_program, system_program,
    token_program, Pubkey,
};
use crate::quote::usdc_to_base_units;
use crate::tx::{AccountMeta, Instruction};

#[derive(Debug, Clone)]
pub struct SplTransferRequest {
    pub payer: Pubkey,
    pub source_owner: Pubkey,
    pub destination_owner: Pubkey,
    pub mint: Pubkey,
    /// Decimal USDC string (6 decimals).
    pub amount: String,
    pub memo: Option<String>,
    /// When true, prepend create-idempotent ATA for destination.
    pub create_dest_ata: bool,
}

#[derive(Debug, Clone)]
pub struct SplTransferPlan {
    pub instructions: Vec<Instruction>,
    pub source_ata: Pubkey,
    pub dest_ata: Pubkey,
    pub amount_base_units: u64,
    pub summary_lines: Vec<String>,
}

pub fn build_spl_transfer_plan(req: &SplTransferRequest) -> Result<SplTransferPlan, String> {
    let amount_base_units = usdc_to_base_units(&req.amount)?;
    if amount_base_units == 0 {
        return Err("amount must be > 0".into());
    }
    let source_ata = get_associated_token_address(&req.source_owner, &req.mint)?;
    let dest_ata = get_associated_token_address(&req.destination_owner, &req.mint)?;

    let mut instructions = Vec::new();
    if req.create_dest_ata {
        instructions.push(create_associated_token_account_idempotent(
            &req.payer,
            &req.destination_owner,
            &req.mint,
        ));
    }
    if let Some(memo) = &req.memo {
        instructions.push(memo_instruction(memo, &[&req.payer]));
    }
    instructions.push(spl_transfer_checked(
        &source_ata,
        &req.mint,
        &dest_ata,
        &req.source_owner,
        amount_base_units,
        6,
    ));

    let summary_lines = vec![
        format!("SPL transfer {}", req.amount),
        format!("mint {}", req.mint.short()),
        format!("from {} (ata {})", req.source_owner.short(), source_ata.short()),
        format!("to {} (ata {})", req.destination_owner.short(), dest_ata.short()),
        if req.create_dest_ata {
            "create destination ATA if needed".into()
        } else {
            "assume destination ATA exists".into()
        },
    ];

    Ok(SplTransferPlan {
        instructions,
        source_ata,
        dest_ata,
        amount_base_units,
        summary_lines,
    })
}

/// Associated Token Account Program: CreateIdempotent (ix index 1).
pub fn create_associated_token_account_idempotent(
    payer: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
) -> Instruction {
    let ata = get_associated_token_address(wallet, mint).expect("ata");
    Instruction {
        program_id: associated_token_program(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata, false),
            AccountMeta::readonly(*wallet, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::readonly(system_program(), false),
            AccountMeta::readonly(token_program(), false),
        ],
        data: vec![1], // CreateIdempotent
    }
}

/// SPL Token TransferChecked (ix index 12).
pub fn spl_transfer_checked(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Writer::with_capacity(1 + 8 + 1);
    data.push(12);
    data.push_u64_le(amount);
    data.push(decimals);
    Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::readonly(*owner, true),
        ],
        data: data.into_vec(),
    }
}

pub fn memo_instruction(memo: &str, signers: &[&Pubkey]) -> Instruction {
    let mut accounts = Vec::new();
    for s in signers {
        accounts.push(AccountMeta::readonly(**s, true));
    }
    Instruction {
        program_id: memo_program(),
        accounts,
        data: memo.as_bytes().to_vec(),
    }
}

/// System Program AdvanceNonceAccount (ix index 4).
pub fn advance_nonce_instruction(nonce_account: &Pubkey, nonce_authority: &Pubkey) -> Instruction {
    let mut data = Writer::with_capacity(4);
    data.push_u32_le(4);
    Instruction {
        program_id: system_program(),
        accounts: vec![
            AccountMeta::new(*nonce_account, false),
            // RecentBlockhashes sysvar
            AccountMeta::readonly(
                Pubkey::from_base58("SysvarRecentB1ockHashes11111111111111111111").expect("sysvar"),
                false,
            ),
            AccountMeta::readonly(*nonce_authority, true),
        ],
        data: data.into_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubkey::{usdc_mint_mainnet, SYSTEM_PROGRAM_ID};

    #[test]
    fn builds_transfer_plan() {
        let payer = Pubkey::from_base58("11111111111111111111111111111112").unwrap_or(SYSTEM_PROGRAM_ID);
        // Use a valid 32-byte key — decode a known pubkey.
        let owner = Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let dest = Pubkey::from_base58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();
        let plan = build_spl_transfer_plan(&SplTransferRequest {
            payer: owner,
            source_owner: owner,
            destination_owner: dest,
            mint: usdc_mint_mainnet(),
            amount: "25.00".into(),
            memo: Some("INV=412 BRL=25.00".into()),
            create_dest_ata: true,
        })
        .unwrap();
        assert_eq!(plan.amount_base_units, 25_000_000);
        assert_eq!(plan.instructions.len(), 3);
        let _ = payer;
    }
}
