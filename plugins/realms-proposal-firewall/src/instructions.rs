use crate::{
    governance::{GovernanceConfig, InstructionData, VoteThreshold, VoteTipping},
    pubkey::{
        associated_token_address, associated_token_program_id, bpf_upgradeable_loader_id,
        spl_token_program_id, system_program_id, token_2022_program_id, Pubkey,
    },
};

const RENT_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161,
    253, 68, 227, 219, 217, 138, 0, 0, 0, 0,
]);
const CLOCK_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155,
    75, 109, 92, 115, 85, 91, 33, 0, 0, 0, 0,
]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeOutcome {
    Decoded(Operation),
    Malformed(MalformedInstruction),
    UnsupportedProgram {
        program_id: Pubkey,
    },
    UnsupportedInstruction {
        program_id: Pubkey,
        tag: Option<u32>,
        reason: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MalformedInstruction {
    pub program_id: Pubkey,
    pub tag: u32,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenAuthorityType {
    MintTokens,
    FreezeAccount,
    AccountOwner,
    CloseAccount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociatedTokenCreateKind {
    Create,
    CreateIdempotent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmAuthorityAction {
    SetUnchecked,
    SetChecked,
    Remove,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    SystemTransfer {
        source: Pubkey,
        destination: Pubkey,
        lamports: u64,
    },
    TokenTransfer {
        source: Pubkey,
        destination: Pubkey,
        authority: Pubkey,
        amount: u64,
    },
    TokenApprove {
        source: Pubkey,
        delegate: Pubkey,
        authority: Pubkey,
        amount: u64,
    },
    TokenSetAuthority {
        account: Pubkey,
        current_authority: Pubkey,
        authority_type: TokenAuthorityType,
        new_authority: Option<Pubkey>,
    },
    TokenMintTo {
        mint: Pubkey,
        destination: Pubkey,
        authority: Pubkey,
        amount: u64,
    },
    TokenBurn {
        source: Pubkey,
        mint: Pubkey,
        authority: Pubkey,
        amount: u64,
    },
    TokenCloseAccount {
        account: Pubkey,
        destination: Pubkey,
        authority: Pubkey,
    },
    TokenTransferChecked {
        source: Pubkey,
        mint: Pubkey,
        destination: Pubkey,
        authority: Pubkey,
        amount: u64,
        decimals: u8,
    },
    AssociatedTokenCreate {
        kind: AssociatedTokenCreateKind,
        payer: Pubkey,
        account: Pubkey,
        owner: Pubkey,
        mint: Pubkey,
    },
    UpgradeableLoaderUpgrade {
        programdata: Pubkey,
        program: Pubkey,
        buffer: Pubkey,
        spill: Pubkey,
        current_authority: Pubkey,
        close_buffer: bool,
        versioned: bool,
    },
    UpgradeableLoaderSetAuthority {
        account: Pubkey,
        current_authority: Pubkey,
        new_authority: Option<Pubkey>,
        checked: bool,
        remove: bool,
    },
    SetGovernanceConfig {
        governance: Pubkey,
        config: GovernanceConfig,
    },
    SetRealmAuthority {
        realm: Pubkey,
        current_authority: Pubkey,
        new_authority: Option<Pubkey>,
        action: RealmAuthorityAction,
    },
}

pub fn decode_instruction(
    instruction: &InstructionData,
    governance_program_ids: &[Pubkey],
) -> DecodeOutcome {
    let program_id = instruction.program_id;
    if program_id == system_program_id() {
        decode_system(instruction)
    } else if program_id == spl_token_program_id() {
        decode_token(instruction)
    } else if program_id == associated_token_program_id() {
        decode_associated_token(instruction)
    } else if program_id == bpf_upgradeable_loader_id() {
        decode_loader(instruction)
    } else if program_id == token_2022_program_id() {
        DecodeOutcome::UnsupportedProgram { program_id }
    } else if governance_program_ids.contains(&program_id) {
        decode_governance(instruction)
    } else {
        DecodeOutcome::UnsupportedProgram { program_id }
    }
}

fn decode_system(ix: &InstructionData) -> DecodeOutcome {
    let Some(tag) = u32_tag(&ix.data) else {
        return unsupported(ix, None, "missing system instruction tag");
    };
    if tag != 2 {
        return unsupported(ix, Some(tag), "unsupported system instruction");
    }
    if ix.data.len() != 12 {
        return malformed(ix, tag, "system transfer data length");
    }
    if !metas(ix, &[(true, true), (false, true)]) {
        return malformed(ix, tag, "system transfer accounts");
    }
    DecodeOutcome::Decoded(Operation::SystemTransfer {
        source: ix.accounts[0].pubkey,
        destination: ix.accounts[1].pubkey,
        lamports: le_u64(&ix.data[4..12]),
    })
}

fn decode_token(ix: &InstructionData) -> DecodeOutcome {
    let Some(&tag) = ix.data.first() else {
        return unsupported(ix, None, "missing token instruction tag");
    };
    match tag {
        3 => decode_token_amount(ix, tag, TokenAmountKind::Transfer),
        4 => decode_token_amount(ix, tag, TokenAmountKind::Approve),
        6 => decode_token_set_authority(ix),
        7 => decode_token_amount(ix, tag, TokenAmountKind::MintTo),
        8 => decode_token_amount(ix, tag, TokenAmountKind::Burn),
        9 => decode_token_close(ix),
        12 => decode_token_checked(ix),
        _ => unsupported(ix, Some(tag as u32), "unsupported token instruction"),
    }
}

#[derive(Clone, Copy)]
enum TokenAmountKind {
    Transfer,
    Approve,
    MintTo,
    Burn,
}

fn decode_token_amount(ix: &InstructionData, tag: u8, kind: TokenAmountKind) -> DecodeOutcome {
    if ix.data.len() != 9 {
        return malformed(ix, tag as u32, "token instruction data length");
    }
    if token_multisig(ix, 2) {
        return unsupported(ix, Some(tag as u32), "token multisig authority");
    }
    let expected = [(false, true), (false, true), (true, false)];
    let approve = [(false, true), (false, false), (true, false)];
    let flags = if matches!(kind, TokenAmountKind::Approve) {
        &approve
    } else {
        &expected
    };
    if !metas(ix, flags) {
        return malformed(ix, tag as u32, "token instruction accounts");
    }
    let amount = le_u64(&ix.data[1..9]);
    let a = &ix.accounts;
    let operation = match kind {
        TokenAmountKind::Transfer => Operation::TokenTransfer {
            source: a[0].pubkey,
            destination: a[1].pubkey,
            authority: a[2].pubkey,
            amount,
        },
        TokenAmountKind::Approve => Operation::TokenApprove {
            source: a[0].pubkey,
            delegate: a[1].pubkey,
            authority: a[2].pubkey,
            amount,
        },
        TokenAmountKind::MintTo => Operation::TokenMintTo {
            mint: a[0].pubkey,
            destination: a[1].pubkey,
            authority: a[2].pubkey,
            amount,
        },
        TokenAmountKind::Burn => Operation::TokenBurn {
            source: a[0].pubkey,
            mint: a[1].pubkey,
            authority: a[2].pubkey,
            amount,
        },
    };
    DecodeOutcome::Decoded(operation)
}

fn decode_token_set_authority(ix: &InstructionData) -> DecodeOutcome {
    const TAG: u32 = 6;
    if ix.data.len() < 3 {
        return malformed(ix, TAG, "set-authority data length");
    }
    let authority_type = match ix.data[1] {
        0 => TokenAuthorityType::MintTokens,
        1 => TokenAuthorityType::FreezeAccount,
        2 => TokenAuthorityType::AccountOwner,
        3 => TokenAuthorityType::CloseAccount,
        _ => return malformed(ix, TAG, "token authority type"),
    };
    let (new_authority, expected_len) = match ix.data[2] {
        0 => (None, 3),
        1 if ix.data.len() >= 35 => (Some(pubkey(&ix.data[3..35])), 35),
        1 => return malformed(ix, TAG, "set-authority new authority"),
        _ => return malformed(ix, TAG, "set-authority option tag"),
    };
    if ix.data.len() != expected_len {
        return malformed(ix, TAG, "set-authority trailing data");
    }
    if token_multisig(ix, 1) {
        return unsupported(ix, Some(TAG), "token multisig authority");
    }
    if !metas(ix, &[(false, true), (true, false)]) {
        return malformed(ix, TAG, "set-authority accounts");
    }
    DecodeOutcome::Decoded(Operation::TokenSetAuthority {
        account: ix.accounts[0].pubkey,
        current_authority: ix.accounts[1].pubkey,
        authority_type,
        new_authority,
    })
}

fn decode_token_close(ix: &InstructionData) -> DecodeOutcome {
    const TAG: u32 = 9;
    if ix.data.len() != 1 {
        return malformed(ix, TAG, "close-account trailing data");
    }
    if token_multisig(ix, 2) {
        return unsupported(ix, Some(TAG), "token multisig authority");
    }
    if !metas(ix, &[(false, true), (false, true), (true, false)]) {
        return malformed(ix, TAG, "close-account accounts");
    }
    DecodeOutcome::Decoded(Operation::TokenCloseAccount {
        account: ix.accounts[0].pubkey,
        destination: ix.accounts[1].pubkey,
        authority: ix.accounts[2].pubkey,
    })
}

fn decode_token_checked(ix: &InstructionData) -> DecodeOutcome {
    const TAG: u32 = 12;
    if ix.data.len() != 10 {
        return malformed(ix, TAG, "transfer-checked data length");
    }
    if token_multisig(ix, 3) {
        return unsupported(ix, Some(TAG), "token multisig authority");
    }
    if !metas(
        ix,
        &[(false, true), (false, false), (false, true), (true, false)],
    ) {
        return malformed(ix, TAG, "transfer-checked accounts");
    }
    DecodeOutcome::Decoded(Operation::TokenTransferChecked {
        source: ix.accounts[0].pubkey,
        mint: ix.accounts[1].pubkey,
        destination: ix.accounts[2].pubkey,
        authority: ix.accounts[3].pubkey,
        amount: le_u64(&ix.data[1..9]),
        decimals: ix.data[9],
    })
}

fn token_multisig(ix: &InstructionData, authority_index: usize) -> bool {
    ix.accounts
        .get(authority_index)
        .is_some_and(|authority| !authority.is_signer)
}

fn decode_associated_token(ix: &InstructionData) -> DecodeOutcome {
    let (kind, tag) = match ix.data.as_slice() {
        [] | [0] => (AssociatedTokenCreateKind::Create, 0),
        [1] => (AssociatedTokenCreateKind::CreateIdempotent, 1),
        [0, ..] => return malformed(ix, 0, "associated-token trailing data"),
        [1, ..] => return malformed(ix, 1, "associated-token trailing data"),
        [tag, ..] => {
            return unsupported(
                ix,
                Some(*tag as u32),
                "unsupported associated-token instruction",
            )
        }
    };
    let flags6 = [
        (true, true),
        (false, true),
        (false, false),
        (false, false),
        (false, false),
        (false, false),
    ];
    let flags7 = [
        (true, true),
        (false, true),
        (false, false),
        (false, false),
        (false, false),
        (false, false),
        (false, false),
    ];
    if !(metas(ix, &flags6) || metas(ix, &flags7)) {
        return malformed(ix, tag, "associated-token accounts");
    }
    if ix.accounts[4].pubkey != system_program_id()
        || ix.accounts[5].pubkey != spl_token_program_id()
        || (ix.accounts.len() == 7 && ix.accounts[6].pubkey != RENT_SYSVAR_ID)
    {
        return malformed(ix, tag, "associated-token program or sysvar account");
    }
    let owner = ix.accounts[2].pubkey;
    let mint = ix.accounts[3].pubkey;
    let Ok((expected, _)) = associated_token_address(&owner, &mint) else {
        return malformed(ix, tag, "associated-token derivation");
    };
    if ix.accounts[1].pubkey != expected {
        return malformed(ix, tag, "associated-token address");
    }
    DecodeOutcome::Decoded(Operation::AssociatedTokenCreate {
        kind,
        payer: ix.accounts[0].pubkey,
        account: expected,
        owner,
        mint,
    })
}

fn decode_loader(ix: &InstructionData) -> DecodeOutcome {
    let Some(tag) = u32_tag(&ix.data) else {
        return unsupported(ix, None, "missing loader instruction tag");
    };
    match tag {
        3 => decode_loader_upgrade(ix),
        4 => decode_loader_authority(ix, false),
        7 => decode_loader_authority(ix, true),
        _ => unsupported(ix, Some(tag), "unsupported loader instruction"),
    }
}

fn decode_loader_upgrade(ix: &InstructionData) -> DecodeOutcome {
    const TAG: u32 = 3;
    let (close_buffer, versioned) = match ix.data.as_slice() {
        [3, 0, 0, 0] => (true, false),
        [3, 0, 0, 0, 0] => (false, true),
        [3, 0, 0, 0, 1] => (true, true),
        _ => return malformed(ix, TAG, "loader upgrade data"),
    };
    if !metas(
        ix,
        &[
            (false, true),
            (false, true),
            (false, true),
            (false, true),
            (false, false),
            (false, false),
            (true, false),
        ],
    ) {
        return malformed(ix, TAG, "loader upgrade accounts");
    }
    if ix.accounts[4].pubkey != RENT_SYSVAR_ID || ix.accounts[5].pubkey != CLOCK_SYSVAR_ID {
        return malformed(ix, TAG, "loader upgrade sysvars");
    }
    DecodeOutcome::Decoded(Operation::UpgradeableLoaderUpgrade {
        programdata: ix.accounts[0].pubkey,
        program: ix.accounts[1].pubkey,
        buffer: ix.accounts[2].pubkey,
        spill: ix.accounts[3].pubkey,
        current_authority: ix.accounts[6].pubkey,
        close_buffer,
        versioned,
    })
}

fn decode_loader_authority(ix: &InstructionData, checked: bool) -> DecodeOutcome {
    let tag: u32 = if checked { 7 } else { 4 };
    if ix.data != tag.to_le_bytes() {
        return malformed(ix, tag, "loader set-authority data");
    }
    let valid = if checked {
        metas(ix, &[(false, true), (true, false), (true, false)])
    } else {
        metas(ix, &[(false, true), (true, false)])
            || metas(ix, &[(false, true), (true, false), (false, false)])
    };
    if !valid {
        return malformed(ix, tag, "loader set-authority accounts");
    }
    let new_authority = ix.accounts.get(2).map(|account| account.pubkey);
    DecodeOutcome::Decoded(Operation::UpgradeableLoaderSetAuthority {
        account: ix.accounts[0].pubkey,
        current_authority: ix.accounts[1].pubkey,
        new_authority,
        checked,
        remove: new_authority.is_none(),
    })
}

fn decode_governance(ix: &InstructionData) -> DecodeOutcome {
    let Some(&tag) = ix.data.first() else {
        return unsupported(ix, None, "missing governance instruction tag");
    };
    match tag {
        19 => decode_governance_config(ix),
        21 => decode_realm_authority(ix),
        _ => unsupported(ix, Some(tag as u32), "unsupported governance instruction"),
    }
}

fn decode_governance_config(ix: &InstructionData) -> DecodeOutcome {
    const TAG: u32 = 19;
    if !metas(ix, &[(true, true)]) {
        return malformed(ix, TAG, "set-governance-config accounts");
    }
    let mut reader = SliceReader::new(&ix.data[1..]);
    let result = read_governance_config(&mut reader);
    let config = match result {
        Ok(config) if reader.is_empty() => config,
        Ok(_) => return malformed(ix, TAG, "set-governance-config trailing data"),
        Err(reason) => return malformed(ix, TAG, reason),
    };
    DecodeOutcome::Decoded(Operation::SetGovernanceConfig {
        governance: ix.accounts[0].pubkey,
        config,
    })
}

fn decode_realm_authority(ix: &InstructionData) -> DecodeOutcome {
    const TAG: u32 = 21;
    if ix.data.len() != 2 {
        return malformed(ix, TAG, "set-realm-authority data length");
    }
    let action = match ix.data[1] {
        0 => RealmAuthorityAction::SetUnchecked,
        1 => RealmAuthorityAction::SetChecked,
        2 => RealmAuthorityAction::Remove,
        _ => return malformed(ix, TAG, "realm authority action"),
    };
    let valid = if action == RealmAuthorityAction::Remove {
        metas(ix, &[(false, true), (true, false)])
    } else {
        metas(ix, &[(false, true), (true, false), (false, false)])
    };
    if !valid {
        return malformed(ix, TAG, "set-realm-authority accounts");
    }
    DecodeOutcome::Decoded(Operation::SetRealmAuthority {
        realm: ix.accounts[0].pubkey,
        current_authority: ix.accounts[1].pubkey,
        new_authority: ix.accounts.get(2).map(|account| account.pubkey),
        action,
    })
}

fn read_governance_config(reader: &mut SliceReader<'_>) -> Result<GovernanceConfig, &'static str> {
    let community_vote_threshold = reader.threshold()?;
    let min_community_weight_to_create_proposal = reader.u64()?;
    let transactions_hold_up_time = reader.u32()?;
    let voting_base_time = reader.u32()?;
    let community_vote_tipping = reader.tipping()?;
    let council_vote_threshold = reader.threshold()?;
    if council_vote_threshold == VoteThreshold::YesVotePercentage(0) {
        return Err("legacy governance config marker");
    }
    let council_veto_vote_threshold = reader.threshold()?;
    let min_council_weight_to_create_proposal = reader.u64()?;
    let council_vote_tipping = reader.tipping()?;
    let community_veto_vote_threshold = reader.threshold()?;
    let voting_cool_off_time = reader.u32()?;
    let deposit_exempt_proposal_count = reader.u8()?;
    if community_vote_threshold == VoteThreshold::Disabled
        && council_vote_threshold == VoteThreshold::Disabled
    {
        return Err("all electorate vote thresholds disabled");
    }
    if deposit_exempt_proposal_count == u8::MAX {
        return Err("deposit exempt proposal count");
    }
    Ok(GovernanceConfig {
        community_vote_threshold,
        min_community_weight_to_create_proposal,
        transactions_hold_up_time,
        voting_base_time,
        community_vote_tipping,
        council_vote_threshold,
        council_veto_vote_threshold,
        min_council_weight_to_create_proposal,
        council_vote_tipping,
        community_veto_vote_threshold,
        voting_cool_off_time,
        deposit_exempt_proposal_count,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenAccountState {
    Uninitialized,
    Initialized,
    Frozen,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenMintState {
    pub mint_authority: Option<Pubkey>,
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
    pub freeze_authority: Option<Pubkey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenAccountData {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    pub state: TokenAccountState,
    pub is_native: Option<u64>,
    pub delegated_amount: u64,
    pub close_authority: Option<Pubkey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpgradeableLoaderState {
    Buffer {
        authority: Option<Pubkey>,
        data_offset: usize,
    },
    Program {
        programdata_address: Pubkey,
    },
    ProgramData {
        slot: u64,
        upgrade_authority: Option<Pubkey>,
        data_offset: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateDecodeError(pub &'static str);

pub fn parse_token_mint(data: &[u8]) -> Result<TokenMintState, StateDecodeError> {
    if data.len() != 82 {
        return Err(StateDecodeError("token mint length"));
    }
    let mint_authority = state_coption_pubkey(&data[0..36])?;
    let is_initialized = match data[45] {
        0 => false,
        1 => true,
        _ => return Err(StateDecodeError("token mint initialized bool")),
    };
    let freeze_authority = state_coption_pubkey(&data[46..82])?;
    Ok(TokenMintState {
        mint_authority,
        supply: le_u64(&data[36..44]),
        decimals: data[44],
        is_initialized,
        freeze_authority,
    })
}

pub fn parse_token_account(data: &[u8]) -> Result<TokenAccountData, StateDecodeError> {
    if data.len() != 165 {
        return Err(StateDecodeError("token account length"));
    }
    let state = match data[108] {
        0 => TokenAccountState::Uninitialized,
        1 => TokenAccountState::Initialized,
        2 => TokenAccountState::Frozen,
        _ => return Err(StateDecodeError("token account state")),
    };
    Ok(TokenAccountData {
        mint: pubkey(&data[0..32]),
        owner: pubkey(&data[32..64]),
        amount: le_u64(&data[64..72]),
        delegate: state_coption_pubkey(&data[72..108])?,
        state,
        is_native: state_coption_u64(&data[109..121])?,
        delegated_amount: le_u64(&data[121..129]),
        close_authority: state_coption_pubkey(&data[129..165])?,
    })
}

pub fn parse_upgradeable_loader_state(
    data: &[u8],
) -> Result<UpgradeableLoaderState, StateDecodeError> {
    let tag = data
        .get(0..4)
        .map(le_u32)
        .ok_or(StateDecodeError("loader state tag"))?;
    match tag {
        1 => {
            if data.len() < 37 {
                return Err(StateDecodeError("loader buffer metadata length"));
            }
            Ok(UpgradeableLoaderState::Buffer {
                authority: bincode_option_pubkey(&data[4..37])?,
                data_offset: 37,
            })
        }
        2 => {
            if data.len() != 36 {
                return Err(StateDecodeError("loader program state length"));
            }
            Ok(UpgradeableLoaderState::Program {
                programdata_address: pubkey(&data[4..36]),
            })
        }
        3 => {
            if data.len() < 45 {
                return Err(StateDecodeError("loader programdata metadata length"));
            }
            Ok(UpgradeableLoaderState::ProgramData {
                slot: le_u64(&data[4..12]),
                upgrade_authority: bincode_option_pubkey(&data[12..45])?,
                data_offset: 45,
            })
        }
        _ => Err(StateDecodeError("unsupported loader state")),
    }
}

fn state_coption_pubkey(data: &[u8]) -> Result<Option<Pubkey>, StateDecodeError> {
    match le_u32(&data[0..4]) {
        0 => Ok(None),
        1 => Ok(Some(pubkey(&data[4..36]))),
        _ => Err(StateDecodeError("token COption<Pubkey> tag")),
    }
}

fn state_coption_u64(data: &[u8]) -> Result<Option<u64>, StateDecodeError> {
    match le_u32(&data[0..4]) {
        0 => Ok(None),
        1 => Ok(Some(le_u64(&data[4..12]))),
        _ => Err(StateDecodeError("token COption<u64> tag")),
    }
}

fn bincode_option_pubkey(data: &[u8]) -> Result<Option<Pubkey>, StateDecodeError> {
    match data[0] {
        0 => Ok(None),
        1 => Ok(Some(pubkey(&data[1..33]))),
        _ => Err(StateDecodeError("loader authority option tag")),
    }
}

fn metas(ix: &InstructionData, expected: &[(bool, bool)]) -> bool {
    ix.accounts.len() == expected.len()
        && ix
            .accounts
            .iter()
            .zip(expected)
            .all(|(actual, &(signer, writable))| {
                actual.is_signer == signer && actual.is_writable == writable
            })
}

fn malformed(ix: &InstructionData, tag: u32, reason: &'static str) -> DecodeOutcome {
    DecodeOutcome::Malformed(MalformedInstruction {
        program_id: ix.program_id,
        tag,
        reason,
    })
}

fn unsupported(ix: &InstructionData, tag: Option<u32>, reason: &'static str) -> DecodeOutcome {
    DecodeOutcome::UnsupportedInstruction {
        program_id: ix.program_id,
        tag,
        reason,
    }
}

fn u32_tag(data: &[u8]) -> Option<u32> {
    data.get(0..4).map(le_u32)
}

fn le_u32(data: &[u8]) -> u32 {
    let mut bytes = [0; 4];
    if let Some(value) = data.get(..4) {
        bytes.copy_from_slice(value);
    }
    u32::from_le_bytes(bytes)
}

fn le_u64(data: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    if let Some(value) = data.get(..8) {
        bytes.copy_from_slice(value);
    }
    u64::from_le_bytes(bytes)
}

fn pubkey(data: &[u8]) -> Pubkey {
    let mut bytes = [0; 32];
    if let Some(value) = data.get(..32) {
        bytes.copy_from_slice(value);
    }
    Pubkey::new(bytes)
}

struct SliceReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or("governance config overflow")?;
        let value = self
            .data
            .get(self.offset..end)
            .ok_or("truncated governance config")?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(le_u32(self.take(4)?))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(le_u64(self.take(8)?))
    }

    fn threshold(&mut self) -> Result<VoteThreshold, &'static str> {
        match self.u8()? {
            0 => match self.u8()? {
                value @ 1..=100 => Ok(VoteThreshold::YesVotePercentage(value)),
                _ => Err("vote threshold percentage"),
            },
            1 => {
                self.u8()?;
                Err("quorum vote threshold")
            }
            2 => Ok(VoteThreshold::Disabled),
            _ => Err("vote threshold tag"),
        }
    }

    fn tipping(&mut self) -> Result<VoteTipping, &'static str> {
        match self.u8()? {
            0 => Ok(VoteTipping::Strict),
            1 => Ok(VoteTipping::Early),
            2 => Ok(VoteTipping::Disabled),
            _ => Err("vote tipping"),
        }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.data.len()
    }
}
