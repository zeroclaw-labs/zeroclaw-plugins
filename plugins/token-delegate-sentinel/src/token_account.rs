use crate::address::Address;

pub const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;
const EXTENSION_ACCOUNT_TYPE_OFFSET: usize = TOKEN_ACCOUNT_LEN;
const EXTENSION_TLV_OFFSET: usize = TOKEN_ACCOUNT_LEN + 1;
const TOKEN_2022_MINT_TYPE: u8 = 1;
const TOKEN_2022_ACCOUNT_TYPE: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramKind {
    SplToken,
    Token2022,
}

impl ProgramKind {
    pub fn program_id(self) -> &'static str {
        match self {
            Self::SplToken => SPL_TOKEN_PROGRAM_ID,
            Self::Token2022 => TOKEN_2022_PROGRAM_ID,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    Initialized,
    Frozen,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenAccount {
    pub address: Address,
    pub program: ProgramKind,
    pub mint: Address,
    pub owner: Address,
    pub amount: u64,
    pub delegate: Option<Address>,
    pub state: AccountState,
    pub is_native: bool,
    pub delegated_amount: u64,
    pub close_authority: Option<Address>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintAccount {
    pub address: Address,
    pub program: ProgramKind,
    pub supply: u64,
    pub decimals: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    InvalidLength,
    InvalidDelegateOption,
    InvalidNativeOption,
    InvalidCloseAuthorityOption,
    InvalidState,
    InconsistentDelegate,
    InvalidMint,
    InvalidAccountType,
    InvalidExtension,
    DuplicateExtension,
}

pub fn decode_token_account(
    address: Address,
    program: ProgramKind,
    data: &[u8],
) -> Result<TokenAccount, DecodeError> {
    match program {
        ProgramKind::SplToken if data.len() != TOKEN_ACCOUNT_LEN => {
            return Err(DecodeError::InvalidLength);
        }
        ProgramKind::Token2022 if data.len() < TOKEN_ACCOUNT_LEN => {
            return Err(DecodeError::InvalidLength);
        }
        ProgramKind::Token2022 if data.len() > TOKEN_ACCOUNT_LEN => {
            validate_extensions(data, TOKEN_ACCOUNT_LEN, TOKEN_2022_ACCOUNT_TYPE)?
        }
        _ => {}
    }

    let mint = read_address(data, 0)?;
    let owner = read_address(data, 32)?;
    let amount = read_u64(data, 64)?;
    let delegate = read_coption_address(data, 72, DecodeError::InvalidDelegateOption)?;
    let state = match *data.get(108).ok_or(DecodeError::InvalidLength)? {
        1 => AccountState::Initialized,
        2 => AccountState::Frozen,
        _ => return Err(DecodeError::InvalidState),
    };
    let is_native = read_coption_u64(data, 109, DecodeError::InvalidNativeOption)?.is_some();
    let delegated_amount = read_u64(data, 121)?;
    let close_authority =
        read_coption_address(data, 129, DecodeError::InvalidCloseAuthorityOption)?;
    if delegate.is_none() && delegated_amount != 0 {
        return Err(DecodeError::InconsistentDelegate);
    }

    Ok(TokenAccount {
        address,
        program,
        mint,
        owner,
        amount,
        delegate,
        state,
        is_native,
        delegated_amount,
        close_authority,
    })
}

pub fn decode_mint_account(
    address: Address,
    program: ProgramKind,
    data: &[u8],
) -> Result<MintAccount, DecodeError> {
    match program {
        ProgramKind::SplToken if data.len() != MINT_LEN => {
            return Err(DecodeError::InvalidLength);
        }
        ProgramKind::Token2022 if data.len() < MINT_LEN => {
            return Err(DecodeError::InvalidLength);
        }
        ProgramKind::Token2022 if data.len() > MINT_LEN => {
            validate_extensions(data, MINT_LEN, TOKEN_2022_MINT_TYPE)?
        }
        _ => {}
    }

    let _mint_authority = read_coption_address(data, 0, DecodeError::InvalidMint)?;
    let supply = read_u64(data, 36)?;
    let decimals = *data.get(44).ok_or(DecodeError::InvalidLength)?;
    if data.get(45) != Some(&1) {
        return Err(DecodeError::InvalidMint);
    }
    let _freeze_authority = read_coption_address(data, 46, DecodeError::InvalidMint)?;
    Ok(MintAccount {
        address,
        program,
        supply,
        decimals,
    })
}

fn validate_extensions(
    data: &[u8],
    base_len: usize,
    expected_account_type: u8,
) -> Result<(), DecodeError> {
    if data.len() < EXTENSION_TLV_OFFSET
        || data
            .get(base_len..EXTENSION_ACCOUNT_TYPE_OFFSET)
            .ok_or(DecodeError::InvalidExtension)?
            .iter()
            .any(|byte| *byte != 0)
        || data.get(EXTENSION_ACCOUNT_TYPE_OFFSET) != Some(&expected_account_type)
    {
        return Err(DecodeError::InvalidAccountType);
    }
    let mut cursor = EXTENSION_TLV_OFFSET;
    let mut seen = std::collections::BTreeSet::new();
    while cursor < data.len() {
        if data[cursor..].iter().all(|byte| *byte == 0) {
            return Ok(());
        }
        let header_end = cursor.checked_add(4).ok_or(DecodeError::InvalidExtension)?;
        let header = data
            .get(cursor..header_end)
            .ok_or(DecodeError::InvalidExtension)?;
        let extension_type = u16::from_le_bytes([header[0], header[1]]);
        let extension_len = u16::from_le_bytes([header[2], header[3]]) as usize;
        if extension_type == 0 || !seen.insert(extension_type) {
            return Err(if extension_type == 0 {
                DecodeError::InvalidExtension
            } else {
                DecodeError::DuplicateExtension
            });
        }
        cursor = header_end
            .checked_add(extension_len)
            .ok_or(DecodeError::InvalidExtension)?;
        if cursor > data.len() {
            return Err(DecodeError::InvalidExtension);
        }
    }
    Ok(())
}

fn read_address(data: &[u8], offset: usize) -> Result<Address, DecodeError> {
    let bytes: [u8; 32] = data
        .get(offset..offset + 32)
        .ok_or(DecodeError::InvalidLength)?
        .try_into()
        .map_err(|_| DecodeError::InvalidLength)?;
    Ok(Address::from_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, DecodeError> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or(DecodeError::InvalidLength)?
        .try_into()
        .map_err(|_| DecodeError::InvalidLength)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_coption_address(
    data: &[u8],
    offset: usize,
    invalid_option: DecodeError,
) -> Result<Option<Address>, DecodeError> {
    let tag: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or(DecodeError::InvalidLength)?
        .try_into()
        .map_err(|_| DecodeError::InvalidLength)?;
    match u32::from_le_bytes(tag) {
        0 => Ok(None),
        1 => read_address(data, offset + 4).map(Some),
        _ => Err(invalid_option),
    }
}

fn read_coption_u64(
    data: &[u8],
    offset: usize,
    invalid_option: DecodeError,
) -> Result<Option<u64>, DecodeError> {
    let tag: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or(DecodeError::InvalidLength)?
        .try_into()
        .map_err(|_| DecodeError::InvalidLength)?;
    match u32::from_le_bytes(tag) {
        0 => Ok(None),
        1 => read_u64(data, offset + 4).map(Some),
        _ => Err(invalid_option),
    }
}
