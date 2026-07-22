//! Pure, stateless payment-matching logic for the `payment-watch` tool.
//!
//! An SOP invokes the component on its schedule. The component returns a
//! structured `payment-received` event only when an observed transaction
//! matches every expected value; otherwise it returns `waiting`.

use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

pub const PARAMETERS_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "recipient": { "type": "string", "description": "Base58 wallet-owner public key expected to receive payment" },
    "amount": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$", "description": "Exact positive decimal amount, e.g. \"25.0\"" },
    "decimals": { "type": "integer", "minimum": 0, "maximum": 19, "description": "Mint decimal precision used to compare the exact amount" },
    "mint": { "type": "string", "description": "Base58 SPL token mint" },
    "reference": { "type": "string", "description": "Base58 Solana Pay reference public key that must appear in the transaction" },
    "token_2022": { "type": "boolean", "default": false, "description": "Use the Token-2022 associated token-account derivation" }
  },
  "required": ["recipient", "amount", "decimals", "mint", "reference"]
}"#;

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("invalid base58 public key")]
    InvalidPubkey,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("PDA derivation failed")]
    PdaNotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn from_base58(value: &str) -> Result<Self, WatchError> {
        let bytes = bs58::decode(value)
            .into_vec()
            .map_err(|_| WatchError::InvalidPubkey)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| WatchError::InvalidPubkey)?;
        Ok(Self(bytes))
    }

    pub fn to_base58(self) -> String {
        bs58::encode(self.0).into_string()
    }

    fn find_program_address(seeds: &[&[u8]], program_id: &Self) -> Result<Self, WatchError> {
        for bump in (0u8..=255).rev() {
            let mut hasher = Sha256::new();
            for seed in seeds {
                hasher.update(seed);
            }
            hasher.update([bump]);
            hasher.update(program_id.0);
            hasher.update(b"ProgramDerivedAddress");
            let hash: [u8; 32] = hasher.finalize().into();
            if CompressedEdwardsY(hash).decompress().is_none() {
                return Ok(Self(hash));
            }
        }
        Err(WatchError::PdaNotFound)
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_base58())
    }
}

pub fn derive_ata(
    owner: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
) -> Result<Pubkey, WatchError> {
    let ata_program = Pubkey::from_base58(ATA_PROGRAM_ID)?;
    Pubkey::find_program_address(&[&owner.0, &token_program.0, &mint.0], &ata_program)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentWatchArgs {
    pub recipient: String,
    pub amount: String,
    pub decimals: u8,
    pub mint: String,
    pub reference: String,
    #[serde(default)]
    pub token_2022: bool,
}

#[derive(Debug, Clone)]
pub struct ExpectedPayment {
    pub recipient: Pubkey,
    pub mint: Pubkey,
    pub reference: Pubkey,
    pub amount_base_units: u64,
    pub decimals: u8,
    pub token_program: Pubkey,
}

impl PaymentWatchArgs {
    pub fn expected(&self) -> Result<ExpectedPayment, WatchError> {
        if self.decimals > 19 {
            return Err(WatchError::InvalidInput(
                "decimals must be at most 19".into(),
            ));
        }
        let recipient = Pubkey::from_base58(&self.recipient)?;
        let mint = Pubkey::from_base58(&self.mint)?;
        let reference = Pubkey::from_base58(&self.reference)?;
        let token_program = Pubkey::from_base58(if self.token_2022 {
            TOKEN_2022_PROGRAM_ID
        } else {
            TOKEN_PROGRAM_ID
        })?;
        Ok(ExpectedPayment {
            recipient,
            mint,
            reference,
            amount_base_units: parse_amount_to_base_units(&self.amount, self.decimals)?,
            decimals: self.decimals,
            token_program,
        })
    }
}

fn parse_amount_to_base_units(amount: &str, decimals: u8) -> Result<u64, WatchError> {
    if amount.is_empty() || amount.trim() != amount {
        return Err(WatchError::InvalidInput(
            "amount must be a non-empty decimal string without whitespace".into(),
        ));
    }
    let mut parts = amount.split('.');
    let whole = parts.next().expect("split returns one element");
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.is_some_and(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(WatchError::InvalidInput(
            "amount must be a positive decimal string".into(),
        ));
    }
    let fraction = fraction.unwrap_or("");
    if fraction.len() > decimals as usize {
        return Err(WatchError::InvalidInput(format!(
            "amount has more than {decimals} decimal places"
        )));
    }
    let scale = 10u64
        .checked_pow(decimals as u32)
        .ok_or_else(|| WatchError::InvalidInput("amount overflows u64 base units".into()))?;
    let whole_units = whole
        .parse::<u64>()
        .map_err(|_| WatchError::InvalidInput("amount overflows u64 base units".into()))?
        .checked_mul(scale)
        .ok_or_else(|| WatchError::InvalidInput("amount overflows u64 base units".into()))?;
    let fraction_units = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u64>()
            .map_err(|_| WatchError::InvalidInput("amount overflows u64 base units".into()))?
            .checked_mul(10u64.pow((decimals as usize - fraction.len()) as u32))
            .ok_or_else(|| WatchError::InvalidInput("amount overflows u64 base units".into()))?
    };
    let amount = whole_units
        .checked_add(fraction_units)
        .ok_or_else(|| WatchError::InvalidInput("amount overflows u64 base units".into()))?;
    if amount == 0 {
        return Err(WatchError::InvalidInput(
            "amount must be greater than zero base units".into(),
        ));
    }
    Ok(amount)
}

#[derive(Debug, Clone)]
pub struct ObservedPayment {
    pub signature: String,
    pub sender: String,
    pub recipient: Pubkey,
    pub mint: Pubkey,
    pub amount_base_units: u64,
    pub decimals: u8,
    pub reference_present: bool,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct PaymentEvent {
    pub event: &'static str,
    pub message: String,
    pub signature: String,
    pub sender: String,
    pub recipient: String,
    pub mint: String,
    pub amount_base_units: u64,
    pub decimals: u8,
    pub reference: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct WatchResult {
    pub status: &'static str,
    pub checked_transactions: usize,
    pub event: Option<PaymentEvent>,
}

pub fn match_payment(expected: &ExpectedPayment, observed: &[ObservedPayment]) -> WatchResult {
    for payment in observed {
        if payment.recipient == expected.recipient
            && payment.mint == expected.mint
            && payment.amount_base_units == expected.amount_base_units
            && payment.decimals == expected.decimals
            && payment.reference_present
        {
            let message = format!(
                "Payment received: {} base units of {} from {} (signature {}).",
                payment.amount_base_units, expected.mint, payment.sender, payment.signature,
            );
            return WatchResult {
                status: "paid",
                checked_transactions: observed.len(),
                event: Some(PaymentEvent {
                    event: "payment-received",
                    message,
                    signature: payment.signature.clone(),
                    sender: payment.sender.clone(),
                    recipient: expected.recipient.to_base58(),
                    mint: expected.mint.to_base58(),
                    amount_base_units: payment.amount_base_units,
                    decimals: expected.decimals,
                    reference: expected.reference.to_base58(),
                }),
            };
        }
    }
    WatchResult {
        status: "waiting",
        checked_transactions: observed.len(),
        event: None,
    }
}

pub trait RpcClient {
    fn recent_payments(
        &self,
        expected: &ExpectedPayment,
    ) -> Result<Vec<ObservedPayment>, WatchError>;
}

pub fn check_payment(
    args: &PaymentWatchArgs,
    rpc: &dyn RpcClient,
) -> Result<WatchResult, WatchError> {
    let expected = args.expected()?;
    let observed = rpc.recent_payments(&expected)?;
    Ok(match_payment(&expected, &observed))
}
