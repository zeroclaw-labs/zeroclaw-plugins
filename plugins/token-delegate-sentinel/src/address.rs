use std::fmt;

use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    InvalidEncoding,
    InvalidLength,
    NonCanonical,
}

impl Address {
    pub fn parse(value: &str) -> Result<Self, AddressError> {
        if value.is_empty() || value.len() > 44 {
            return Err(AddressError::InvalidLength);
        }
        let decoded = bs58::decode(value)
            .into_vec()
            .map_err(|_| AddressError::InvalidEncoding)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| AddressError::InvalidLength)?;
        let address = Self(bytes);
        if address.to_string() != value {
            return Err(AddressError::NonCanonical);
        }
        Ok(address)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&bs58::encode(self.0).into_string())
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
