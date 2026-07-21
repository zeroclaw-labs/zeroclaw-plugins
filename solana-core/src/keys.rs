use crate::{CoreError, CoreResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pubkey([u8; 32]);

impl Pubkey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_base58(s: &str) -> CoreResult<Self> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| CoreError::msg(format!("invalid base58 pubkey: {e}")))?;
        if bytes.len() != 32 {
            return Err(CoreError::msg(format!(
                "pubkey must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }
}
