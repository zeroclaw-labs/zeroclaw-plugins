//! Ed25519 signing for partially-signed transactions (the x402 client role).
//!
//! Used ONLY by T2 plugins holding a *scoped session key* — a throwaway
//! keypair funded with a small allowance, never a main wallet. The key bytes
//! come from the plugin's jailed config (`config_read`), already decrypted
//! by the host.

use ed25519_dalek::{Signer, SigningKey};

use crate::encoding::{b64_encode, encode_compact_u16};
use crate::message::{serialize_message, Message};
use crate::pubkey::Pubkey;

/// A session keypair parsed from config. Accepts base58-encoded 32-byte
/// seed or 64-byte (seed+pub) solana-keygen format.
pub struct SessionKey {
    signing: SigningKey,
    pub pubkey: Pubkey,
}

impl SessionKey {
    pub fn from_base58(s: &str) -> Result<Self, String> {
        let bytes = bs58::decode(s.trim())
            .into_vec()
            .map_err(|e| format!("session key: invalid base58: {e}"))?;
        Self::from_bytes(&bytes)
    }

    /// Accepts a JSON array (solana-keygen id.json format) too.
    pub fn from_config_value(v: &str) -> Result<Self, String> {
        let t = v.trim();
        if t.starts_with('[') {
            let arr: Vec<u8> =
                serde_json::from_str(t).map_err(|e| format!("session key: bad JSON array: {e}"))?;
            Self::from_bytes(&arr)
        } else {
            Self::from_base58(t)
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let seed: [u8; 32] = match bytes.len() {
            32 => bytes.try_into().unwrap(),
            64 => bytes[..32].try_into().unwrap(),
            n => return Err(format!("session key: expected 32 or 64 bytes, got {n}")),
        };
        let signing = SigningKey::from_bytes(&seed);
        let pubkey = Pubkey(signing.verifying_key().to_bytes());
        Ok(Self { signing, pubkey })
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Serialize a transaction with real signatures where we have them and
/// zeroed placeholders where we don't (e.g. the sponsor's feePayer slot in
/// an x402 payment). `signers` maps account index → session key.
pub fn partially_signed_transaction_base64(
    msg: &Message,
    signers: &[(usize, &SessionKey)],
) -> Result<String, String> {
    let body = serialize_message(msg);
    let n = msg.num_required_signatures as usize;
    let mut sigs = vec![[0u8; 64]; n];
    for (index, key) in signers {
        if *index >= n {
            return Err(format!("signer index {index} out of range ({n} slots)"));
        }
        let expected = &msg.account_keys[*index];
        if key.pubkey != *expected {
            return Err(format!(
                "signer mismatch at index {index}: key {} != account {}",
                key.pubkey, expected
            ));
        }
        sigs[*index] = key.sign(&body);
    }
    let mut out = Vec::with_capacity(1 + 64 * n + body.len());
    encode_compact_u16(n as u16, &mut out);
    for s in &sigs {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(&body);
    Ok(b64_encode(&out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::system_transfer;
    use crate::message::compile_message;
    use ed25519_dalek::Verifier;

    fn session() -> SessionKey {
        SessionKey::from_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn parses_seed_and_keypair_formats() {
        let seed = [1u8; 32];
        let k32 = SessionKey::from_bytes(&seed).unwrap();
        let mut sixty_four = seed.to_vec();
        sixty_four.extend_from_slice(&k32.pubkey.0);
        let k64 = SessionKey::from_bytes(&sixty_four).unwrap();
        assert_eq!(k32.pubkey, k64.pubkey);
        assert!(SessionKey::from_bytes(&[0u8; 31]).is_err());
    }

    #[test]
    fn json_array_format() {
        let seed = vec![9u8; 32];
        let json = serde_json::to_string(&seed).unwrap();
        assert!(SessionKey::from_config_value(&json).is_ok());
    }

    #[test]
    fn signature_verifies_and_placement_is_correct() {
        let payer = session(); // session key is the sole signer here
        let to = Pubkey([2u8; 32]);
        let msg = compile_message(
            payer.pubkey,
            &[system_transfer(payer.pubkey, to, 9)],
            [3u8; 32],
        )
        .unwrap();
        let b64 = partially_signed_transaction_base64(&msg, &[(0, &payer)]).unwrap();
        let raw = crate::encoding::b64_decode(&b64).unwrap();
        assert_eq!(raw[0], 1);
        let sig_bytes: [u8; 64] = raw[1..65].try_into().unwrap();
        let body = &raw[65..];
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&payer.pubkey.0).unwrap();
        vk.verify(body, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .expect("signature must verify over the message body");
    }

    #[test]
    fn rejects_wrong_signer() {
        let payer = session();
        let other = SessionKey::from_bytes(&[8u8; 32]).unwrap();
        let to = Pubkey([2u8; 32]);
        let msg = compile_message(
            payer.pubkey,
            &[system_transfer(payer.pubkey, to, 9)],
            [0u8; 32],
        )
        .unwrap();
        assert!(partially_signed_transaction_base64(&msg, &[(0, &other)]).is_err());
    }
}
