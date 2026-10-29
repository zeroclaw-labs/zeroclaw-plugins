//! Base58 (Bitcoin alphabet), which is how Solana writes public keys.
//!
//! This is vendored rather than imported from the sibling `durable-tx-build`
//! plugin, and the reason is a linker error worth recording. That crate is
//! `crate-type = ["cdylib", "rlib"]` and its component shim is gated on
//! `#[cfg(target_family = "wasm")]`, so depending on it as an rlib and then
//! building for `wasm32-wasip2` compiles *both* components into one artifact:
//!
//! ```text
//! rust-lld: error: duplicate symbol: cabi_post_zeroclaw:plugin/tool@0.1.0#description
//! rust-lld: error: duplicate symbol: cabi_post_zeroclaw:plugin/tool@0.1.0#parameters-schema
//! ```
//!
//! One component exports one tool. Sharing code between plugins therefore means
//! sharing a crate that is *not itself a component* — or, for something this
//! small, carrying it. Sixty lines of base58 is a better trade than a shared
//! crate that both components must link without exporting.
//!
//! Deliberately narrower than the sibling's `codec`: no curve25519, because
//! nothing here derives a PDA or an associated token account.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn b58_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    // Leading zero bytes are significant in base58 and encode as '1' each.
    let zeros = input.iter().take_while(|b| **b == 0).count();

    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for d in digits.iter().rev() {
        out.push(ALPHABET[*d as usize] as char);
    }
    out
}

pub fn b58_decode(input: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Err("empty base58 string".to_string());
    }

    let zeros = input.bytes().take_while(|b| *b == b'1').count();

    let mut bytes: Vec<u8> = Vec::with_capacity(input.len());
    for ch in input.bytes().skip(zeros) {
        let value = ALPHABET
            .iter()
            .position(|a| *a == ch)
            .ok_or_else(|| format!("{:?} is not a base58 character", ch as char))?
            as u32;

        let mut carry = value;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

/// Checks that a string is a syntactically valid 32-byte Solana address.
///
/// This is a format check, not an ownership or on-curve check. A reference key
/// is used read-only to identify a payment and never needs a private key, so
/// on-curve validity is not required of it.
pub fn is_valid_address(s: &str) -> Result<[u8; 32], String> {
    let bytes = b58_decode(s)?;
    bytes
        .try_into()
        .map_err(|_| format!("address {s:?} does not decode to 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_real_address() {
        let a = "GsbwXfJraMomNxBcjK1LfJ8HPnzUnEzUcNvLYSbxNQpr";
        assert_eq!(b58_encode(&b58_decode(a).unwrap()), a);
    }

    #[test]
    fn round_trips_thirty_two_bytes() {
        let bytes: Vec<u8> = (0u8..32).collect();
        assert_eq!(b58_decode(&b58_encode(&bytes)).unwrap(), bytes);
    }

    /// Leading zeros are significant and encode as '1'. Getting this wrong
    /// produces addresses that are a byte short and decode fine anyway, which
    /// is the kind of bug that only shows up on-chain.
    #[test]
    fn preserves_leading_zero_bytes() {
        let bytes = vec![0u8, 0, 0, 7, 9];
        let encoded = b58_encode(&bytes);
        assert!(encoded.starts_with("111"));
        assert_eq!(b58_decode(&encoded).unwrap(), bytes);
    }

    #[test]
    fn all_zero_key_encodes_to_thirty_two_ones() {
        let encoded = b58_encode(&[0u8; 32]);
        assert_eq!(encoded, "1".repeat(32));
        assert_eq!(b58_decode(&encoded).unwrap(), vec![0u8; 32]);
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // 0, O, I and l are excluded precisely because they are confusable.
        for bad in ["0OIl", "abc!", "hello world"] {
            assert!(b58_decode(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn rejects_a_string_that_is_not_thirty_two_bytes() {
        assert!(is_valid_address("abc").is_err());
        assert!(is_valid_address("GsbwXfJraMomNxBcjK1LfJ8HPnzUnEzUcNvLYSbxNQpr").is_ok());
    }
}
