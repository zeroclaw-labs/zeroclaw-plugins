//! Hand-rolled base58 (Bitcoin alphabet), as the bounty brief predicts:
//! "Assume you'll be assembling transactions with bs58 / borsh / hand-rolled
//! instruction encoding." No lookup crate, no unsafe, golden-vector tested.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes as base58.
pub fn encode(input: &[u8]) -> String {
    // Count leading zero bytes -> leading '1's.
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    // Base-256 -> base-58 long division.
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in input.iter().skip(zeros) {
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
    out.extend(std::iter::repeat_n('1', zeros));
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// Decode a base58 string. Returns `None` on any character outside the alphabet.
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let zeros = input.bytes().take_while(|&b| b == b'1').count();
    let mut bytes: Vec<u8> = Vec::with_capacity(input.len());
    for ch in input.bytes().skip(zeros) {
        let val = ALPHABET.iter().position(|&a| a == ch)? as u32;
        let mut carry = val;
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
    Some(out)
}

/// Decode and require exactly 32 bytes — a Solana public key. This is the
/// validation gate every address-shaped config value and argument passes
/// through; anything else fails closed.
pub fn decode_pubkey(input: &str) -> Option<[u8; 32]> {
    let v = decode(input)?;
    let arr: [u8; 32] = v.try_into().ok()?;
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical Bitcoin test vectors (hex -> base58).
    const VECTORS: &[(&str, &str)] = &[
        ("", ""),
        ("61", "2g"),
        ("626262", "a3gV"),
        ("636363", "aPEr"),
        (
            "73696d706c792061206c6f6e6720737472696e67",
            "2cFupjhnEsSn59qHXstmK2ffpLv2",
        ),
        (
            "00eb15231dfceb60925886b67d065299925915aeb172c06647",
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        ),
        ("516b6fcd0f", "ABnLTmg"),
        ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
        ("572e4794", "3EFU7m"),
        ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
        ("10c8511e", "Rt5zm"),
        ("00000000000000000000", "1111111111"),
    ];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn golden_encode() {
        for (hex, b58) in VECTORS {
            assert_eq!(encode(&unhex(hex)), *b58, "encode {hex}");
        }
    }

    #[test]
    fn golden_decode_roundtrip() {
        for (hex, b58) in VECTORS {
            assert_eq!(decode(b58).unwrap(), unhex(hex), "decode {b58}");
        }
    }

    #[test]
    fn rejects_invalid_chars() {
        for bad in ["0", "O", "I", "l", "hello world", "abc!"] {
            assert!(decode(bad).is_none(), "{bad} must be rejected");
        }
    }

    #[test]
    fn solana_system_program_is_32_zero_bytes() {
        let k = decode_pubkey("11111111111111111111111111111111").unwrap();
        assert_eq!(k, [0u8; 32]);
        assert_eq!(encode(&k), "11111111111111111111111111111111");
    }

    #[test]
    fn usdc_mint_decodes_to_32_bytes() {
        // Mainnet USDC mint — the default mint kiosk-charge ships with.
        assert!(decode_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").is_some());
    }

    #[test]
    fn short_or_long_keys_fail_closed() {
        assert!(decode_pubkey("abc").is_none());
        assert!(decode_pubkey("2g").is_none());
        // 33 bytes of 0xff encodes to something longer than a pubkey.
        assert!(decode_pubkey(&encode(&[0xffu8; 33])).is_none());
    }
}
