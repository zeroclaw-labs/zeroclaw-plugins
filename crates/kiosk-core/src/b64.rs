//! Standard base64 (RFC 4648, `+/` alphabet, `=` padding). Hand-rolled, no
//! dependency, golden-vector tested — needed to read `getAccountInfo` account
//! data (base64 in) and to emit the unsigned transaction message (base64 out),
//! both wasm32-wasip2-friendly.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard base64 with padding.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64. Returns `None` on any invalid character, bad length,
/// or malformed padding — fail closed, never a silent partial result.
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut vals = [0u32; 4];
        let mut pad = 0;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                // Padding only allowed in the last one or two positions.
                if i < 2 {
                    return None;
                }
                pad += 1;
                vals[i] = 0;
            } else {
                if pad > 0 {
                    return None; // data after padding
                }
                vals[i] = sextet(c)? as u32;
            }
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10 test vectors.
    const VECTORS: &[(&str, &str)] = &[
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn golden_encode() {
        for (plain, b64) in VECTORS {
            assert_eq!(encode(plain.as_bytes()), *b64, "encode {plain:?}");
        }
    }

    #[test]
    fn golden_decode() {
        for (plain, b64) in VECTORS {
            assert_eq!(decode(b64).unwrap(), plain.as_bytes(), "decode {b64:?}");
        }
    }

    #[test]
    fn roundtrips_binary() {
        let data: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
        // 80-byte nonce-account-sized blob.
        let nonce = vec![0xABu8; 80];
        assert_eq!(decode(&encode(&nonce)).unwrap(), nonce);
    }

    #[test]
    fn fails_closed_on_bad_input() {
        assert!(decode("Zg=").is_none()); // length not multiple of 4
        assert!(decode("Zg===").is_none()); // length not multiple of 4
        assert!(decode("Z===").is_none()); // padding in position < 2
        assert!(decode("====").is_none()); // all padding
        assert!(decode("Zm9v!===").is_none()); // invalid char / bad shape
        assert!(decode("Zm9 v").is_none()); // space invalid
        assert!(decode("Zg==Zg==").is_some()); // two valid quanta OK
        assert!(decode("=AAA").is_none()); // leading pad
    }
}
