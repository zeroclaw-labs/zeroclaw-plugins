//! Hand-rolled Base64 (standard alphabet) — no external deps.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_char(c: u8) -> Result<u8, String> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(format!("invalid base64 character: {}", c as char)),
    }
}

/// Decode a standard Base64 string (padding optional).
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();

    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    let pad = cleaned.iter().rev().take_while(|&&c| c == b'=').count();
    let len = cleaned.len();
    if !len.is_multiple_of(4) {
        return Err("invalid base64 length".into());
    }

    let mut out = Vec::with_capacity(len / 4 * 3);
    for chunk in cleaned.chunks(4) {
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            decode_char(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            decode_char(chunk[3])?
        };

        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push((c << 6) | d);
        }
    }

    // If padding was present we already stopped early; trim any accidental
    // trailing zeros from malformed inputs is unnecessary because we keyed
    // off '=' above. Silence unused warning when pad is computed for future.
    let _ = pad;
    Ok(out)
}

/// Encode raw bytes as standard Base64 (with padding).
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"hello solana guard";
        let enc = encode(data);
        assert_eq!(decode(&enc).unwrap(), data);
    }

    #[test]
    fn known_vector() {
        // "Man" → TWFu
        assert_eq!(encode(b"Man"), "TWFu");
        assert_eq!(decode("TWFu").unwrap(), b"Man");
    }
}
