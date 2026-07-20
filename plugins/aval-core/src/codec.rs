//! Base58 and base64 codecs, hand-rolled so the core carries no codec
//! dependencies into the wasm32-wasip2 build.

const B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn b58_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
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
    for &d in digits.iter().rev() {
        out.push(B58_ALPHABET[d as usize] as char);
    }
    out
}

pub fn b58_decode(s: &str) -> Result<Vec<u8>, String> {
    let zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut digits: Vec<u8> = Vec::with_capacity(s.len());
    for c in s[zeros..].bytes() {
        let val = B58_ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| format!("invalid base58 character {:?}", c as char))?
            as u32;
        let mut carry = val;
        for d in digits.iter_mut() {
            carry += *d as u32 * 58;
            *d = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            digits.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(digits.iter().rev());
    Ok(out)
}

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut vals: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.trim().bytes() {
        if c == b'=' {
            break;
        }
        if c == b'\n' || c == b'\r' {
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(format!("invalid base64 character {:?}", c as char)),
        };
        vals.push(v);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let pad = |i: usize| *chunk.get(i).unwrap_or(&0) as u32;
        let n = (pad(0) << 18) | (pad(1) << 12) | (pad(2) << 6) | pad(3);
        match chunk.len() {
            4 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]),
            3 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]),
            2 => out.push((n >> 16) as u8),
            _ => return Err("truncated base64 input".into()),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b58_known_vectors() {
        // The system program id is 32 zero bytes.
        assert_eq!(b58_encode(&[0u8; 32]), "1".repeat(32));
        assert_eq!(b58_decode(&"1".repeat(32)).unwrap(), vec![0u8; 32]);
        // 58 decimal is [1, 0] in base58 → "21"; 255 is [4, 23] → "5Q".
        assert_eq!(b58_encode(&[58]), "21");
        assert_eq!(b58_encode(&[255]), "5Q");
        assert_eq!(b58_decode("5Q").unwrap(), vec![255]);
    }

    #[test]
    fn b58_roundtrip() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0],
            vec![0, 0, 1],
            vec![255; 32],
            (0u8..64).collect(),
        ];
        for c in cases {
            assert_eq!(b58_decode(&b58_encode(&c)).unwrap(), c);
        }
    }

    #[test]
    fn b58_rejects_invalid_characters() {
        assert!(b58_decode("0OIl").is_err());
        assert!(b58_decode("abc!").is_err());
    }

    #[test]
    fn b64_known_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(b64_decode("Zg==").unwrap(), b"f");
    }

    #[test]
    fn b64_roundtrip() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data);
    }

    #[test]
    fn b64_rejects_garbage() {
        assert!(b64_decode("!!!").is_err());
    }
}
