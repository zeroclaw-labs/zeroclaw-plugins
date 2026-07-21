//! Wire-format helpers: Solana shortvec (compact-u16) and base64 wrappers.
//!
//! Message serialization itself is delegated to the canonical Agave
//! micro-crates (`solana-message`, `solana-instruction`, `solana-transaction`) —
//! the same code validators run. We hand-roll only the pieces they do not cover.

/// Encode a length as Solana shortvec (little-endian base-128, 7 bits per byte,
/// continuation bit on all but the last).
pub fn shortvec_encode(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Decode a shortvec at `bytes[..]`, returning (value, bytes consumed).
/// Errors on truncation or a sequence longer than 3 bytes (Solana's bound).
pub fn shortvec_decode(bytes: &[u8]) -> Result<(usize, usize), String> {
    let mut value = 0usize;
    for (i, byte) in bytes.iter().take(3).enumerate() {
        value |= ((byte & 0x7f) as usize) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    if bytes.len() >= 3 && bytes[2] & 0x80 != 0 {
        return Err("shortvec exceeds 3-byte bound".to_string());
    }
    Err("shortvec truncated".to_string())
}

/// Decode a base64 string into bytes, rejecting oversized payloads up front.
pub fn base64_decode(input: &str, max_chars: usize) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let input = input.trim();
    if input.len() > max_chars {
        return Err(format!(
            "base64 input too large: {} chars > {} bound",
            input.len(),
            max_chars
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("invalid base64: {e}"))
}

/// Encode bytes as standard base64.
pub fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortvec_golden_vectors() {
        // Canonical boundaries from the Solana wire spec.
        assert_eq!(shortvec_encode(0), vec![0x00]);
        assert_eq!(shortvec_encode(127), vec![0x7f]);
        assert_eq!(shortvec_encode(128), vec![0x80, 0x01]);
        assert_eq!(shortvec_encode(16_383), vec![0xff, 0x7f]);
        assert_eq!(shortvec_encode(16_384), vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn shortvec_roundtrip_and_bounds() {
        for v in [0usize, 1, 127, 128, 300, 16_383, 16_384, 123_456] {
            let enc = shortvec_encode(v);
            let (dec, used) = shortvec_decode(&enc).expect("decode");
            assert_eq!((dec, used), (v, enc.len()));
        }
        assert!(shortvec_decode(&[]).is_err());
        assert!(shortvec_decode(&[0x80]).is_err());
        assert!(shortvec_decode(&[0x80, 0x80, 0x80]).is_err());
    }

    #[test]
    fn base64_size_bound() {
        assert!(base64_decode("AAAA", 3).is_err());
        assert!(base64_decode("AAAA", 4).is_ok());
    }
}
