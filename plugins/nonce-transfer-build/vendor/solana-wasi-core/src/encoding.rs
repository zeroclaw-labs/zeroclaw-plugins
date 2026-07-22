//! Compact-u16 ("shortvec") and base64 helpers used by the Solana wire format.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

/// Encode a length as Solana's compact-u16 (1–3 bytes, 7 bits + continuation).
pub fn encode_compact_u16(mut value: u16, out: &mut Vec<u8>) {
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
}

/// Decode a compact-u16 from `bytes[offset..]`, returning (value, bytes read).
pub fn decode_compact_u16(bytes: &[u8], offset: usize) -> Result<(u16, usize), String> {
    let mut value: u32 = 0;
    let mut size = 0usize;
    loop {
        let byte = *bytes
            .get(offset + size)
            .ok_or_else(|| "compact-u16: unexpected end of input".to_string())?;
        value |= ((byte & 0x7f) as u32) << (7 * size);
        size += 1;
        if byte & 0x80 == 0 {
            break;
        }
        if size == 3 {
            return Err("compact-u16: too long".into());
        }
    }
    if value > u16::MAX as u32 {
        return Err("compact-u16: overflow".into());
    }
    Ok((value as u16, size))
}

pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    // Tolerate missing padding (chat channels routinely strip trailing '=').
    let padded;
    let input = if !t.len().is_multiple_of(4) {
        padded = format!("{t}{}", "=".repeat(4 - t.len() % 4));
        &padded
    } else {
        t
    };
    B64.decode(input)
        .map_err(|e| format!("invalid base64: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_u16_roundtrip() {
        for v in [
            0u16,
            1,
            5,
            0x7f,
            0x80,
            0xff,
            0x100,
            0x3fff,
            0x4000,
            u16::MAX,
        ] {
            let mut buf = Vec::new();
            encode_compact_u16(v, &mut buf);
            let (decoded, read) = decode_compact_u16(&buf, 0).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(read, buf.len());
        }
    }

    #[test]
    fn compact_u16_known_vectors() {
        // From the Solana wire-format docs.
        let mut buf = Vec::new();
        encode_compact_u16(0x7f, &mut buf);
        assert_eq!(buf, [0x7f]);
        buf.clear();
        encode_compact_u16(0x80, &mut buf);
        assert_eq!(buf, [0x80, 0x01]);
        buf.clear();
        encode_compact_u16(0x3fff, &mut buf);
        assert_eq!(buf, [0xff, 0x7f]);
    }

    #[test]
    fn compact_u16_rejects_truncated() {
        assert!(decode_compact_u16(&[0x80], 0).is_err());
    }
}
