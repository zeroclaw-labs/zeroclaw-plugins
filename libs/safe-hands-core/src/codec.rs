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
        if i == 2 && byte & 0x7c != 0 {
            return Err("shortvec exceeds u16 value bound".to_string());
        }
        value |= ((byte & 0x7f) as usize) << (7 * i);
        if byte & 0x80 == 0 {
            let used = i + 1;
            if shortvec_encode(value).len() != used {
                return Err("shortvec encoding is non-minimal".to_string());
            }
            return Ok((value, used));
        }
    }
    if bytes.len() >= 3 && bytes[2] & 0x80 != 0 {
        return Err("shortvec exceeds 3-byte bound".to_string());
    }
    Err("shortvec truncated".to_string())
}

/// Build canonical wire bytes for an unsigned Solana transaction.
///
/// The transaction wire format is a shortvec signature count, exactly that
/// many zero-filled 64-byte signature slots, and the serialized message.
/// Bare messages remain valid decoder inputs; this helper is for RPC methods
/// that require a complete transaction artifact.
pub fn unsigned_transaction_bytes(
    serialized_message: &[u8],
    required_signatures: usize,
) -> Result<Vec<u8>, String> {
    if serialized_message.is_empty() {
        return Err("cannot wrap an empty serialized message".to_string());
    }
    if required_signatures > u8::MAX as usize {
        return Err(format!(
            "required signature count exceeds message-header bound: {required_signatures}"
        ));
    }
    let signature_bytes = required_signatures
        .checked_mul(64)
        .ok_or_else(|| "signature byte length overflow".to_string())?;
    let prefix = shortvec_encode(required_signatures);
    let capacity = prefix
        .len()
        .checked_add(signature_bytes)
        .and_then(|size| size.checked_add(serialized_message.len()))
        .ok_or_else(|| "unsigned transaction length overflow".to_string())?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&prefix);
    out.resize(out.len() + signature_bytes, 0);
    out.extend_from_slice(serialized_message);
    Ok(out)
}

/// Build canonical standard-base64 for an unsigned Solana transaction.
pub fn unsigned_transaction_base64(
    serialized_message: &[u8],
    required_signatures: usize,
) -> Result<String, String> {
    unsigned_transaction_bytes(serialized_message, required_signatures)
        .map(|bytes| base64_encode(&bytes))
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
        for v in [0usize, 1, 127, 128, 300, 16_383, 16_384, 65_535] {
            let enc = shortvec_encode(v);
            let (dec, used) = shortvec_decode(&enc).expect("decode");
            assert_eq!((dec, used), (v, enc.len()));
        }
        assert!(shortvec_decode(&[]).is_err());
        assert!(shortvec_decode(&[0x80]).is_err());
        assert!(shortvec_decode(&[0x80, 0x80, 0x80]).is_err());
        for overflow in [
            shortvec_encode(65_536),
            shortvec_encode(123_456),
            vec![0x80, 0x80, 0x04],
        ] {
            assert!(
                shortvec_decode(&overflow).is_err(),
                "accepted out-of-range ShortU16 {overflow:?}"
            );
        }
        for non_minimal in [
            &[0x80, 0x00][..],
            &[0x81, 0x00],
            &[0xff, 0x00],
            &[0x80, 0x80, 0x00],
        ] {
            assert!(
                shortvec_decode(non_minimal).is_err(),
                "accepted non-minimal shortvec {non_minimal:?}"
            );
        }
    }

    #[test]
    fn unsigned_transaction_has_exact_zeroed_signature_slots() {
        let message = [1u8, 2, 3, 4];
        let wire = unsigned_transaction_bytes(&message, 2).expect("wrap message");
        assert_eq!(wire[0], 2);
        assert_eq!(wire.len(), 1 + 2 * 64 + message.len());
        assert!(wire[1..129].iter().all(|byte| *byte == 0));
        assert_eq!(&wire[129..], &message);
        let encoded = unsigned_transaction_base64(&message, 2).expect("base64");
        assert_eq!(base64_decode(&encoded, 1_000).expect("decode"), wire);
    }

    #[test]
    fn unsigned_transaction_rejects_empty_or_impossible_header() {
        assert!(unsigned_transaction_bytes(&[], 1).is_err());
        assert!(unsigned_transaction_bytes(&[1], 256).is_err());
    }

    #[test]
    fn base64_size_bound() {
        assert!(base64_decode("AAAA", 3).is_err());
        assert!(base64_decode("AAAA", 4).is_ok());
    }
}
