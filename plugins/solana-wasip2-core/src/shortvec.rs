//! Solana compact-u16 ("shortvec") length encoding.
//!
//! Every length-prefixed field in the transaction wire format uses this, and it
//! is the single easiest thing to get subtly wrong: a naive implementation that
//! emits a continuation bit on the final byte, or one that accepts
//! non-canonical multi-byte encodings of a small value, produces bytes that
//! *look* right until the chain rejects them.
//!
//! Decoding here is deliberately strict. A component that accepts sloppy input
//! and guesses is a component that fails open, which in this codebase is the
//! failure mode that matters ([[reference_bounty_payout_rails]] is unrelated;
//! see the crate README's threat-model section).

/// Append `n` to `out` in compact-u16 form.
pub fn push(out: &mut Vec<u8>, mut n: u16) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

/// Encode `n` on its own.
pub fn encode(n: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(3);
    push(&mut v, n);
    v
}

/// Read a compact-u16 from the front of `input`.
///
/// Returns `(value, bytes_consumed)`. Errors — never panics, never guesses — on:
/// truncated input, more than three bytes, a value that overflows `u16`, and
/// **non-canonical encodings** (a value padded into more bytes than it needs).
/// Rejecting non-canonical forms matters: otherwise two different byte strings
/// decode to the same length, which is a parser-differential waiting to happen.
pub fn decode(input: &[u8]) -> Result<(u16, usize), String> {
    let mut value: u32 = 0;
    for (i, &byte) in input.iter().enumerate() {
        if i >= 3 {
            return Err("compact-u16 longer than 3 bytes".into());
        }
        value |= u32::from(byte & 0x7f) << (i * 7);
        if byte & 0x80 == 0 {
            if value > u16::MAX as u32 {
                return Err(format!("compact-u16 value {value} overflows u16"));
            }
            // Canonical check: re-encoding must reproduce exactly these bytes.
            if encode(value as u16).len() != i + 1 {
                return Err(format!(
                    "non-canonical compact-u16: {value} encoded in {} bytes",
                    i + 1
                ));
            }
            return Ok((value as u16, i + 1));
        }
    }
    Err("truncated compact-u16 (no terminating byte)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from the Solana shortvec spec — carried over verbatim from the
    /// depin-attest implementation these were first proven against.
    const VECTORS: &[(u16, &[u8])] = &[
        (0, &[0x00]),
        (5, &[0x05]),
        (0x7f, &[0x7f]),
        (0x80, &[0x80, 0x01]),
        (0xff, &[0xff, 0x01]),
        (0x100, &[0x80, 0x02]),
        (0x3fff, &[0xff, 0x7f]),
    ];

    #[test]
    fn encodes_known_vectors() {
        for (n, expect) in VECTORS {
            assert_eq!(&encode(*n), expect, "encoding of {n}");
        }
    }

    #[test]
    fn decodes_known_vectors() {
        for (n, bytes) in VECTORS {
            assert_eq!(decode(bytes).unwrap(), (*n, bytes.len()), "decoding {n}");
        }
    }

    #[test]
    fn roundtrips_every_u16() {
        for n in 0..=u16::MAX {
            let e = encode(n);
            assert_eq!(decode(&e).unwrap(), (n, e.len()), "roundtrip {n}");
        }
    }

    #[test]
    fn decode_reports_trailing_bytes_correctly() {
        let mut buf = encode(300);
        buf.extend_from_slice(b"trailing junk");
        let (v, used) = decode(&buf).unwrap();
        assert_eq!(v, 300);
        assert_eq!(used, 2);
    }

    #[test]
    fn rejects_non_canonical_encoding() {
        // 0 padded into two bytes: continuation set, then an empty high group.
        assert!(decode(&[0x80, 0x00]).is_err());
    }

    #[test]
    fn rejects_truncated_and_overlong() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0x80]).is_err());
        assert!(decode(&[0x80, 0x80]).is_err());
        assert!(decode(&[0x80, 0x80, 0x80]).is_err());
    }

    #[test]
    fn rejects_u16_overflow() {
        // 0x1_0000 — one past u16::MAX.
        assert!(decode(&[0x80, 0x80, 0x04]).is_err());
    }
}
