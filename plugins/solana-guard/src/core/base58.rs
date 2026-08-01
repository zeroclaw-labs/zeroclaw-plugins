//! Hand-rolled Base58 (Bitcoin alphabet) — no external deps.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode raw bytes as Base58.
pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Leading zero bytes map to leading '1' characters. Encode only the
    // non-leading-zero suffix so an all-zero buffer does not emit an extra '1'.
    let leading_zeros = data.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &data[leading_zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        out.push('1');
    }
    for d in digits.iter().rev() {
        out.push(ALPHABET[*d as usize] as char);
    }
    out
}

/// Decode a Base58 string into raw bytes.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let leading_ones = s.chars().take_while(|c| *c == '1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.chars().skip(leading_ones) {
        let value = ALPHABET
            .iter()
            .position(|&a| a == c as u8)
            .ok_or_else(|| format!("invalid base58 character: {c}"))? as u32;

        let mut carry = value;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry % 256) as u8;
            carry /= 256;
        }
        while carry > 0 {
            bytes.push((carry % 256) as u8);
            carry /= 256;
        }
    }

    let mut out = vec![0u8; leading_ones];
    out.extend(bytes.iter().rev());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_system_program() {
        let pk = [0u8; 32];
        let encoded = encode(&pk);
        assert_eq!(encoded, "11111111111111111111111111111111");
        assert_eq!(decode(&encoded).unwrap(), pk);
    }

    #[test]
    fn roundtrip_randomish() {
        let data: Vec<u8> = (0..32).map(|i| (i * 7 + 3) as u8).collect();
        let encoded = encode(&data);
        assert_eq!(decode(&encoded).unwrap(), data);
    }
}
