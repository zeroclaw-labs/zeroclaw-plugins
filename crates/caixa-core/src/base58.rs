//! Bitcoin-alphabet base58 encode/decode (Solana pubkeys / signatures).

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut zeros = 0usize;
    while zeros < data.len() && data[zeros] == 0 {
        zeros += 1;
    }

    let size = (data.len() - zeros) * 138 / 100 + 1;
    let mut buf = vec![0u8; size];
    let mut length = 0usize;

    for &byte in &data[zeros..] {
        let mut carry = byte as u32;
        let mut j = 0usize;
        let mut k = size;
        while k > 0 && (carry != 0 || j < length) {
            k -= 1;
            carry += 256 * (buf[k] as u32);
            buf[k] = (carry % 58) as u8;
            carry /= 58;
            j += 1;
        }
        length = j;
    }

    let mut i = size - length;
    while i < size && buf[i] == 0 {
        i += 1;
    }

    let mut out = String::with_capacity(zeros + (size - i));
    for _ in 0..zeros {
        out.push('1');
    }
    for &b in &buf[i..] {
        out.push(ALPHABET[b as usize] as char);
    }
    out
}

pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let mut zeros = 0usize;
    for c in s.chars() {
        if c == '1' {
            zeros += 1;
        } else {
            break;
        }
    }

    let size = s.len() * 733 / 1000 + 1;
    let mut buf = vec![0u8; size];
    let mut length = 0usize;

    for c in s.chars().skip(zeros) {
        let digit = ALPHABET
            .iter()
            .position(|&a| a == c as u8)
            .ok_or_else(|| format!("invalid base58 character: {c}"))? as u32;
        let mut carry = digit;
        let mut j = 0usize;
        let mut k = size;
        while k > 0 && (carry != 0 || j < length) {
            k -= 1;
            carry += 58 * (buf[k] as u32);
            buf[k] = (carry % 256) as u8;
            carry /= 256;
            j += 1;
        }
        length = j;
    }

    let mut i = size - length;
    while i < size && buf[i] == 0 {
        i += 1;
    }

    let mut out = vec![0u8; zeros];
    out.extend_from_slice(&buf[i..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_system_program() {
        let raw = [0u8; 32];
        let s = encode(&raw);
        assert_eq!(s, "11111111111111111111111111111111");
        assert_eq!(decode(&s).unwrap(), raw);
    }

    #[test]
    fn known_vector() {
        // "Hello World" classic vector is base58check; use raw bytes instead.
        let data = b"\x00\x00\x00\x00";
        let enc = encode(data);
        assert!(enc.starts_with("1111"));
        assert_eq!(decode(&enc).unwrap(), data);
    }
}
