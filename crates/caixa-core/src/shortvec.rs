//! Solana compact-u16 (shortvec) encoding.

use crate::encode::Writer;

pub fn push_shortvec_len(w: &mut Writer, len: usize) {
    let mut rem = len;
    loop {
        let mut elem = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem == 0 {
            w.push(elem);
            break;
        } else {
            elem |= 0x80;
            w.push(elem);
        }
    }
}

pub fn encode_len(len: usize) -> Vec<u8> {
    let mut w = Writer::new();
    push_shortvec_len(&mut w, len);
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_boundaries() {
        assert_eq!(encode_len(0), vec![0]);
        assert_eq!(encode_len(127), vec![127]);
        assert_eq!(encode_len(128), vec![0x80, 0x01]);
        assert_eq!(encode_len(0x3fff), vec![0xff, 0x7f]);
    }
}
