//! PIX BR Code (EMV QRCPS-MPM) static “Copia e Cola” payload builder.
//!
//! Layout (IDs):
//! - 00 Payload Format Indicator = `"01"`
//! - 26 Merchant Account Information (GUI + PIX key)
//! - 52 MCC = `"0000"`
//! - 53 Currency = `"986"` (BRL)
//! - 54 Amount (optional)
//! - 58 Country = `"BR"`
//! - 59 Merchant name (≤25)
//! - 60 City (≤15)
//! - 62 Additional Data (txid)
//! - 63 CRC16-CCITT (poly 0x1021, init 0xFFFF)

use crate::shape::{sanitize_alnum, sanitize_pix_key, truncate_upper};

/// Parameters for a static PIX BR Code.
#[derive(Debug, Clone)]
pub struct PixParams<'a> {
    pub pix_key: &'a str,
    pub merchant_name: &'a str,
    pub merchant_city: &'a str,
    /// Amount string e.g. `"150.00"`. When `None`, field 54 is omitted.
    pub amount: Option<&'a str>,
    /// Invoice / transaction id (sanitized to ≤25 alphanumeric).
    pub txid: &'a str,
}

/// The GUI that identifies a PIX merchant account inside field 26. A PIX *key*
/// never contains it — a whole BR Code does, which is the mistake this catches.
const PIX_GUI: &str = "br.gov.bcb.pix";

/// The operator pasted the entire “Copia e Cola” their bank generated into the
/// `pix_key` config instead of the key alone. Wrapping a payload in a payload
/// produces a code no bank will accept, so refuse rather than emit it.
pub const PIX_KEY_IS_PAYLOAD_ERROR: &str =
    "pix_key looks like a whole PIX BR Code, not a key: it contains \
     \"br.gov.bcb.pix\". Set pix_key to the key alone — for a random key that \
     is the UUID that appears right after \"0136\" in the code your bank gave \
     you (36 characters, four hyphens).";

/// Build a complete PIX “Copia e Cola” payload including CRC field `6304XXXX`.
///
/// Fails instead of returning a payload that only *looks* valid. EMV encodes a
/// field length in exactly two decimal digits, so a value of 100 bytes or more
/// writes three digits and shifts every field after it — and the CRC is then
/// computed over the already-corrupted bytes, so the result carries a correct
/// checksum for the wrong structure. Nothing downstream can detect that; the
/// customer's bank app just rejects the code.
pub fn build_pix_payload(params: &PixParams<'_>) -> Result<String, String> {
    // Name: accents stripped + truncated (banks prefer ASCII-ish EMV).
    let name = truncate_upper(params.merchant_name, 25);
    let city = truncate_upper(params.merchant_city, 15);
    let txid = sanitize_txid(params.txid);
    let pix_key = sanitize_pix_key(params.pix_key);

    if pix_key.contains(PIX_GUI) {
        return Err(PIX_KEY_IS_PAYLOAD_ERROR.to_string());
    }

    let mut payload = String::with_capacity(256);
    payload.push_str(&checked_tlv("00", "01")?);

    // Merchant Account Information (ID 26)
    let gui = checked_tlv("00", PIX_GUI)?;
    let key = checked_tlv("01", &pix_key)?;
    let mai = format!("{gui}{key}");
    payload.push_str(&checked_tlv("26", &mai)?);

    payload.push_str(&checked_tlv("52", "0000")?);
    payload.push_str(&checked_tlv("53", "986")?);

    if let Some(amount) = params.amount {
        if !amount.is_empty() {
            payload.push_str(&checked_tlv("54", amount)?);
        }
    }

    payload.push_str(&checked_tlv("58", "BR")?);
    payload.push_str(&checked_tlv("59", &name)?);
    payload.push_str(&checked_tlv("60", &city)?);

    // Additional Data Field Template — subfield 05 = Reference Label (txid)
    let ref_label = if txid.is_empty() {
        "***".to_string()
    } else {
        txid
    };
    let adf = checked_tlv("05", &ref_label)?;
    payload.push_str(&checked_tlv("62", &adf)?);

    // CRC over payload + "6304"
    payload.push_str("6304");
    let crc = crc16_ccitt(payload.as_bytes());
    payload.push_str(&format!("{crc:04X}"));
    Ok(payload)
}

/// Largest value an EMV two-digit length field can describe.
const MAX_TLV_VALUE_LEN: usize = 99;

/// [`tlv`] that refuses to overflow the two-digit length field.
fn checked_tlv(id: &str, value: &str) -> Result<String, String> {
    let len = value.len();
    if len > MAX_TLV_VALUE_LEN {
        return Err(format!(
            "PIX field {id} is {len} bytes; EMV encodes a length in two digits, \
             so anything over {MAX_TLV_VALUE_LEN} would silently corrupt every \
             field after it. Shorten the value behind field {id}."
        ));
    }
    Ok(tlv(id, value))
}

/// Sanitize invoice id for PIX txid: max 25 alphanumeric characters.
pub fn sanitize_txid(s: &str) -> String {
    sanitize_alnum(s, 25)
}

/// EMV TLV: ID (2 chars) + LEN (2 decimal digits) + VALUE.
pub fn tlv(id: &str, value: &str) -> String {
    debug_assert_eq!(id.len(), 2, "EMV ID must be 2 characters");
    let len = value.len();
    // EMV length is byte length of the value (PIX payloads are ASCII).
    format!("{id}{len:02}{value}")
}

/// CRC16-CCITT (poly 0x1021, init 0xFFFF), non-reflected.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pix_starts_with_000201_and_ends_with_crc() {
        let payload = build_pix_payload(&PixParams {
            pix_key: "merchant@example.com",
            merchant_name: "Loja Demo",
            merchant_city: "Sao Paulo",
            amount: Some("150.00"),
            txid: "inv-001",
        })
        .expect("fixture params are valid");
        assert!(
            payload.starts_with("000201"),
            "payload should start with 000201, got {}",
            &payload[..payload.len().min(20)]
        );
        // Ends with 6304 + 4 hex uppercase
        let tail = &payload[payload.len() - 8..];
        assert!(tail.starts_with("6304"), "CRC field missing: tail={tail}");
        let crc_hex = &tail[4..];
        assert_eq!(crc_hex.len(), 4);
        assert!(
            crc_hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()),
            "CRC must be 4 uppercase hex, got {crc_hex}"
        );
    }

    #[test]
    fn crc_is_4_hex_uppercase() {
        let payload = build_pix_payload(&PixParams {
            pix_key: "12345678901",
            merchant_name: "Test",
            merchant_city: "Brasilia",
            amount: Some("10.00"),
            txid: "ABC123",
        })
        .expect("fixture params are valid");
        let crc_hex = &payload[payload.len() - 4..];
        assert_eq!(crc_hex.len(), 4);
        assert!(crc_hex.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')));
    }

    #[test]
    fn crc_matches_known_vector() {
        // Verify algorithm: CRC of "123456789" with this poly/init is a known value
        // for CRC-16/CCITT-FALSE: 0x29B1
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
    }

    #[test]
    fn tlv_format() {
        assert_eq!(tlv("00", "01"), "000201");
        assert_eq!(tlv("58", "BR"), "5802BR");
    }

    /// Reproduces a real misconfiguration seen in production: the operator put
    /// the whole “Copia e Cola” their bank generated into `pix_key`, instead of
    /// the key inside it. The old builder wrapped payload in payload and
    /// returned it with a correct CRC over the corrupt bytes, so nothing looked
    /// wrong until a customer's bank app refused the code.
    #[test]
    fn whole_br_code_pasted_as_the_key_is_refused() {
        let whole_code = "00020101021126580014br.gov.bcb.pix0136\
                          5f82fc06-57d1-4195-977d-81a785ec6909520400005303986\
                          5802BR5922LOJA DEMO6013SAO PAULO62070503***6304EB6A";
        let err = build_pix_payload(&PixParams {
            pix_key: whole_code,
            merchant_name: "Loja Demo",
            merchant_city: "Sao Paulo",
            amount: Some("55.00"),
            txid: "INV-DEMO-A",
        })
        .expect_err("a BR Code is not a key");
        assert_eq!(err, PIX_KEY_IS_PAYLOAD_ERROR);
    }

    /// The deeper defect the case above exposed: EMV writes a length in exactly
    /// two digits, so a 100-byte value emits three and shifts every later field.
    /// Refuse rather than emit a payload whose CRC certifies the wrong shape.
    #[test]
    fn a_field_too_long_for_the_length_prefix_is_refused_not_truncated() {
        let long_key = "a".repeat(100);
        let err = build_pix_payload(&PixParams {
            pix_key: &long_key,
            merchant_name: "Loja",
            merchant_city: "Sao Paulo",
            amount: Some("10.00"),
            txid: "T1",
        })
        .expect_err("100 bytes cannot be described by two digits");
        assert!(
            err.contains("two digits"),
            "the error should say why, got: {err}"
        );
    }

    /// The boundary itself still works: 99 bytes is the largest value two
    /// digits can describe, and field 26 wraps the key with 22 more bytes.
    #[test]
    fn the_longest_key_that_still_fits_is_accepted() {
        let key = "a".repeat(99 - 22);
        let payload = build_pix_payload(&PixParams {
            pix_key: &key,
            merchant_name: "Loja",
            merchant_city: "Sao Paulo",
            amount: Some("10.00"),
            txid: "T1",
        })
        .expect("a key this long still fits field 26");
        assert!(payload.starts_with("00020126"));
    }

    /// Every field of a well-formed payload parses back as ID + 2-digit length
    /// + value, with nothing left over. A payload that has silently overflowed
    /// a length prefix fails this walk, which is what the guards prevent.
    #[test]
    fn a_built_payload_walks_back_as_clean_tlv() {
        let payload = build_pix_payload(&PixParams {
            pix_key: "5f82fc06-57d1-4195-977d-81a785ec6909",
            merchant_name: "Eduardo A A dos Santos",
            merchant_city: "Sao Paulo",
            amount: Some("55.00"),
            txid: "INV-DEMO-A",
        })
        .expect("fixture params are valid");

        let bytes = payload.as_bytes();
        let mut i = 0;
        let mut seen = Vec::new();
        while i < bytes.len() {
            assert!(i + 4 <= bytes.len(), "trailing bytes are not a TLV header");
            let id = &payload[i..i + 2];
            let len: usize = payload[i + 2..i + 4]
                .parse()
                .unwrap_or_else(|_| panic!("length after id {id} is not two digits"));
            assert!(i + 4 + len <= bytes.len(), "field {id} claims {len} bytes");
            seen.push(id.to_string());
            i += 4 + len;
        }
        assert_eq!(i, bytes.len(), "payload did not end on a field boundary");
        assert_eq!(seen.first().map(String::as_str), Some("00"));
        assert_eq!(seen.last().map(String::as_str), Some("63"));
    }

    #[test]
    fn amount_field_present() {
        let payload = build_pix_payload(&PixParams {
            pix_key: "k@e.com",
            merchant_name: "M",
            merchant_city: "C",
            amount: Some("150.00"),
            txid: "T1",
        })
        .expect("fixture params are valid");
        assert!(payload.contains("54150.00") || payload.contains("5406150.00"));
        // 54 + len 6 + 150.00
        assert!(payload.contains("5406150.00"));
    }

    #[test]
    fn name_truncated_to_25() {
        let long = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 26
        let payload = build_pix_payload(&PixParams {
            pix_key: "k",
            merchant_name: long,
            merchant_city: "CITY",
            amount: None,
            txid: "x",
        })
        .expect("fixture params are valid");
        // 59 + 25 + first 25 letters (uppercase via truncate_upper)
        assert!(payload.contains("5925ABCDEFGHIJKLMNOPQRSTUVWXY"));
        assert!(!payload.contains("5926"));
    }

    #[test]
    fn cpf_key_strips_punctuation() {
        let payload = build_pix_payload(&PixParams {
            pix_key: "123.456.789-09",
            merchant_name: "Loja",
            merchant_city: "SP",
            amount: Some("1.00"),
            txid: "T1",
        })
        .expect("fixture params are valid");
        assert!(payload.contains("12345678909"));
        assert!(!payload.contains("123.456"));
    }
}
