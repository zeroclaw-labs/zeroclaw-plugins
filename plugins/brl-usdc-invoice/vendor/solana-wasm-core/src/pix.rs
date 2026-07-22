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

/// Build a complete PIX “Copia e Cola” payload including CRC field `6304XXXX`.
pub fn build_pix_payload(params: &PixParams<'_>) -> String {
    // Name: accents stripped + truncated (banks prefer ASCII-ish EMV).
    let name = truncate_upper(params.merchant_name, 25);
    let city = truncate_upper(params.merchant_city, 15);
    let txid = sanitize_txid(params.txid);
    let pix_key = sanitize_pix_key(params.pix_key);

    let mut payload = String::with_capacity(256);
    payload.push_str(&tlv("00", "01"));

    // Merchant Account Information (ID 26)
    let gui = tlv("00", "br.gov.bcb.pix");
    let key = tlv("01", &pix_key);
    let mai = format!("{gui}{key}");
    payload.push_str(&tlv("26", &mai));

    payload.push_str(&tlv("52", "0000"));
    payload.push_str(&tlv("53", "986"));

    if let Some(amount) = params.amount {
        if !amount.is_empty() {
            payload.push_str(&tlv("54", amount));
        }
    }

    payload.push_str(&tlv("58", "BR"));
    payload.push_str(&tlv("59", &name));
    payload.push_str(&tlv("60", &city));

    // Additional Data Field Template — subfield 05 = Reference Label (txid)
    let ref_label = if txid.is_empty() {
        "***".to_string()
    } else {
        txid
    };
    let adf = tlv("05", &ref_label);
    payload.push_str(&tlv("62", &adf));

    // CRC over payload + "6304"
    payload.push_str("6304");
    let crc = crc16_ccitt(payload.as_bytes());
    payload.push_str(&format!("{crc:04X}"));
    payload
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
        });
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
        });
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

    #[test]
    fn amount_field_present() {
        let payload = build_pix_payload(&PixParams {
            pix_key: "k@e.com",
            merchant_name: "M",
            merchant_city: "C",
            amount: Some("150.00"),
            txid: "T1",
        });
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
        });
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
        });
        assert!(payload.contains("12345678909"));
        assert!(!payload.contains("123.456"));
    }
}
