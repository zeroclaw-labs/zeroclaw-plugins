use depin_attest::provenance::{verify_provenance, MAX_STALENESS_SECS};

fn hex_decode(s: &str, out: &mut [u8]) {
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
}

// Helper to get the standard RFC 8032 test vector
fn get_test_vector() -> ([u8; 32], &'static [u8], [u8; 64]) {
    let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    let msg = b"";

    let mut pk = [0u8; 32];
    hex_decode(pk_hex, &mut pk);

    let mut sig = [0u8; 64];
    hex_decode(sig_hex, &mut sig);
    
    (pk, msg, sig)
}

#[test]
fn test_valid_signature_and_fresh_timestamp() {
    let (pk, msg, sig) = get_test_vector();
    let current_ts = 1000000;
    let reading_ts = current_ts - 100; // 100 seconds old
    
    assert!(verify_provenance(&pk, msg, &sig, reading_ts, current_ts).is_ok());
}

#[test]
fn test_tampered_message() {
    let (pk, _msg, sig) = get_test_vector();
    let tampered_msg = b"tampered";
    let current_ts = 1000000;
    let reading_ts = current_ts - 100;
    
    assert!(verify_provenance(&pk, tampered_msg, &sig, reading_ts, current_ts).is_err());
}

#[test]
fn test_wrong_pubkey() {
    let (_, msg, sig) = get_test_vector();
    let mut wrong_pk = [0u8; 32];
    wrong_pk[0] = 0xff; // Alter the pubkey
    let current_ts = 1000000;
    let reading_ts = current_ts - 100;
    
    assert!(verify_provenance(&wrong_pk, msg, &sig, reading_ts, current_ts).is_err());
}

#[test]
fn test_stale_timestamp() {
    let (pk, msg, sig) = get_test_vector();
    let current_ts = 1000000;
    let reading_ts = current_ts - (MAX_STALENESS_SECS + 1); // 301 seconds old
    
    let res = verify_provenance(&pk, msg, &sig, reading_ts, current_ts);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("too stale"));
}

#[test]
fn test_future_timestamp() {
    let (pk, msg, sig) = get_test_vector();
    let current_ts = 1000000;
    let reading_ts = current_ts + 50; // 50 seconds in the future
    
    let res = verify_provenance(&pk, msg, &sig, reading_ts, current_ts);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("in the future"));
}
