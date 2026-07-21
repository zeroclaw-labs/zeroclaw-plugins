use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// We allow up to 300 seconds (5 minutes) of staleness. 
// DePIN sensors often operate on loose networks (cellular, LoRaWAN) where 
// small buffering or transmission delays are normal. However, any reading older 
// than 5 minutes risks being a replay of stale state rather than a current attestation.
pub const MAX_STALENESS_SECS: i64 = 300;

pub fn verify_provenance(
    pubkey: &[u8; 32],
    message: &[u8],
    sig: &[u8; 64],
    reading_timestamp: i64,
    current_timestamp: i64,
) -> Result<(), String> {
    let verifying_key = VerifyingKey::from_bytes(pubkey).map_err(|e| e.to_string())?;
    let signature = Signature::from_bytes(sig);
    
    verifying_key
        .verify(message, &signature)
        .map_err(|e| format!("Invalid signature: {}", e))?;

    let age = current_timestamp - reading_timestamp;
    if age < 0 {
        return Err("Reading timestamp is in the future".to_string());
    }
    
    if age > MAX_STALENESS_SECS {
        return Err(format!(
            "Reading is too stale: {} seconds old (max {})",
            age, MAX_STALENESS_SECS
        ));
    }

    Ok(())
}
