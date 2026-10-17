#!/usr/bin/env node
/**
 * Oracle: derive the attestation PDA using sas-lib's deriveAttestationPda.
 * Cross-check against palinurus-core's find_program_address (Rust).
 *
 * Run: node tools/verify-attest-pda.mjs
 * (sas-lib is a devDependency in tools/package.json)
 */

import { deriveAttestationPda } from 'sas-lib';

// Fixed test vector (matches tests/depin_attest.rs test_config + test_reading).
const CREDENTIAL = '22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG'; // SAS (stand-in credential)
const SCHEMA = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';       // Memo (stand-in schema)

// The nonce = Pubkey(sha256(sensor_id || timestamp_le || value_le || unit)).
// This must match the Rust SensorReading::derive_nonce for the same inputs.
// For the test: sensor_id="bme280-1", value=24.7, unit="celsius", timestamp=1753000000.
// The Rust test computes this; we use a known nonce here to cross-check the PDA derivation.
// To get the exact nonce, run: cargo test nonce_matches_manual_sha256 -- --nocapture
// and paste the nonce base58 here. For now, use a placeholder nonce.
const NONCE = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'; // placeholder

async function main() {
  const [pda, bump] = await deriveAttestationPda({
    credential: CREDENTIAL,
    schema: SCHEMA,
    nonce: NONCE,
  });

  console.log('=== Attestation PDA (sas-lib oracle) ===');
  console.log('seeds:    ["attestation", credential, schema, nonce]');
  console.log('credential:', CREDENTIAL);
  console.log('schema:   ', SCHEMA);
  console.log('nonce:    ', NONCE);
  console.log('PDA:      ', pda);
  console.log('bump:     ', bump);
  console.log();
  console.log('Paste this PDA into tests/depin_attest.rs as the expected value.');
}

main().catch(e => { console.error(e); process.exit(1); });
