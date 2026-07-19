#!/usr/bin/env node
/**
 * Oracle: build the full SAS create_attestation instruction using sas-lib's
 * getCreateAttestationInstruction. Cross-check the accounts (order, isSigner,
 * isWritable) + data against the Rust build_attest_ix output.
 *
 * Run: node tools/verify-attest-ix.mjs
 * (sas-lib is a devDependency in tools/package.json)
 */

import { getCreateAttestationInstruction } from 'sas-lib';

// Fixed test vector (matches tests/depin_attest.rs).
const PAYER = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const AUTHORITY = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const CREDENTIAL = '22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG';
const SCHEMA = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const ATTESTATION = '11111111111111111111111111111111'; // placeholder — derive from verify-attest-pda.mjs
const NONCE = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'; // placeholder
const DATA = Buffer.from('palinurus test payload');
const EXPIRY = 1760776000n;

const ix = getCreateAttestationInstruction({
  payer: PAYER,
  authority: AUTHORITY,
  credential: CREDENTIAL,
  schema: SCHEMA,
  attestation: ATTESTATION,
  nonce: NONCE,
  data: DATA,
  expiry: EXPIRY,
});

console.log('=== SAS create_attestation instruction (sas-lib oracle) ===');
console.log('program:', ix.programAddress);
console.log();
console.log('accounts (order, isSigner, isWritable):');
ix.accounts.forEach((a, i) => {
  console.log(`  [${i}] ${a.address}  signer=${a.isSigner}  writable=${a.isWritable}`);
});
console.log();
console.log('data hex:', Buffer.from(ix.data).toString('hex'));
console.log('data len:', ix.data.length);
console.log();
console.log('Cross-check against Rust build_attest_ix output:');
console.log('  - program_id must be SAS (22zoJ…)');
console.log('  - 6 accounts: [payer W-signer, authority R-signer, credential R, schema R, attestation W, system R]');
console.log('  - data = [disc=6][nonce 32B][u32 LE len][data][i64 LE expiry]');
