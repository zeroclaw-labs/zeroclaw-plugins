#!/usr/bin/env node
/**
 * Sign and send a Safe Hands transparency-log anchor.
 *
 *   just log-anchor                     # prints the unsigned transaction
 *   node tools/sign-anchor.js <keypair.json> <unsigned-base64> [rpc-url]
 *
 * Safe Hands never holds a key, so `--log-anchor` stops at unsigned bytes like
 * every other transaction the suite produces. This is the operator's half:
 * their key, their signature, their submission.
 *
 * No dependencies. Node's crypto has had Ed25519 since v12, so a Solana CLI
 * keypair file can be used directly without pulling in a signing library — one
 * fewer package with access to a private key, which is the point of a tool like
 * this existing at all.
 *
 * It refuses to sign anything that is not an anchor. A script that will sign
 * whatever base64 it is handed is a signing oracle, and handing one to an agent
 * would undo the entire architecture.
 */

'use strict';

const fs = require('fs');
const crypto = require('crypto');

const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const ANCHOR_PREFIX = 'sh1 ';
const DEFAULT_RPC = 'https://api.devnet.solana.com';

// ── base58 ──────────────────────────────────────────────────────────────────

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  let num = 0n;
  for (const byte of bytes) num = num * 256n + BigInt(byte);
  let out = '';
  while (num > 0n) {
    out = B58[Number(num % 58n)] + out;
    num /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    out = '1' + out;
  }
  return out || '1';
}

function base58Decode(text) {
  let num = 0n;
  for (const ch of text) {
    const index = B58.indexOf(ch);
    if (index < 0) throw new Error(`not base58: ${text}`);
    num = num * 58n + BigInt(index);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num /= 256n;
  }
  for (const ch of text) {
    if (ch !== '1') break;
    bytes.unshift(0);
  }
  return Buffer.from(bytes);
}

// ── wire format ─────────────────────────────────────────────────────────────

/** Read a compact-u16 (shortvec) length. Returns [value, bytesConsumed]. */
function readCompactU16(buffer, offset) {
  let value = 0;
  let consumed = 0;
  for (;;) {
    const byte = buffer[offset + consumed];
    if (byte === undefined) throw new Error('truncated compact-u16');
    value |= (byte & 0x7f) << (7 * consumed);
    consumed += 1;
    if ((byte & 0x80) === 0) break;
    if (consumed > 3) throw new Error('malformed compact-u16');
  }
  return [value, consumed];
}

/**
 * Pull apart an unsigned transaction far enough to check it and to find the
 * blockhash. Deliberately a partial parse: this tool must understand what it is
 * signing, but it has no business rewriting instructions.
 */
function inspect(wire) {
  const [signatureCount, sigLenBytes] = readCompactU16(wire, 0);
  if (signatureCount !== 1) {
    throw new Error(`expected exactly one signature slot, found ${signatureCount}`);
  }
  const sigStart = sigLenBytes;
  const messageStart = sigStart + 64 * signatureCount;
  const signature = wire.subarray(sigStart, messageStart);
  if (!signature.every((byte) => byte === 0)) {
    throw new Error('this transaction is already signed; refusing to sign it again');
  }

  const message = wire.subarray(messageStart);
  const numRequiredSignatures = message[0];
  if (numRequiredSignatures !== 1) {
    throw new Error(`message wants ${numRequiredSignatures} signatures, this tool provides one`);
  }
  const [accountCount, accountLenBytes] = readCompactU16(message, 3);
  const keysStart = 3 + accountLenBytes;
  const keys = [];
  for (let i = 0; i < accountCount; i += 1) {
    keys.push(message.subarray(keysStart + 32 * i, keysStart + 32 * (i + 1)));
  }
  const blockhashOffset = messageStart + keysStart + 32 * accountCount;

  return { messageStart, blockhashOffset, keys, feePayer: keys[0] };
}

/** The anchor memo carried by this transaction, or null if there is not one. */
function anchorMemo(wire, keys) {
  const text = wire.toString('utf8');
  const start = text.indexOf(ANCHOR_PREFIX);
  if (start < 0) return null;
  if (!keys.some((key) => base58Encode(key) === MEMO_PROGRAM)) return null;
  return text.slice(start).trim();
}

// ── signing ─────────────────────────────────────────────────────────────────

/** Wrap a raw Ed25519 seed in the PKCS#8 envelope Node's crypto expects. */
function privateKeyFromSeed(seed) {
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    seed,
  ]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

async function rpc(url, method, params) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function main() {
  const [keypairPath, unsignedBase64, rpcArg] = process.argv.slice(2);
  if (!keypairPath || !unsignedBase64) {
    console.error('usage: node tools/sign-anchor.js <keypair.json> <unsigned-base64> [rpc-url]');
    process.exit(2);
  }
  const url = rpcArg || process.env.SOLANA_RPC_URL || DEFAULT_RPC;

  const secret = Buffer.from(JSON.parse(fs.readFileSync(keypairPath, 'utf8')));
  if (secret.length !== 64) {
    throw new Error(`${keypairPath} is not a 64-byte Solana keypair`);
  }
  const seed = secret.subarray(0, 32);
  const publicKey = secret.subarray(32);

  const wire = Buffer.from(unsignedBase64.trim(), 'base64');
  const { blockhashOffset, keys, feePayer } = inspect(wire);

  const memo = anchorMemo(wire, keys);
  if (!memo) {
    throw new Error(
      'this transaction is not a Safe Hands anchor — it carries no `sh1` memo to the ' +
        'SPL Memo program. This tool signs anchors and nothing else.',
    );
  }
  if (!feePayer.equals(publicKey)) {
    throw new Error(
      `fee payer is ${base58Encode(feePayer)}, but ${keypairPath} holds ` +
        `${base58Encode(publicKey)}`,
    );
  }

  // A human looking at an anchor takes longer than a blockhash lives. Refresh
  // it in place: the 32 bytes at a known offset, nothing else. The memo — the
  // only thing being attested — is untouched.
  const { value } = await rpc(url, 'getLatestBlockhash', [{ commitment: 'finalized' }]);
  base58Decode(value.blockhash).copy(wire, blockhashOffset);

  const message = wire.subarray(inspect(wire).messageStart);
  const signature = crypto.sign(null, message, privateKeyFromSeed(seed));
  signature.copy(wire, 1);

  const txSignature = await rpc(url, 'sendTransaction', [
    wire.toString('base64'),
    { encoding: 'base64', preflightCommitment: 'confirmed' },
  ]);

  console.log(`memo       ${memo}`);
  console.log(`signer     ${base58Encode(publicKey)}`);
  console.log(`signature  ${txSignature}`);
  console.log(`explorer   https://explorer.solana.com/tx/${txSignature}?cluster=devnet`);
  console.log('\nThe head is published. Every entry it covers is now pinned.');
}

main().catch((error) => {
  console.error(`\n${error.message}`);
  process.exit(1);
});
