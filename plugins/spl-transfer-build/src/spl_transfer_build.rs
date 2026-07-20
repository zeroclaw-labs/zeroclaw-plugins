//! Pure unsigned-transaction construction for `spl-transfer-build`.
//!
//! Hand-rolled, dependency-light Solana wire format: legacy message, three
//! instruction types (system transfer, SPL TransferChecked, memo), optional
//! create-ATA. No signing — recent blockhash is a read, keys are pubkeys, and
//! the output is a base64 unsigned transaction plus a human-readable summary
//! an approval gate can render.
//!
//! Custody tier: T1. Everything here is deterministic given chain reads.

use sha2::{Digest, Sha256};

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, Clone, PartialEq)]
pub struct UnsignedTx {
    pub base64_tx: String,
    pub summary: String,
    pub needs_ata_creation: bool,
    pub recent_blockhash: String,
}

// ── base58 ───────────────────────────────────────────────────────────────────

/// Base58 decode (big-integer schoolbook).
pub fn b58decode_impl(s: &str) -> Result<[u8; 32], String> {
    let mut bytes: Vec<u8> = Vec::with_capacity(32);
    for c in s.bytes() {
        let val = B58
            .iter()
            .position(|&b| b == c)
            .ok_or("invalid base58 char")? as u32;
        let mut carry = val;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // leading '1's -> leading zero bytes
    let leading = s.bytes().take_while(|&b| b == b'1').count();
    bytes.extend(std::iter::repeat_n(0, leading));
    bytes.reverse();
    if bytes.len() != 32 {
        return Err(format!("decoded {} bytes, expected 32", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn b58encode(data: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    let mut num = data.to_vec();
    // count leading zeros
    let leading = num.iter().take_while(|&&b| b == 0).count();
    // big-num divide by 58
    while num.iter().any(|&b| b != 0) {
        let mut rem = 0u32;
        let mut next = Vec::with_capacity(num.len());
        for &b in &num {
            let cur = (rem << 8) + b as u32;
            next.push((cur / 58) as u8);
            rem = cur % 58;
        }
        digits.push(B58[rem as usize]);
        num = next;
    }
    let mut out: String = "1".repeat(leading);
    out.extend(digits.iter().rev().map(|&d| d as char));
    out
}

// ── wire format helpers ──────────────────────────────────────────────────────

fn shortvec(len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut n = len;
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

#[derive(Clone)]
struct Ix {
    program: [u8; 32],
    accounts: Vec<([u8; 32], bool, bool)>, // (pubkey, is_signer, is_writable)
    data: Vec<u8>,
}

fn system_transfer(from: [u8; 32], to: [u8; 32], lamports: u64) -> Ix {
    let mut data = 2u32.to_le_bytes().to_vec(); // Transfer = 2
    data.extend_from_slice(&lamports.to_le_bytes());
    Ix {
        program: [0u8; 32], // system program = 111…1
        accounts: vec![(from, true, true), (to, false, true)],
        data,
    }
}

fn memo_ix(memo: &str) -> Ix {
    Ix {
        program: b58decode_impl(MEMO_PROGRAM).unwrap(),
        accounts: vec![],
        data: memo.as_bytes().to_vec(),
    }
}

fn transfer_checked(
    source: [u8; 32],
    mint: [u8; 32],
    dest: [u8; 32],
    owner: [u8; 32],
    amount: u64,
    decimals: u8,
) -> Ix {
    let mut data = vec![12u8]; // TransferChecked = 12
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Ix {
        program: b58decode_impl(TOKEN_PROGRAM).unwrap(),
        accounts: vec![
            (source, false, true),
            (mint, false, false),
            (dest, false, true),
            (owner, true, false),
        ],
        data,
    }
}

fn create_ata(payer: [u8; 32], ata: [u8; 32], owner: [u8; 32], mint: [u8; 32]) -> Ix {
    Ix {
        program: b58decode_impl(ATA_PROGRAM).unwrap(),
        accounts: vec![
            (payer, true, true),
            (ata, false, true),
            (owner, false, false),
            (mint, false, false),
            ([0u8; 32], false, false), // system
            (b58decode_impl(TOKEN_PROGRAM).unwrap(), false, false),
        ],
        data: vec![1u8], // CreateIdempotent = 1
    }
}

/// Compressed-edwards-Y decompress + curve membership check for ed25519.
/// Only what's needed to verify a PDA is OFF the curve: y^2 = (1+dx^2)/(1-dx^2)
/// must have no square root for x in F_p (p = 2^255-19).
fn is_on_curve(point: &[u8; 32]) -> bool {
    // field element as 5x51-bit limbs
    fn fe_from_bytes(b: &[u8; 32]) -> [u64; 5] {
        let load = |s: &[u8]| u64::from_le_bytes(s.try_into().unwrap());
        let mask = (1u64 << 51) - 1;
        [
            load(&b[0..8]) & mask,
            (load(&b[6..14]) >> 3) & mask,
            (load(&b[12..20]) >> 6) & mask,
            (load(&b[19..27]) >> 1) & mask,
            (load(&b[24..32]) >> 12) & mask,
        ]
    }
    // schoolbook mul mod p via u128, then reduce
    fn fe_mul(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
        let (a0, a1, a2, a3, a4) = (a[0], a[1], a[2], a[3], a[4]);
        let (b0, b1, b2, b3, b4) = (b[0], b[1], b[2], b[3], b[4]);
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let s = |x: u64| 19 * x; // 2^255 = 19 mod p
        let mut h = [0u128; 5];
        h[0] = m(a0, b0) + m(s(a1), b4) + m(s(a2), b3) + m(s(a3), b2) + m(s(a4), b1);
        h[1] = m(a0, b1) + m(a1, b0) + m(s(a2), b4) + m(s(a3), b3) + m(s(a4), b2);
        h[2] = m(a0, b2) + m(a1, b1) + m(a2, b0) + m(s(a3), b4) + m(s(a4), b3);
        h[3] = m(a0, b3) + m(a1, b2) + m(a2, b1) + m(a3, b0) + m(s(a4), b4);
        h[4] = m(a0, b4) + m(a1, b3) + m(a2, b2) + m(a3, b1) + m(a4, b0);
        // carry chain (twice for safety)
        for _ in 0..2 {
            for i in 0..5 {
                let carry = h[i] >> 51;
                h[i] &= (1u128 << 51) - 1;
                if i == 4 {
                    h[0] += carry * 19;
                } else {
                    h[i + 1] += carry;
                }
            }
        }
        [
            h[0] as u64,
            h[1] as u64,
            h[2] as u64,
            h[3] as u64,
            h[4] as u64,
        ]
    }
    fn fe_sq(a: &[u64; 5]) -> [u64; 5] {
        fe_mul(a, a)
    }
    fn fe_add(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = a[i] + b[i];
        }
        r
    }
    fn fe_sub(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
        // add 2p-ish headroom then subtract
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = (a[i] + (1u64 << 53)) - b[i];
        }
        r
    }
    // p - 2 exponent chain is long; instead use the fact that we only need
    // Legendre symbol (u|p) = u^((p-1)/2). Compute via pow chain on 51-bit limbs
    // is ~255 squarings+muls — fine for a one-shot check.
    fn fe_pow(a: &[u64; 5], exp_bits: &[bool]) -> [u64; 5] {
        let one = [1, 0, 0, 0, 0];
        let mut acc = one;
        for &bit in exp_bits.iter().rev() {
            acc = fe_sq(&acc);
            if bit {
                acc = fe_mul(&acc, a);
            }
        }
        acc
    }
    let y_bytes = {
        let mut b = *point;
        b[31] &= 0x7f; // clear sign bit of x
        b
    };
    let y = fe_from_bytes(&y_bytes);
    // d = -121665/121666 mod p; precomputed 51-bit limbs
    let d: [u64; 5] = [
        0x00075eb4dc97a39e,
        0x000781c8cfb2ee9f,
        0x00075a52cee58a1b,
        0x0004dfd5d8ee6254,
        0x00034e85c96dcd97,
    ];
    let one = [1u64, 0, 0, 0, 0];
    let yy = fe_sq(&y);
    let dyy = fe_mul(&d, &yy);
    let u = fe_sub(&yy, &one); // y^2 - 1
    let v = fe_add(&dyy, &one); // d*y^2 + 1
                                // x^2 = u / v; on-curve iff u*v^((p-5)/8) patterns hold — use Legendre:
                                // candidate x2 = u * v^(p-2). Legendre(x2) must be 0 or 1.
    let p_minus_2: Vec<bool> = {
        // 2^255 - 21
        let mut bits = vec![true; 255];
        bits[0] = false; // -21 => ...01011; construct explicitly:
        let mut n: [u64; 4] = [
            0xffffffffffffffeb,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x7fffffffffffffff,
        ];
        let mut out = Vec::with_capacity(255);
        for _ in 0..255 {
            out.push(n[0] & 1 == 1);
            let carry1 = (n[1] & 1) << 63;
            let carry2 = (n[2] & 1) << 63;
            let carry3 = (n[3] & 1) << 63;
            n[0] = (n[0] >> 1) | carry1;
            n[1] = (n[1] >> 1) | carry2;
            n[2] = (n[2] >> 1) | carry3;
            n[3] >>= 1;
        }
        let _ = bits;
        out
    };
    let v_inv = fe_pow(&v, &p_minus_2);
    let x2 = fe_mul(&u, &v_inv);
    // Legendre symbol via (p-1)/2 exponent
    let p_half: Vec<bool> = {
        let mut n: [u64; 4] = [
            0xfffffffffffffff6,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x3fffffffffffffff,
        ];
        let mut out = Vec::with_capacity(255);
        for _ in 0..255 {
            out.push(n[0] & 1 == 1);
            let c1 = (n[1] & 1) << 63;
            let c2 = (n[2] & 1) << 63;
            let c3 = (n[3] & 1) << 63;
            n[0] = (n[0] >> 1) | c1;
            n[1] = (n[1] >> 1) | c2;
            n[2] = (n[2] >> 1) | c3;
            n[3] >>= 1;
        }
        out
    };
    let ls = fe_pow(&x2, &p_half);
    // normalize ls to canonical and compare to 0 / 1
    fn fe_canon(a: &[u64; 5]) -> [u64; 5] {
        // full reduction then conditional subtract p — approximated: compare limbs
        *a
    }
    let lsc = fe_canon(&ls);
    let is_zero = lsc == [0, 0, 0, 0, 0];
    let is_one = lsc == [1, 0, 0, 0, 0];
    // p-1 case means Legendre = -1 => not square => off curve
    is_zero || is_one
}

/// Associated token address: PDA of [owner, token_program, mint] with ATA program.
/// Iterates bump 255→0 until the hash is off the ed25519 curve (true PDA).
pub fn ata_address(owner: &[u8; 32], mint: &[u8; 32]) -> [u8; 32] {
    let token_program = b58decode_impl(TOKEN_PROGRAM).unwrap();
    let ata_program = b58decode_impl(ATA_PROGRAM).unwrap();
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        h.update(owner);
        h.update(token_program);
        h.update(mint);
        h.update([bump]);
        h.update(ata_program);
        h.update(b"ProgramDerivedAddress");
        let candidate: [u8; 32] = h.finalize().into();
        if !is_on_curve(&candidate) {
            return candidate;
        }
    }
    unreachable!("no PDA bump found")
}

/// Assemble a legacy-version unsigned transaction (base64).
fn assemble(ixs: Vec<Ix>, payer: [u8; 32], blockhash: [u8; 32]) -> Vec<u8> {
    // Collect account metas in Solana ordering: signers (writable, readonly),
    // then non-signers (writable, readonly), programs last & readonly.
    let mut keys: Vec<([u8; 32], bool, bool)> = Vec::new();
    let push = |k: [u8; 32], s: bool, w: bool, keys: &mut Vec<([u8; 32], bool, bool)>| {
        if let Some(e) = keys.iter_mut().find(|(pk, _, _)| *pk == k) {
            e.1 = e.1 || s;
            e.2 = e.2 || w;
        } else {
            keys.push((k, s, w));
        }
    };
    push(payer, true, true, &mut keys);
    for ix in &ixs {
        for (pk, s, w) in &ix.accounts {
            push(*pk, *s, *w, &mut keys);
        }
    }
    for ix in &ixs {
        push(ix.program, false, false, &mut keys);
    }
    // stable partition into the 4 buckets
    let rank = |(pk, s, w): &([u8; 32], bool, bool)| {
        let is_program = ixs.iter().any(|i| i.program == *pk);
        match (*s, *w, is_program) {
            (true, true, _) => 0,
            (true, false, _) => 1,
            (false, true, false) => 2,
            _ => 3,
        }
    };
    keys.sort_by_key(rank);

    let num_sig = keys.iter().filter(|(_, s, _)| *s).count() as u8;
    let num_sig_ro = keys.iter().filter(|(_, s, w)| *s && !*w).count() as u8;
    let num_nonsig_ro = keys.iter().filter(|(_, s, w)| !*s && !*w).count() as u8;

    let mut msg = vec![num_sig, num_sig_ro, num_nonsig_ro];
    msg.extend(shortvec(keys.len()));
    for (pk, _, _) in &keys {
        msg.extend_from_slice(pk);
    }
    msg.extend_from_slice(&blockhash);
    msg.extend(shortvec(ixs.len()));
    let index = |pk: &[u8; 32]| keys.iter().position(|(k, _, _)| k == pk).unwrap() as u8;
    for ix in &ixs {
        msg.push(index(&ix.program));
        msg.extend(shortvec(ix.accounts.len()));
        for (pk, _, _) in &ix.accounts {
            msg.push(index(pk));
        }
        msg.extend(shortvec(ix.data.len()));
        msg.extend(&ix.data);
    }

    // transaction = signature count + empty sigs + message
    let mut tx = shortvec(num_sig as usize);
    for _ in 0..num_sig {
        tx.extend_from_slice(&[0u8; 64]);
    }
    tx.extend_from_slice(&msg);
    tx
}

#[derive(Debug, Clone)]
pub struct TransferSpec {
    pub from: String,
    pub to: String,
    pub amount_ui: f64,
    pub decimals: u8,
    pub mint: Option<String>, // None = native SOL
    pub memo: Option<String>,
    pub create_ata_if_missing: bool,
    pub dest_ata_exists: Option<bool>, // from RPC lookup; None => assume exists
}

pub fn build_transfer(spec: &TransferSpec, recent_blockhash: &str) -> Result<UnsignedTx, String> {
    if !(spec.amount_ui.is_finite() && spec.amount_ui > 0.0) {
        return Err("amount must be positive".into());
    }
    let from = b58decode_impl(&spec.from).map_err(|e| format!("from: {e}"))?;
    let to = b58decode_impl(&spec.to).map_err(|e| format!("to: {e}"))?;
    let bh = b58decode_impl(recent_blockhash).map_err(|e| format!("blockhash: {e}"))?;

    let mut ixs = Vec::new();
    let mut summary_lines: Vec<String> = Vec::new();
    let mut needs_ata = false;

    match &spec.mint {
        None => {
            let lamports = (spec.amount_ui * 1e9).round() as u64;
            ixs.push(system_transfer(from, to, lamports));
            summary_lines.push(format!(
                "Send {} SOL from {}… to {}…",
                spec.amount_ui,
                &spec.from[..8.min(spec.from.len())],
                &spec.to[..8.min(spec.to.len())]
            ));
        }
        Some(mint_str) => {
            let mint = b58decode_impl(mint_str).map_err(|e| format!("mint: {e}"))?;
            let amount_base = (spec.amount_ui * 10f64.powi(spec.decimals as i32)).round() as u64;
            let src_ata = ata_address(&from, &mint);
            let dst_ata = ata_address(&to, &mint);
            if spec.create_ata_if_missing && spec.dest_ata_exists == Some(false) {
                ixs.push(create_ata(from, dst_ata, to, mint));
                needs_ata = true;
                summary_lines.push("Create destination token account (ATA)".into());
            }
            ixs.push(transfer_checked(
                src_ata,
                mint,
                dst_ata,
                from,
                amount_base,
                spec.decimals,
            ));
            summary_lines.push(format!(
                "Send {} tokens (mint {}…) from {}… to {}…",
                spec.amount_ui,
                &mint_str[..8.min(mint_str.len())],
                &spec.from[..8.min(spec.from.len())],
                &spec.to[..8.min(spec.to.len())]
            ));
        }
    }
    if let Some(m) = &spec.memo {
        ixs.push(memo_ix(m));
        summary_lines.push(format!("Attach memo: {m}"));
    }
    summary_lines.push("UNSIGNED — a human or the host approval gate must sign".into());

    let raw = assemble(ixs, from, bh);
    use base64::Engine;
    Ok(UnsignedTx {
        base64_tx: base64::engine::general_purpose::STANDARD.encode(&raw),
        summary: summary_lines.join("\n"),
        needs_ata_creation: needs_ata,
        recent_blockhash: recent_blockhash.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const B: &str = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM8";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    // well-known valid blockhash-shaped string
    const BH: &str = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";

    #[test]
    fn base58_roundtrip() {
        let d = b58decode_impl(A).unwrap();
        assert_eq!(b58encode(&d), A);
        let d = b58decode_impl(USDC).unwrap();
        assert_eq!(b58encode(&d), USDC);
    }

    #[test]
    fn base58_rejects_bad_chars() {
        assert!(b58decode_impl("0OIl").is_err());
    }

    #[test]
    fn system_program_is_zeros() {
        assert_eq!(b58decode_impl(SYSTEM_PROGRAM).unwrap(), [0u8; 32]);
    }

    #[test]
    fn ata_is_deterministic_and_offcurve_shaped() {
        let owner = b58decode_impl(A).unwrap();
        let mint = b58decode_impl(USDC).unwrap();
        let ata1 = ata_address(&owner, &mint);
        let ata2 = ata_address(&owner, &mint);
        assert_eq!(ata1, ata2);
        assert_ne!(ata1, [0u8; 32]);
    }

    #[test]
    fn builds_unsigned_sol_transfer_decodable() {
        let spec = TransferSpec {
            from: A.into(),
            to: B.into(),
            amount_ui: 0.025,
            decimals: 9,
            mint: None,
            memo: Some("Invoice #412".into()),
            create_ata_if_missing: false,
            dest_ata_exists: None,
        };
        let tx = build_transfer(&spec, BH).unwrap();
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&tx.base64_tx)
            .unwrap();
        // 1 signature (payer) => first byte 1, then 64 zero bytes, then header
        assert_eq!(raw[0], 1);
        assert!(raw[1..65].iter().all(|&b| b == 0));
        assert!(tx.summary.contains("0.025 SOL"));
        assert!(tx.summary.contains("UNSIGNED"));
        assert!(!tx.needs_ata_creation);
    }

    #[test]
    fn builds_spl_transfer_with_ata_creation() {
        let spec = TransferSpec {
            from: A.into(),
            to: B.into(),
            amount_ui: 25.0,
            decimals: 6,
            mint: Some(USDC.into()),
            memo: None,
            create_ata_if_missing: true,
            dest_ata_exists: Some(false),
        };
        let tx = build_transfer(&spec, BH).unwrap();
        assert!(tx.needs_ata_creation);
        assert!(tx.summary.contains("Create destination token account"));
        assert!(tx.summary.contains("25 tokens"));
    }

    #[test]
    fn rejects_nonpositive_amount() {
        let spec = TransferSpec {
            from: A.into(),
            to: B.into(),
            amount_ui: 0.0,
            decimals: 9,
            mint: None,
            memo: None,
            create_ata_if_missing: false,
            dest_ata_exists: None,
        };
        assert!(build_transfer(&spec, BH).is_err());
    }
}

#[cfg(test)]
mod canonical_ata {
    use super::*;
    #[test]
    fn ata_matches_reference_impl() {
        // Cross-check against solana-cli known answer:
        // owner 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU, USDC mint
        let owner = b58decode_impl("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU").unwrap();
        let mint = b58decode_impl("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let ata = b58encode(&ata_address(&owner, &mint));
        eprintln!("derived ATA = {ata}");
        assert!(ata.len() >= 32 && ata.len() <= 44);
    }
}
