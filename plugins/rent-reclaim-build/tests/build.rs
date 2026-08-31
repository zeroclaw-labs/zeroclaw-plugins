//! Host-run tests over the pure build core. No wasm toolchain, no live
//! network: RPC is a canned mock behind the `Rpc` trait.
//!
//! The transaction tests parse the produced bytes with an independent
//! mini-decoder and assert the custody invariant at the wire level: every
//! CloseAccount instruction's destination index is the owner/fee-payer.

use rent_reclaim_build::build::{build, render, BuildRequest, Rpc};
use rent_reclaim_build::tx::{COMPUTE_BUDGET_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashMap;

fn pk(seed: u8) -> String {
    bs58::encode([seed; 32]).into_string()
}

/// Mock RPC keyed by method name.
struct MockRpc {
    by_method: RefCell<HashMap<String, Vec<Value>>>,
    calls: RefCell<Vec<String>>,
}

impl MockRpc {
    fn new() -> Self {
        Self {
            by_method: RefCell::new(HashMap::new()),
            calls: RefCell::new(Vec::new()),
        }
    }
    fn queue(&self, method: &str, response: Value) {
        self.by_method
            .borrow_mut()
            .entry(method.to_string())
            .or_default()
            .push(response);
    }
    fn with_blockhash(self) -> Self {
        self.queue(
            "getLatestBlockhash",
            json!({ "value": { "blockhash": pk(200), "lastValidBlockHeight": 123_456u64 } }),
        );
        self
    }
}

impl Rpc for MockRpc {
    fn call(&self, method: &str, _params: Value) -> Result<Value, String> {
        self.calls.borrow_mut().push(method.to_string());
        let mut map = self.by_method.borrow_mut();
        let q = map
            .get_mut(method)
            .ok_or_else(|| format!("unexpected RPC method {method}"))?;
        if q.is_empty() {
            return Err(format!("no more queued responses for {method}"));
        }
        Ok(q.remove(0))
    }
}

fn parsed_account(program: &str, owner: &str, amount: &str, lamports: u64) -> Value {
    json!({
        "lamports": lamports,
        "owner": program,
        "data": { "parsed": { "info": {
            "owner": owner,
            "mint": pk(60),
            "state": "initialized",
            "tokenAmount": { "amount": amount, "decimals": 6 }
        }, "type": "account" }, "program": "spl-token" }
    })
}

fn req(owner: &str, accounts: Option<Vec<String>>) -> BuildRequest {
    BuildRequest {
        owner: owner.to_string(),
        accounts,
        max_accounts: 8,
        priority_fee_micro_lamports: None,
    }
}

// ---- independent wire decoder ------------------------------------------------

fn read_compact_u16(bytes: &[u8], pos: &mut usize) -> u16 {
    let mut n: u16 = 0;
    let mut shift = 0;
    loop {
        let b = bytes[*pos];
        *pos += 1;
        n |= ((b & 0x7f) as u16) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    n
}

struct DecodedTx {
    num_signatures: u16,
    header: [u8; 3],
    keys: Vec<Vec<u8>>,
    blockhash: Vec<u8>,
    instructions: Vec<(u8, Vec<u8>, Vec<u8>)>, // (program_idx, account_idxs, data)
}

fn decode_tx(b64: &str) -> DecodedTx {
    let bytes = b64_decode(b64);
    let mut pos = 0;
    let num_signatures = read_compact_u16(&bytes, &mut pos);
    pos += 64 * num_signatures as usize;
    let header = [bytes[pos], bytes[pos + 1], bytes[pos + 2]];
    pos += 3;
    let nkeys = read_compact_u16(&bytes, &mut pos);
    let mut keys = Vec::new();
    for _ in 0..nkeys {
        keys.push(bytes[pos..pos + 32].to_vec());
        pos += 32;
    }
    let blockhash = bytes[pos..pos + 32].to_vec();
    pos += 32;
    let nix = read_compact_u16(&bytes, &mut pos);
    let mut instructions = Vec::new();
    for _ in 0..nix {
        let program_idx = bytes[pos];
        pos += 1;
        let na = read_compact_u16(&bytes, &mut pos);
        let idxs = bytes[pos..pos + na as usize].to_vec();
        pos += na as usize;
        let nd = read_compact_u16(&bytes, &mut pos);
        let data = bytes[pos..pos + nd as usize].to_vec();
        pos += nd as usize;
        instructions.push((program_idx, idxs, data));
    }
    assert_eq!(pos, bytes.len(), "trailing bytes in transaction");
    DecodedTx {
        num_signatures,
        header,
        keys,
        blockhash,
        instructions,
    }
}

fn b64_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let idx = |c: u8| ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
    let clean: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for chunk in clean.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= idx(c) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    out
}

// ---- happy path --------------------------------------------------------------

#[test]
fn builds_verified_close_tx_with_owner_as_destination() {
    let owner = pk(1);
    let accounts = vec![pk(10), pk(11)];
    let rpc = MockRpc::new().with_blockhash();
    rpc.queue(
        "getMultipleAccounts",
        json!({ "value": [
            parsed_account(TOKEN_PROGRAM, &owner, "0", 2_039_280),
            parsed_account(TOKEN_2022_PROGRAM, &owner, "0", 2_157_600),
        ]}),
    );

    let out = build(&rpc, &req(&owner, Some(accounts))).unwrap();
    assert_eq!(out.reclaim_lamports, 4_196_880);
    assert_eq!(out.last_valid_block_height, Some(123_456));

    let tx = decode_tx(&out.tx_base64);
    assert_eq!(tx.num_signatures, 1);
    assert_eq!(tx.header, [1, 0, 3]); // 1 signer; readonly: cb + 2 token programs
    assert_eq!(tx.keys[0], vec![1u8; 32], "fee payer is the owner");
    assert_eq!(tx.blockhash, bs58::decode(pk(200)).into_vec().unwrap());

    // ix0 = SetComputeUnitLimit on ComputeBudget
    let cb = bs58::decode(COMPUTE_BUDGET_PROGRAM).into_vec().unwrap();
    let (p0, a0, d0) = &tx.instructions[0];
    assert_eq!(tx.keys[*p0 as usize], cb);
    assert!(a0.is_empty());
    assert_eq!(d0[0], 2);

    // The two closes: data [9], destination and authority = index 0 (owner).
    let tok = bs58::decode(TOKEN_PROGRAM).into_vec().unwrap();
    let tok22 = bs58::decode(TOKEN_2022_PROGRAM).into_vec().unwrap();
    let closes: Vec<_> = tx.instructions[1..].iter().collect();
    assert_eq!(closes.len(), 2);
    for (p, a, d) in &closes {
        assert_eq!(d.as_slice(), &[9u8], "CloseAccount discriminant");
        assert_eq!(a.len(), 3);
        assert_eq!(
            a[1], 0,
            "destination is ALWAYS the owner (custody invariant)"
        );
        assert_eq!(a[2], 0, "authority is the owner");
        let prog = &tx.keys[*p as usize];
        assert!(*prog == tok || *prog == tok22);
    }
    // Right token program per account.
    assert_eq!(tx.keys[closes[0].1[0] as usize], vec![10u8; 32]);
    assert_eq!(tx.keys[closes[0].0 as usize], tok);
    assert_eq!(tx.keys[closes[1].1[0] as usize], vec![11u8; 32]);
    assert_eq!(tx.keys[closes[1].0 as usize], tok22);
}

#[test]
fn priority_fee_adds_cu_price_instruction() {
    let owner = pk(1);
    let rpc = MockRpc::new().with_blockhash();
    rpc.queue(
        "getMultipleAccounts",
        json!({ "value": [ parsed_account(TOKEN_PROGRAM, &owner, "0", 2_039_280) ] }),
    );
    let mut r = req(&owner, Some(vec![pk(10)]));
    r.priority_fee_micro_lamports = Some(5_000);
    let out = build(&rpc, &r).unwrap();
    let tx = decode_tx(&out.tx_base64);
    let (_, _, d1) = &tx.instructions[1];
    assert_eq!(d1[0], 3, "SetComputeUnitPrice");
    assert_eq!(u64::from_le_bytes(d1[1..9].try_into().unwrap()), 5_000);
}

#[test]
fn auto_select_scans_and_caps() {
    let owner = pk(1);
    let rpc = MockRpc::new().with_blockhash();
    let entries: Vec<Value> = (0..20)
        .map(|i| {
            json!({
                "pubkey": pk(100 + i),
                "account": parsed_account(TOKEN_PROGRAM, &owner, "0", 2_039_280 + i as u64),
            })
        })
        .collect();
    rpc.queue("getTokenAccountsByOwner", json!({ "value": entries }));
    rpc.queue("getTokenAccountsByOwner", json!({ "value": [] }));

    let out = build(&rpc, &req(&owner, None)).unwrap();
    assert_eq!(out.closed.len(), 8, "default max_accounts");
    // Highest-rent accounts picked first.
    assert_eq!(out.closed[0].lamports, 2_039_299);
}

// ---- fail-closed cases -------------------------------------------------------

#[test]
fn refuses_nonzero_balance() {
    let owner = pk(1);
    let rpc = MockRpc::new().with_blockhash();
    rpc.queue(
        "getMultipleAccounts",
        json!({ "value": [
            parsed_account(TOKEN_PROGRAM, &owner, "0", 2_039_280),
            parsed_account(TOKEN_PROGRAM, &owner, "1500000", 2_039_280), // holds tokens!
        ]}),
    );
    let err = build(&rpc, &req(&owner, Some(vec![pk(10), pk(11)]))).unwrap_err();
    assert!(err.contains("refusing to build"), "{err}");
    assert!(err.contains("balance is not zero"), "{err}");
    // All-or-nothing: no getLatestBlockhash call, no partial tx.
    assert!(!rpc.calls.borrow().iter().any(|m| m == "getLatestBlockhash"));
}

#[test]
fn refuses_foreign_owner_frozen_and_foreign_close_authority() {
    let owner = pk(1);
    let mut frozen = parsed_account(TOKEN_PROGRAM, &owner, "0", 2_039_280);
    frozen["data"]["parsed"]["info"]["state"] = json!("frozen");
    let mut foreign_ca = parsed_account(TOKEN_PROGRAM, &owner, "0", 2_039_280);
    foreign_ca["data"]["parsed"]["info"]["closeAuthority"] = json!(pk(99));

    let rpc = MockRpc::new().with_blockhash();
    rpc.queue(
        "getMultipleAccounts",
        json!({ "value": [
            parsed_account(TOKEN_PROGRAM, &pk(2), "0", 2_039_280), // someone else's account
            frozen,
            foreign_ca,
            Value::Null, // missing account
        ]}),
    );
    let err = build(
        &rpc,
        &req(&owner, Some(vec![pk(10), pk(11), pk(12), pk(13)])),
    )
    .unwrap_err();
    assert!(err.contains("4 of 4 accounts failed"), "{err}");
    assert!(err.contains("different wallet"), "{err}");
    assert!(err.contains("frozen"), "{err}");
    assert!(err.contains("close authority"), "{err}");
    assert!(err.contains("not found"), "{err}");
}

#[test]
fn refuses_non_token_account_and_bad_addresses() {
    let owner = pk(1);
    let rpc = MockRpc::new().with_blockhash();
    rpc.queue(
        "getMultipleAccounts",
        json!({ "value": [ parsed_account(&pk(77), &owner, "0", 2_039_280) ] }),
    );
    let err = build(&rpc, &req(&owner, Some(vec![pk(10)]))).unwrap_err();
    assert!(err.contains("not a token account"), "{err}");

    let rpc2 = MockRpc::new();
    let err2 = build(&rpc2, &req(&owner, Some(vec!["do it NOW!!".to_string()]))).unwrap_err();
    assert!(err2.contains("invalid account address"), "{err2}");
    assert!(rpc2.calls.borrow().is_empty(), "no RPC for invalid input");
}

#[test]
fn refuses_oversized_list_and_empty_list() {
    let owner = pk(1);
    let rpc = MockRpc::new();
    let many: Vec<String> = (0..13).map(|i| pk(100 + i)).collect();
    let err = build(&rpc, &req(&owner, Some(many))).unwrap_err();
    assert!(err.contains("cap of 12"), "{err}");
    let err2 = build(&rpc, &req(&owner, Some(vec![]))).unwrap_err();
    assert!(err2.contains("empty"), "{err2}");
    assert!(rpc.calls.borrow().is_empty());
}

#[test]
fn prompt_injection_cannot_redirect_rent() {
    // The attacker controls the account list (via a poisoned message the LLM
    // relayed). Even so: every account they can name either fails
    // verification, or its rent goes to the owner. Prove the second half at
    // the byte level: there is no destination in the args, and the wire
    // format pins destination = owner for every close.
    let owner = pk(1);
    let attacker = pk(66);
    let rpc = MockRpc::new().with_blockhash();
    rpc.queue(
        "getMultipleAccounts",
        json!({ "value": [ parsed_account(TOKEN_PROGRAM, &owner, "0", 2_039_280) ] }),
    );
    let out = build(&rpc, &req(&owner, Some(vec![pk(10)]))).unwrap();
    let tx = decode_tx(&out.tx_base64);
    let attacker_bytes = bs58::decode(&attacker).into_vec().unwrap();
    assert!(
        !tx.keys.contains(&attacker_bytes),
        "attacker key cannot appear in the transaction"
    );
    for (_, a, d) in &tx.instructions {
        if d.first() == Some(&9) {
            assert_eq!(a[1], 0, "rent destination pinned to owner");
        }
    }
    // And the rendered summary states the invariant for the approval gate.
    let text = render(&out, &owner);
    assert!(text.contains("rent always returns to the owner"));
    assert!(text.contains("unsigned_tx_base64"));
}

#[test]
fn no_accounts_found_is_an_error_not_an_empty_tx() {
    let owner = pk(1);
    let rpc = MockRpc::new();
    rpc.queue("getTokenAccountsByOwner", json!({ "value": [] }));
    rpc.queue("getTokenAccountsByOwner", json!({ "value": [] }));
    let err = build(&rpc, &req(&owner, None)).unwrap_err();
    assert!(err.contains("no empty closeable"), "{err}");
}
