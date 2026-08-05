//! A ZeroClaw WIT tool plugin: `solana-verify`.
//!
//! Local, pure-compute verification an AI agent can trust without any network egress
//! (the `tool-plugin` WIT world grants no outbound HTTP). One tool, dispatched by an `op`
//! field:
//!   * `merkle_verify`   — fold a keccak-256 Merkle proof to an anchored root
//!                         (the exact TxODDS on-chain settlement primitive).
//!   * `ed25519_verify`  — verify a Solana ed25519 signature over a message.
//!   * `pubkey_decode`   — base58 Solana pubkey → 32 raw bytes (hex).
//!   * `pubkey_encode`   — 32 raw bytes (hex) → base58 pubkey.
//!
//! The pure core lives in [`verify`] with no wasm dependency, so it compiles and tests on
//! the host with a plain `cargo test`; the wasm component reuses the exact same logic.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod verify;

/// Shared, wasm-independent request handling so the host `cargo test` exercises the exact
/// dispatch the component runs. Input/Output are JSON strings.
pub mod handler {
    use crate::verify::*;
    use base64::Engine as _;
    use serde::Deserialize;
    use serde_json::{json, Value};

    #[derive(Deserialize)]
    struct ProofIn {
        hash: String,
        #[serde(default)]
        right: bool,
    }

    /// Default Solana mainnet RPC when the caller passes no `rpc_url` and config has none.
    pub const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

    /// Performs one Solana JSON-RPC call: `(url, method, params) -> result`. On the host it
    /// is a mock; in the wasm component it is a `waki` POST over `wasi:http`. Injecting it
    /// keeps every pure op testable and exercises the exact live dispatch under `cargo test`.
    pub type Fetcher<'a> = dyn Fn(&str, &str, Value) -> Result<Value, String> + 'a;

    /// Run one `solana-verify` op. Returns (output_json, ok). `ok` is false only for
    /// malformed input; a *valid-but-false* verdict (e.g. a forged proof) is a successful
    /// tool call that reports `"valid": false`. Only `merkle_verify_onchain` touches the
    /// network; the pure-compute ops ignore `fetch`.
    pub fn run(args: &str, fetch: &Fetcher) -> (String, bool) {
        let v: Value = match serde_json::from_str(args) {
            Ok(v) => v,
            Err(e) => return (err(&format!("invalid JSON args: {e}")), false),
        };
        let op = v.get("op").and_then(|o| o.as_str()).unwrap_or("");
        match op {
            "merkle_verify" => merkle(&v),
            "merkle_verify_onchain" => merkle_onchain(&v, fetch),
            "merkle_verify_batch" => merkle_batch(&v, fetch),
            "ed25519_verify" => ed25519(&v),
            "pubkey_decode" => pubkey_decode(&v),
            "pubkey_encode" => pubkey_encode(&v),
            "" => (err("missing 'op' (merkle_verify|merkle_verify_onchain|merkle_verify_batch|ed25519_verify|pubkey_decode|pubkey_encode)"), false),
            other => (err(&format!("unknown op '{other}'")), false),
        }
    }

    fn err(msg: &str) -> String {
        json!({ "ok": false, "error": msg }).to_string()
    }

    fn merkle(v: &Value) -> (String, bool) {
        let leaf = match field_hex32(v, "leaf") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let root = match field_hex32(v, "root") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let proof_val = v.get("proof").cloned().unwrap_or(json!([]));
        let nodes_in: Vec<ProofIn> = match serde_json::from_value(proof_val) {
            Ok(n) => n,
            Err(e) => return (err(&format!("bad proof array: {e}")), false),
        };
        let mut proof = Vec::with_capacity(nodes_in.len());
        for n in &nodes_in {
            match hex32(&n.hash) {
                Ok(h) => proof.push(ProofNode { hash: h, is_right_sibling: n.right }),
                Err(e) => return (err(&format!("bad proof node hash: {e}")), false),
            }
        }
        let valid = merkle_verify(leaf, &proof, root);
        (json!({
            "ok": true, "op": "merkle_verify", "valid": valid,
            "agent_verdict": if valid { "GREEN" } else { "RED" },
            "reason": if valid { "proof folds to the supplied root" } else { "proof does NOT fold to the supplied root — rejected" },
            "hash": "keccak256", "depth": proof.len(),
            "root": to_hex(&root),
        }).to_string(), true)
    }

    /// Parse the `proof` array of `{hash, right}` nodes shared by both merkle ops.
    fn parse_proof(v: &Value) -> Result<Vec<ProofNode>, String> {
        let proof_val = v.get("proof").cloned().unwrap_or(json!([]));
        let nodes_in: Vec<ProofIn> =
            serde_json::from_value(proof_val).map_err(|e| format!("bad proof array: {e}"))?;
        let mut proof = Vec::with_capacity(nodes_in.len());
        for n in &nodes_in {
            let h = hex32(&n.hash).map_err(|e| format!("bad proof node hash: {e}"))?;
            proof.push(ProofNode { hash: h, is_right_sibling: n.right });
        }
        Ok(proof)
    }

    /// Live variant of `merkle_verify`: instead of trusting a caller-supplied `root`, read
    /// the anchored root straight from chain. Fetches `getAccountInfo(account, base64)`,
    /// takes the 32 bytes at `offset` (default 0) as the root, and folds the proof against
    /// it. This closes the trust gap — the settlement root comes from the chain, not the
    /// prompt — so a prompt-injected "trust me, it's settled" cannot flip the verdict.
    /// Read a 32-byte anchored root from an account's data at `offset` over RPC. Shared by
    /// `merkle_verify_onchain` and `merkle_verify_batch`. Returns (root, slot, account, offset).
    fn read_onchain_root(v: &Value, fetch: &Fetcher) -> Result<([u8; 32], Option<u64>, String, usize), String> {
        let account = v.get("account").and_then(|x| x.as_str())
            .ok_or("missing 'account' (base58 pubkey holding the anchored root)")?
            .to_string();
        if b58_32(&account).is_err() {
            return Err("'account' must be a base58 32-byte Solana pubkey".into());
        }
        let offset = v.get("offset").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
        let rpc = v.get("rpc_url").and_then(|x| x.as_str()).unwrap_or(DEFAULT_RPC);
        let resp = fetch(rpc, "getAccountInfo", json!([account, {"encoding": "base64"}]))
            .map_err(|e| format!("RPC getAccountInfo failed: {e}"))?;
        let value = &resp["result"]["value"];
        if value.is_null() {
            return Err(format!("account {account} not found on chain"));
        }
        let b64 = value["data"][0].as_str()
            .ok_or("account data missing (expected base64 encoding)")?;
        let data = base64::engine::general_purpose::STANDARD.decode(b64)
            .map_err(|e| format!("account data is not valid base64: {e}"))?;
        if data.len() < offset + 32 {
            return Err(format!("account data too short: need 32 bytes at offset {offset}, have {}", data.len()));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[offset..offset + 32]);
        let slot = resp["result"]["context"]["slot"].as_u64();
        Ok((root, slot, account, offset))
    }

    fn merkle_onchain(v: &Value, fetch: &Fetcher) -> (String, bool) {
        let leaf = match field_hex32(v, "leaf") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let proof = match parse_proof(v) { Ok(p) => p, Err(e) => return (err(&e), false) };
        let (root, slot, account, offset) = match read_onchain_root(v, fetch) {
            Ok(x) => x,
            Err(e) => return (err(&e), false),
        };
        let valid = merkle_verify(leaf, &proof, root);
        (json!({
            "ok": true, "op": "merkle_verify_onchain", "valid": valid,
            "agent_verdict": if valid { "GREEN" } else { "RED" },
            "reason": if valid { "proof folds to the on-chain anchored root" } else { "proof does NOT fold to the on-chain root — rejected" },
            "hash": "keccak256", "depth": proof.len(),
            "account": account, "offset": offset, "slot": slot,
            "root": to_hex(&root), "source": "on-chain",
        }).to_string(), true)
    }

    /// Verify MANY settlement claims against ONE anchored root in a single call — the
    /// natural TxODDS operation: a batch of leaves each with its proof, folded against a
    /// root that is either supplied (`root`) or read once from chain (`account`/`offset`).
    /// One RPC read covers the whole batch; GREEN only if every claim folds.
    fn merkle_batch(v: &Value, fetch: &Fetcher) -> (String, bool) {
        let (root, slot, source) = if v.get("root").is_some() {
            match field_hex32(v, "root") { Ok(r) => (r, None, "supplied"), Err(e) => return (err(&e), false) }
        } else if v.get("account").is_some() {
            match read_onchain_root(v, fetch) { Ok((r, s, _, _)) => (r, s, "on-chain"), Err(e) => return (err(&e), false) }
        } else {
            return (err("provide either 'root' (32-byte hex) or 'account' (read the root from chain)"), false);
        };
        let items = match v.get("items").and_then(|x| x.as_array()) {
            Some(a) if !a.is_empty() => a,
            _ => return (err("missing non-empty 'items' array of {leaf, proof}"), false),
        };
        let mut results = Vec::with_capacity(items.len());
        let mut valid_count = 0usize;
        for (i, it) in items.iter().enumerate() {
            let leaf = match field_hex32(it, "leaf") { Ok(x) => x, Err(e) => return (err(&format!("items[{i}]: {e}")), false) };
            let proof = match parse_proof(it) { Ok(p) => p, Err(e) => return (err(&format!("items[{i}]: {e}")), false) };
            let valid = merkle_verify(leaf, &proof, root);
            if valid { valid_count += 1; }
            results.push(json!({ "index": i, "leaf": to_hex(&leaf), "valid": valid, "depth": proof.len() }));
        }
        let all = valid_count == items.len();
        (json!({
            "ok": true, "op": "merkle_verify_batch",
            "agent_verdict": if all { "GREEN" } else { "RED" },
            "reason": if all {
                format!("all {} claims fold to the anchored root", items.len())
            } else {
                format!("{} of {} claims do NOT fold to the anchored root — rejected", items.len() - valid_count, items.len())
            },
            "hash": "keccak256", "source": source, "slot": slot,
            "root": to_hex(&root), "count": items.len(), "valid_count": valid_count,
            "all_valid": all, "items": results,
        }).to_string(), true)
    }

    fn ed25519(v: &Value) -> (String, bool) {
        let pk = match field_pubkey(v, "pubkey") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let msg = match field_bytes(v, "message") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let sig_bytes = match field_bytes(v, "signature") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let sig: [u8; 64] = match sig_bytes.try_into() {
            Ok(s) => s,
            Err(_) => return (err("signature must be 64 bytes"), false),
        };
        let valid = ed25519_verify(&pk, &msg, &sig);
        (json!({ "ok": true, "op": "ed25519_verify", "valid": valid,
                 "agent_verdict": if valid { "GREEN" } else { "RED" },
                 "reason": if valid { "signature is valid for this pubkey and message" } else { "signature is INVALID — rejected" },
                 "pubkey": b58_encode(&pk) }).to_string(), true)
    }

    fn pubkey_decode(v: &Value) -> (String, bool) {
        let pk = match field_pubkey(v, "pubkey") { Ok(x) => x, Err(e) => return (err(&e), false) };
        (json!({ "ok": true, "op": "pubkey_decode", "bytes_hex": to_hex(&pk) }).to_string(), true)
    }

    fn pubkey_encode(v: &Value) -> (String, bool) {
        let b = match field_hex32(v, "bytes") { Ok(x) => x, Err(e) => return (err(&e), false) };
        (json!({ "ok": true, "op": "pubkey_encode", "pubkey": b58_encode(&b) }).to_string(), true)
    }

    // field extractors: accept hex ("0x.."/"..") or, for pubkeys, base58.
    fn field_hex32(v: &Value, k: &str) -> Result<[u8; 32], String> {
        let s = v.get(k).and_then(|x| x.as_str()).ok_or(format!("missing '{k}' (32-byte hex)"))?;
        hex32(s)
    }
    fn field_bytes(v: &Value, k: &str) -> Result<Vec<u8>, String> {
        let s = v.get(k).and_then(|x| x.as_str()).ok_or(format!("missing '{k}'"))?;
        from_hex(s)
    }
    fn field_pubkey(v: &Value, k: &str) -> Result<[u8; 32], String> {
        let s = v.get(k).and_then(|x| x.as_str()).ok_or(format!("missing '{k}' (base58 pubkey)"))?;
        // try base58 first (Solana pubkeys), then hex
        b58_32(s).or_else(|_| hex32(s))
    }

    pub const SCHEMA: &str = r#"{
      "type": "object",
      "properties": {
        "op": {"type": "string", "enum": ["merkle_verify","merkle_verify_onchain","merkle_verify_batch","ed25519_verify","pubkey_decode","pubkey_encode"],
               "description": "Which Solana check to run. merkle_verify_onchain/batch read the anchored root live from chain; merkle_verify_batch folds many claims against one root in a single call; the rest are local no-network."},
        "leaf": {"type": "string", "description": "merkle_verify[_onchain]: 32-byte leaf hash, hex."},
        "root": {"type": "string", "description": "merkle_verify / merkle_verify_batch: 32-byte anchored root, hex (batch may instead read it from chain via account)."},
        "account": {"type": "string", "description": "merkle_verify_onchain / merkle_verify_batch: base58 account holding the anchored root on chain."},
        "offset": {"type": "integer", "description": "merkle_verify_onchain / merkle_verify_batch: byte offset of the 32-byte root in the account data (default 0)."},
        "rpc_url": {"type": "string", "description": "on-chain ops: optional Solana RPC endpoint (defaults to mainnet-beta)."},
        "items": {"type": "array", "description": "merkle_verify_batch: claims to fold against the one root.",
                  "items": {"type": "object",
                    "properties": {"leaf": {"type": "string"},
                                   "proof": {"type": "array", "items": {"type": "object",
                                     "properties": {"hash": {"type": "string"}, "right": {"type": "boolean"}}, "required": ["hash"]}}},
                    "required": ["leaf"]}},
        "proof": {"type": "array", "description": "merkle_verify[_onchain]: sibling path.",
                  "items": {"type": "object",
                    "properties": {"hash": {"type": "string"}, "right": {"type": "boolean"}},
                    "required": ["hash"]}},
        "pubkey": {"type": "string", "description": "base58 Solana pubkey (or 32-byte hex)."},
        "message": {"type": "string", "description": "ed25519_verify: signed message, hex."},
        "signature": {"type": "string", "description": "ed25519_verify: 64-byte signature, hex."},
        "bytes": {"type": "string", "description": "pubkey_encode: 32 raw bytes, hex."}
      },
      "required": ["op"]
    }"#;

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A fetcher the pure-compute ops must never call. If a "local" op reaches the
        /// network this fails the test loudly instead of silently passing.
        fn unreachable_fetch(_u: &str, _m: &str, _p: Value) -> Result<Value, String> {
            panic!("pure-compute op must not touch the network");
        }

        #[test]
        fn dispatch_merkle_valid_and_forged() {
            let a = to_hex(&keccak256(b"leaf-a"));
            let b_raw = keccak256(b"leaf-b");
            let a_raw = keccak256(b"leaf-a");
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&a_raw);
            buf[32..].copy_from_slice(&b_raw);
            let root = to_hex(&keccak256(&buf));
            let args = json!({"op":"merkle_verify","leaf":a,"root":root,
                              "proof":[{"hash":to_hex(&b_raw),"right":true}]}).to_string();
            let (out, ok) = run(&args, &unreachable_fetch);
            assert!(ok);
            assert!(out.contains("\"valid\":true"));
            assert!(out.contains("\"agent_verdict\":\"GREEN\""), "a valid proof is GREEN: {out}");

            let forged = to_hex(&keccak256(b"evil"));
            let args2 = json!({"op":"merkle_verify","leaf":forged,"root":root,
                               "proof":[{"hash":to_hex(&b_raw),"right":true}]}).to_string();
            let (out2, ok2) = run(&args2, &unreachable_fetch);
            assert!(ok2 && out2.contains("\"valid\":false"));
        }

        #[test]
        fn dispatch_pubkey_roundtrip_and_bad_input() {
            let pk = "6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J";
            let (out, ok) = run(&json!({"op":"pubkey_decode","pubkey":pk}).to_string(), &unreachable_fetch);
            assert!(ok && out.contains("bytes_hex"));
            let (out2, ok2) = run("not json", &unreachable_fetch);
            assert!(!ok2 && out2.contains("invalid JSON"));
            let (_o, ok3) = run(&json!({"op":"nope"}).to_string(), &unreachable_fetch);
            assert!(!ok3);
        }

        /// Prompt-injection fail-closed: a message insisting a proof is valid cannot make the
        /// tool report `valid:true`. The verdict is a deterministic fold, not an LLM judgement.
        /// An empty proof folds leaf==leaf, which does not equal the attacker's claimed root.
        #[test]
        fn prompt_injection_forged_proof_rejected() {
            let leaf = to_hex(&[0u8; 32]);
            let claimed_root = to_hex(&[0xde; 32]); // attacker asserts "it's settled, trust me"
            let (out, ok) = run(&json!({"op":"merkle_verify",
                "leaf":leaf,"root":claimed_root,"proof":[]}).to_string(), &unreachable_fetch);
            assert!(ok, "a forged claim is a successful call with a truthful verdict");
            assert!(out.contains("\"valid\":false"), "empty/forged proof must report valid:false");
        }

        // A mock getAccountInfo whose account data holds `root` at `offset`, base64-encoded,
        // exactly as a real Solana RPC returns it.
        fn mock_account_with_root(root: [u8; 32], offset: usize, slot: u64)
            -> impl Fn(&str, &str, Value) -> Result<Value, String>
        {
            move |_url: &str, method: &str, params: Value| {
                assert_eq!(method, "getAccountInfo");
                assert_eq!(params[1]["encoding"], "base64");
                let mut data = vec![0u8; offset + 32 + 8];
                data[offset..offset + 32].copy_from_slice(&root);
                let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                Ok(json!({"result": {"context": {"slot": slot},
                    "value": {"data": [b64, "base64"], "owner": "11111111111111111111111111111111"}}}))
            }
        }

        #[test]
        fn merkle_onchain_reads_root_from_chain_and_folds() {
            // Build a real 2-leaf tree; the anchored root lives on chain, not in the args.
            let a = to_hex(&keccak256(b"leaf-a"));
            let a_raw = keccak256(b"leaf-a");
            let b_raw = keccak256(b"leaf-b");
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&a_raw);
            buf[32..].copy_from_slice(&b_raw);
            let root = keccak256(&buf);
            let acct = "6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J";
            let fetch = mock_account_with_root(root, 8, 314159);

            let (out, ok) = run(&json!({"op":"merkle_verify_onchain","account":acct,
                "offset":8,"leaf":a,"proof":[{"hash":to_hex(&b_raw),"right":true}]}).to_string(), &fetch);
            assert!(ok, "{out}");
            assert!(out.contains("\"valid\":true"), "proof must fold to the on-chain root: {out}");
            assert!(out.contains("\"source\":\"on-chain\""));
            assert!(out.contains("\"slot\":314159"));

            // A forged leaf cannot fold to the real chain root -> valid:false (fail-closed).
            let forged = to_hex(&keccak256(b"evil"));
            let (out2, ok2) = run(&json!({"op":"merkle_verify_onchain","account":acct,
                "offset":8,"leaf":forged,"proof":[{"hash":to_hex(&b_raw),"right":true}]}).to_string(), &fetch);
            assert!(ok2 && out2.contains("\"valid\":false"));
        }

        #[test]
        fn merkle_onchain_account_not_found_is_error() {
            let miss = |_u: &str, _m: &str, _p: Value|
                Ok(json!({"result": {"context": {"slot": 1}, "value": null}}));
            let acct = "6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J";
            let (out, ok) = run(&json!({"op":"merkle_verify_onchain","account":acct,
                "leaf":to_hex(&[0u8;32]),"proof":[]}).to_string(), &miss);
            assert!(!ok && out.contains("not found"));
        }

        #[test]
        fn merkle_onchain_rejects_bad_account() {
            let (out, ok) = run(&json!({"op":"merkle_verify_onchain","account":"not-base58!!",
                "leaf":to_hex(&[0u8;32]),"proof":[]}).to_string(), &unreachable_fetch);
            assert!(!ok && out.contains("base58"));
        }

        // Two leaves of the same 2-leaf tree, plus the shared root.
        fn two_leaf_tree() -> ([u8; 32], String, String, String, String) {
            let a_raw = keccak256(b"leaf-a");
            let b_raw = keccak256(b"leaf-b");
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&a_raw);
            buf[32..].copy_from_slice(&b_raw);
            let root = keccak256(&buf);
            (root, to_hex(&a_raw), to_hex(&b_raw), to_hex(&a_raw), to_hex(&b_raw))
        }

        #[test]
        fn merkle_batch_all_valid_is_green() {
            let (root, a, b, _, _) = two_leaf_tree();
            // Two claims: leaf a (sibling b on the right) and leaf b (sibling a on the left).
            let args = json!({"op":"merkle_verify_batch","root":to_hex(&root),"items":[
                {"leaf":a,"proof":[{"hash":b,"right":true}]},
                {"leaf":b,"proof":[{"hash":a,"right":false}]}
            ]}).to_string();
            let (out, ok) = run(&args, &unreachable_fetch);
            assert!(ok, "{out}");
            assert!(out.contains("\"all_valid\":true") && out.contains("\"valid_count\":2"));
            assert!(out.contains("\"agent_verdict\":\"GREEN\""), "{out}");
            assert!(out.contains("\"source\":\"supplied\""));
        }

        #[test]
        fn merkle_batch_one_forged_claim_is_red() {
            let (root, a, b, _, _) = two_leaf_tree();
            let forged = to_hex(&keccak256(b"evil"));
            let args = json!({"op":"merkle_verify_batch","root":to_hex(&root),"items":[
                {"leaf":a,"proof":[{"hash":b.clone(),"right":true}]},
                {"leaf":forged,"proof":[{"hash":b,"right":true}]}
            ]}).to_string();
            let (out, ok) = run(&args, &unreachable_fetch);
            assert!(ok, "{out}");
            assert!(out.contains("\"all_valid\":false") && out.contains("\"valid_count\":1"));
            assert!(out.contains("\"agent_verdict\":\"RED\""), "one bad claim rejects the batch: {out}");
        }

        #[test]
        fn merkle_batch_reads_root_from_chain() {
            let (root, a, b, _, _) = two_leaf_tree();
            let acct = "6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J";
            let fetch = mock_account_with_root(root, 8, 424242);
            let args = json!({"op":"merkle_verify_batch","account":acct,"offset":8,"items":[
                {"leaf":a,"proof":[{"hash":b,"right":true}]}
            ]}).to_string();
            let (out, ok) = run(&args, &fetch);
            assert!(ok, "{out}");
            assert!(out.contains("\"all_valid\":true") && out.contains("\"source\":\"on-chain\""));
            assert!(out.contains("\"slot\":424242"));
        }

        #[test]
        fn merkle_batch_requires_root_or_account() {
            let (_r, a, b, _, _) = two_leaf_tree();
            let (out, ok) = run(&json!({"op":"merkle_verify_batch","items":[
                {"leaf":a,"proof":[{"hash":b,"right":true}]}]}).to_string(), &unreachable_fetch);
            assert!(!ok && out.contains("either 'root'"));
        }

        #[test]
        fn merkle_batch_rejects_empty_items() {
            let (root, _a, _b, _, _) = two_leaf_tree();
            let (out, ok) = run(&json!({"op":"merkle_verify_batch","root":to_hex(&root),"items":[]}).to_string(), &unreachable_fetch);
            assert!(!ok && out.contains("non-empty 'items'"));
        }
    }
}

// ── the wasm component: reuses `handler` verbatim ───────────────────────────
#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::handler;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde_json::{json, Value};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaVerify;

    const PLUGIN_NAME: &str = "solana-verify";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    impl PluginInfo for SolanaVerify {
        fn plugin_name() -> String { PLUGIN_NAME.to_string() }
        fn plugin_version() -> String { PLUGIN_VERSION.to_string() }
    }

    /// One Solana JSON-RPC POST over wasi:http (TLS is performed host-side; this only
    /// runs after the `http_client` grant is validated by the host). Used solely by the
    /// `merkle_verify_onchain` op to read an anchored root; the other ops never call it.
    fn rpc_fetch(url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        let resp = waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(bytes)
            .send()
            .map_err(|e| format!("wasi:http send failed: {e}"))?;
        let raw = resp.body().map_err(|e| format!("read response body: {e}"))?;
        let v: Value = serde_json::from_slice(&raw).map_err(|e| format!("RPC returned non-JSON: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("RPC error: {err}"));
        }
        Ok(v)
    }

    impl Tool for SolanaVerify {
        fn name() -> String { "solana_verify".to_string() }

        fn description() -> String {
            "Solana verification for an AI agent. Ops: 'merkle_verify' folds a keccak-256 Merkle \
             proof to a supplied anchored root (e.g. a TxODDS on-chain settlement proof); \
             'merkle_verify_onchain' reads the anchored root LIVE from chain (getAccountInfo over \
             wasi:http) and folds the proof against real on-chain state, so a caller cannot fake the \
             root; 'ed25519_verify' checks a Solana signature over a message; \
             'pubkey_decode'/'pubkey_encode' convert base58 pubkeys to/from raw bytes. \
             Pass an 'op' plus its fields as JSON."
                .to_string()
        }

        fn parameters_schema() -> String { handler::SCHEMA.to_string() }

        fn execute(args: String) -> Result<ToolResult, String> {
            let (output, ok) = handler::run(&args, &rpc_fetch);
            emit(
                if ok { PluginAction::Complete } else { PluginAction::Fail },
                if ok { PluginOutcome::Success } else { PluginOutcome::Failure },
                "solana-verify",
            );
            Ok(ToolResult {
                success: ok,
                output,
                error: None,
            })
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_verify::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaVerify);
}
