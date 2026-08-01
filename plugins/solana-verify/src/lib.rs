//! A ZeroClaw WIT tool plugin: `solana-verify`.
//!
//! Offline, pure-compute verification an AI agent can trust without any network egress
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
    use serde::Deserialize;
    use serde_json::{json, Value};

    #[derive(Deserialize)]
    struct ProofIn {
        hash: String,
        #[serde(default)]
        right: bool,
    }

    /// Run one `solana-verify` op. Returns (output_json, ok). `ok` is false only for
    /// malformed input; a *valid-but-false* verdict (e.g. a forged proof) is a successful
    /// tool call that reports `"valid": false`.
    pub fn run(args: &str) -> (String, bool) {
        let v: Value = match serde_json::from_str(args) {
            Ok(v) => v,
            Err(e) => return (err(&format!("invalid JSON args: {e}")), false),
        };
        let op = v.get("op").and_then(|o| o.as_str()).unwrap_or("");
        match op {
            "merkle_verify" => merkle(&v),
            "ed25519_verify" => ed25519(&v),
            "pubkey_decode" => pubkey_decode(&v),
            "pubkey_encode" => pubkey_encode(&v),
            "" => (err("missing 'op' (merkle_verify|ed25519_verify|pubkey_decode|pubkey_encode)"), false),
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
            "hash": "keccak256", "depth": proof.len(),
            "root": to_hex(&root),
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
        "op": {"type": "string", "enum": ["merkle_verify","ed25519_verify","pubkey_decode","pubkey_encode"],
               "description": "Which offline Solana check to run."},
        "leaf": {"type": "string", "description": "merkle_verify: 32-byte leaf hash, hex."},
        "root": {"type": "string", "description": "merkle_verify: 32-byte anchored root, hex."},
        "proof": {"type": "array", "description": "merkle_verify: sibling path.",
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
            let (out, ok) = run(&args);
            assert!(ok);
            assert!(out.contains("\"valid\":true"));

            let forged = to_hex(&keccak256(b"evil"));
            let args2 = json!({"op":"merkle_verify","leaf":forged,"root":root,
                               "proof":[{"hash":to_hex(&b_raw),"right":true}]}).to_string();
            let (out2, ok2) = run(&args2);
            assert!(ok2 && out2.contains("\"valid\":false"));
        }

        #[test]
        fn dispatch_pubkey_roundtrip_and_bad_input() {
            let pk = "6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J";
            let (out, ok) = run(&json!({"op":"pubkey_decode","pubkey":pk}).to_string());
            assert!(ok && out.contains("bytes_hex"));
            let (out2, ok2) = run("not json");
            assert!(!ok2 && out2.contains("invalid JSON"));
            let (_o, ok3) = run(&json!({"op":"nope"}).to_string());
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
                "leaf":leaf,"root":claimed_root,"proof":[]}).to_string());
            assert!(ok, "a forged claim is a successful call with a truthful verdict");
            assert!(out.contains("\"valid\":false"), "empty/forged proof must report valid:false");
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

    impl Tool for SolanaVerify {
        fn name() -> String { "solana_verify".to_string() }

        fn description() -> String {
            "Offline Solana verification — no network needed. Ops: 'merkle_verify' folds a \
             keccak-256 Merkle proof to an anchored root (e.g. a TxODDS on-chain settlement \
             proof); 'ed25519_verify' checks a Solana signature over a message; \
             'pubkey_decode'/'pubkey_encode' convert base58 pubkeys to/from raw bytes. \
             Pass an 'op' plus its fields as JSON."
                .to_string()
        }

        fn parameters_schema() -> String { handler::SCHEMA.to_string() }

        fn execute(args: String) -> Result<ToolResult, String> {
            let (output, ok) = handler::run(&args);
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
