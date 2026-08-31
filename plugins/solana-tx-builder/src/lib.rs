//! A ZeroClaw WIT tool plugin: `solana-tx-builder`.
//!
//! The companion to `solana-verify`. Local, pure-compute construction of Solana
//! instructions and addresses an agent can build without any network egress; a human or
//! wallet signs and sends the result. Nothing here can move funds — it only produces the
//! bytes to sign. Dispatched by an `op` field:
//!   * `derive_pda`       — find_program_address(seeds, program) → (address, bump)
//!   * `derive_ata`       — associated token account for (owner, mint)
//!   * `system_transfer`  — a SystemProgram transfer instruction
//!   * `spl_transfer`     — an SPL-Token transfer instruction
//!
//! The pure core is in [`build`]; instructions come back as JSON (program id + accounts +
//! base64 data) ready to drop into a transaction.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod build;

pub mod handler {
    use crate::build::*;
    use serde_json::{json, Value};

    /// Default Solana mainnet RPC when the caller passes no `rpc_url` and config has none.
    pub const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

    /// Performs one Solana JSON-RPC call: `(url, method, params) -> result`. On the host it
    /// is a mock; in the wasm component it is a `waki` POST over `wasi:http`. Injecting it
    /// keeps the pure ops testable and exercises the exact live dispatch under `cargo test`.
    pub type Fetcher<'a> = dyn Fn(&str, &str, Value) -> Result<Value, String> + 'a;

    pub const SCHEMA: &str = r#"{
      "type": "object",
      "properties": {
        "op": {"type": "string", "enum": ["derive_pda","derive_ata","system_transfer","spl_transfer","prepare_transfer"],
               "description": "Which Solana construction to run. prepare_transfer reads a recent blockhash and checks the recipient live from chain; the rest are local no-network."},
        "program": {"type": "string", "description": "derive_pda: program id (base58)."},
        "seeds": {"type": "array", "items": {"type": "string"},
                  "description": "derive_pda: seeds, each 'utf8:...' or 'hex:...' (default utf8)."},
        "owner": {"type": "string", "description": "derive_ata: token account owner (base58)."},
        "mint": {"type": "string", "description": "derive_ata: SPL mint (base58)."},
        "from": {"type": "string", "description": "system_transfer/prepare_transfer: sender (base58)."},
        "to": {"type": "string", "description": "system_transfer/prepare_transfer: recipient (base58)."},
        "lamports": {"type": "integer", "description": "system_transfer/prepare_transfer: amount in lamports."},
        "source": {"type": "string", "description": "spl_transfer: source token account (base58)."},
        "dest": {"type": "string", "description": "spl_transfer: destination token account (base58)."},
        "authority": {"type": "string", "description": "spl_transfer: signing authority (base58)."},
        "amount": {"type": "integer", "description": "spl_transfer: token amount (base units)."},
        "rpc_url": {"type": "string", "description": "prepare_transfer: optional Solana RPC endpoint (defaults to mainnet-beta)."}
      },
      "required": ["op"]
    }"#;

    /// Only `prepare_transfer` touches the network; the pure construction ops ignore `fetch`.
    pub fn run(args: &str, fetch: &Fetcher) -> (String, bool) {
        let v: Value = match serde_json::from_str(args) {
            Ok(v) => v,
            Err(e) => return (err(&format!("invalid JSON args: {e}")), false),
        };
        match v.get("op").and_then(|o| o.as_str()).unwrap_or("") {
            "derive_pda" => derive_pda(&v),
            "derive_ata" => derive_ata(&v),
            "system_transfer" => system_transfer(&v),
            "spl_transfer" => spl_transfer(&v),
            "prepare_transfer" => prepare_transfer(&v, fetch),
            "" => (err("missing 'op' (derive_pda|derive_ata|system_transfer|spl_transfer|prepare_transfer)"), false),
            other => (err(&format!("unknown op '{other}'")), false),
        }
    }

    fn err(m: &str) -> String { json!({ "ok": false, "error": m }).to_string() }

    fn b58(s: &str) -> Result<[u8; 32], String> {
        bs58::decode(s).into_vec().map_err(|e| format!("bad base58: {e}"))?
            .try_into().map_err(|_| "expected a 32-byte pubkey".to_string())
    }
    fn b58s(s: &str) -> String { bs58::encode(s.as_bytes()).into_string() }
    fn pk(v: &Value, k: &str) -> Result<[u8; 32], String> {
        b58(v.get(k).and_then(|x| x.as_str()).ok_or(format!("missing '{k}' (base58)"))?)
    }
    fn u64f(v: &Value, k: &str) -> Result<u64, String> {
        v.get(k).and_then(|x| x.as_u64()).ok_or(format!("missing/invalid '{k}' (unsigned integer)"))
    }

    fn seed_bytes(s: &str) -> Result<Vec<u8>, String> {
        if let Some(h) = s.strip_prefix("hex:") {
            hex::decode(h).map_err(|e| format!("bad hex seed: {e}"))
        } else {
            Ok(s.strip_prefix("utf8:").unwrap_or(s).as_bytes().to_vec())
        }
    }

    fn ix_json(ix: &Instruction) -> Value {
        json!({
            "program_id": bs58::encode(ix.program_id).into_string(),
            "accounts": ix.accounts.iter().map(|a| json!({
                "pubkey": bs58::encode(a.pubkey).into_string(),
                "is_signer": a.is_signer, "is_writable": a.is_writable,
            })).collect::<Vec<_>>(),
            "data_base64": base64_encode(&ix.data),
            "data_hex": hex::encode(&ix.data),
        })
    }

    // tiny std-only base64 (no extra dep) — instruction data is short
    fn base64_encode(input: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            out.push(T[(b[0] >> 2) as usize] as char);
            out.push(T[(((b[0] & 3) << 4) | (b[1] >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 { T[(((b[1] & 15) << 2) | (b[2] >> 6)) as usize] as char } else { '=' });
            out.push(if chunk.len() > 2 { T[(b[2] & 63) as usize] as char } else { '=' });
        }
        out
    }

    fn derive_pda(v: &Value) -> (String, bool) {
        let program = match pk(v, "program") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let seeds_in: Vec<String> = v.get("seeds").and_then(|s| serde_json::from_value(s.clone()).ok())
            .unwrap_or_default();
        let mut owned = Vec::new();
        for s in &seeds_in {
            match seed_bytes(s) { Ok(b) => owned.push(b), Err(e) => return (err(&e), false) }
        }
        let refs: Vec<&[u8]> = owned.iter().map(|b| b.as_slice()).collect();
        let (addr, bump) = find_program_address(&refs, &program);
        (json!({ "ok": true, "op": "derive_pda",
                 "agent_verdict": "GREEN", "reason": "derived a program address (pure computation, no wallet action)",
                 "address": bs58::encode(addr).into_string(), "bump": bump }).to_string(), true)
    }

    fn derive_ata(v: &Value) -> (String, bool) {
        let owner = match pk(v, "owner") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let mint = match pk(v, "mint") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let tok = b58(TOKEN_PROGRAM).unwrap();
        let ata_prog = b58(ASSOCIATED_TOKEN_PROGRAM).unwrap();
        let (ata, bump) = associated_token_address(&owner, &mint, &tok, &ata_prog);
        (json!({ "ok": true, "op": "derive_ata",
                 "agent_verdict": "GREEN", "reason": "derived an associated token account address (pure computation, no wallet action)",
                 "address": bs58::encode(ata).into_string(), "bump": bump,
                 "token_program": TOKEN_PROGRAM }).to_string(), true)
    }

    fn system_transfer(v: &Value) -> (String, bool) {
        let from = match pk(v, "from") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let to = match pk(v, "to") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let lamports = match u64f(v, "lamports") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let ix = system_transfer_ix(from, to, lamports, b58(SYSTEM_PROGRAM).unwrap());
        (json!({ "ok": true, "op": "system_transfer",
                 "agent_verdict": "GREEN", "reason": "built a SOL-transfer instruction for a wallet to approve; nothing here can move funds",
                 "instruction": ix_json(&ix) }).to_string(), true)
    }

    fn spl_transfer(v: &Value) -> (String, bool) {
        let source = match pk(v, "source") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let dest = match pk(v, "dest") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let authority = match pk(v, "authority") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let amount = match u64f(v, "amount") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let ix = spl_transfer_ix(source, dest, authority, amount, b58(TOKEN_PROGRAM).unwrap());
        (json!({ "ok": true, "op": "spl_transfer",
                 "agent_verdict": "GREEN", "reason": "built an SPL-token transfer instruction for a wallet to approve",
                 "instruction": ix_json(&ix) }).to_string(), true)
    }

    /// Live variant of `system_transfer`: builds the same unsigned SOL-transfer instruction,
    /// then reads the chain so the result is broadcast-ready and typo-safe — a recent
    /// blockhash (required to submit) and whether the recipient actually exists on chain
    /// (a non-existent recipient is the classic address-typo / burn footgun). It still only
    /// returns bytes to sign: no signing, no sending — those capabilities do not exist here.
    fn prepare_transfer(v: &Value, fetch: &Fetcher) -> (String, bool) {
        let from = match pk(v, "from") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let to = match pk(v, "to") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let lamports = match u64f(v, "lamports") { Ok(x) => x, Err(e) => return (err(&e), false) };
        let to_b58 = v.get("to").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let rpc = v.get("rpc_url").and_then(|x| x.as_str()).unwrap_or(DEFAULT_RPC);

        let ix = system_transfer_ix(from, to, lamports, b58(SYSTEM_PROGRAM).unwrap());

        // recent blockhash — required to broadcast; without it the tx cannot be submitted.
        let bh_resp = match fetch(rpc, "getLatestBlockhash", json!([{"commitment": "finalized"}])) {
            Ok(r) => r,
            Err(e) => return (err(&format!("RPC getLatestBlockhash failed: {e}")), false),
        };
        let blockhash = bh_resp["result"]["value"]["blockhash"].as_str().map(|s| s.to_string());
        let last_valid = bh_resp["result"]["value"]["lastValidBlockHeight"].as_u64();
        if blockhash.is_none() {
            return (err("RPC returned no blockhash"), false);
        }

        // recipient existence — a transfer to a non-existent account is almost always a typo.
        let acct = fetch(rpc, "getAccountInfo", json!([to_b58, {"encoding": "base64"}]));
        let (recipient_exists, recipient_lamports) = match acct {
            Ok(r) => {
                let val = &r["result"]["value"];
                (Some(!val.is_null()), val["lamports"].as_u64())
            }
            Err(_) => (None, None), // couldn't check — report unknown rather than fabricate
        };

        let (verdict, reason) = match recipient_exists {
            Some(false) => ("AMBER", "built the transfer, BUT the recipient does not exist on chain — verify the address before approving"),
            _ => ("GREEN", "built a broadcast-ready transfer with a recent blockhash for a wallet to approve"),
        };
        (json!({
            "ok": true, "op": "prepare_transfer",
            "agent_verdict": verdict, "reason": reason,
            "instruction": ix_json(&ix),
            "recent_blockhash": blockhash,
            "last_valid_block_height": last_valid,
            "recipient_exists": recipient_exists,
            "recipient_lamports": recipient_lamports,
            "warning": match recipient_exists {
                Some(false) => Some("recipient account not found on chain — verify the address before approving this transfer"),
                _ => None,
            },
        }).to_string(), true)
    }

    // keep the helper referenced (used by tests indirectly / future ops)
    #[allow(dead_code)]
    fn _touch() { let _ = b58s("x"); }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A fetcher the pure construction ops must never call. If a "local" op reaches the
        /// network this fails the test loudly instead of silently passing.
        fn unreachable_fetch(_u: &str, _m: &str, _p: Value) -> Result<Value, String> {
            panic!("pure-compute op must not touch the network");
        }

        #[test]
        fn system_transfer_dispatch() {
            let (out, ok) = run(&json!({"op":"system_transfer",
                "from":"11111111111111111111111111111112",
                "to":"11111111111111111111111111111113","lamports":1000000}).to_string(), &unreachable_fetch);
            assert!(ok && out.contains("instruction") && out.contains("data_base64"));
        }

        #[test]
        fn derive_pda_dispatch() {
            let (out, ok) = run(&json!({"op":"derive_pda",
                "program":"6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J",
                "seeds":["utf8:daily_scores_roots","hex:d700"]}).to_string(), &unreachable_fetch);
            assert!(ok && out.contains("address") && out.contains("bump"));
        }

        #[test]
        fn bad_input_is_reported() {
            assert!(!run("nope", &unreachable_fetch).1);
            assert!(!run(&json!({"op":"system_transfer","from":"x"}).to_string(), &unreachable_fetch).1);
            assert!(!run(&json!({"op":"zzz"}).to_string(), &unreachable_fetch).1);
        }

        /// Prompt-injection fail-closed: a malicious "drain everything, skip confirmation"
        /// request can, at most, produce an UNSIGNED instruction. The tool never signs and
        /// never broadcasts — no such capability exists in the component.
        #[test]
        fn prompt_injection_cannot_sign_or_send() {
            let (out, ok) = run(&json!({"op":"system_transfer",
                "from":"11111111111111111111111111111112",
                "to":"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PB5tsN",
                "lamports":999999999u64}).to_string(), &unreachable_fetch);
            // It builds the bytes (that's its T1 job) ...
            assert!(ok && out.contains("instruction"), "should build the unsigned instruction");
            // ... but the payer is marked is_signer:true — a signature the plugin cannot supply ...
            assert!(out.contains("\"is_signer\":true"), "payer must still require an external signature");
            // ... and nothing in the output is a signature, a secret, or a broadcast result.
            for forbidden in ["signature", "signed", "secret", "keypair", "private", "txid", "submitted", "sent"] {
                assert!(!out.to_lowercase().contains(forbidden),
                    "output must never contain '{forbidden}' — the plugin cannot sign or send");
            }
        }

        // A mock RPC for prepare_transfer: a fixed blockhash and a recipient that either
        // exists (with lamports) or not, exactly as getLatestBlockhash/getAccountInfo return.
        fn mock_rpc(recipient_exists: bool) -> impl Fn(&str, &str, Value) -> Result<Value, String> {
            move |_url: &str, method: &str, _params: Value| match method {
                "getLatestBlockhash" => Ok(json!({"result": {"context": {"slot": 100},
                    "value": {"blockhash": "9zX8...MockBlockhashForTest", "lastValidBlockHeight": 123456}}})),
                "getAccountInfo" => Ok(json!({"result": {"context": {"slot": 100},
                    "value": if recipient_exists {
                        json!({"lamports": 2_039_280u64, "data": ["", "base64"], "owner": "11111111111111111111111111111111"})
                    } else { Value::Null }}})),
                other => Err(format!("unexpected method {other}")),
            }
        }

        #[test]
        fn prepare_transfer_adds_blockhash_and_recipient_check() {
            let args = json!({"op":"prepare_transfer",
                "from":"11111111111111111111111111111112",
                "to":"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PB5tsN","lamports":1_000_000}).to_string();

            // recipient exists -> broadcast-ready, no warning.
            let (out, ok) = run(&args, &mock_rpc(true));
            assert!(ok, "{out}");
            assert!(out.contains("instruction") && out.contains("recent_blockhash"));
            assert!(out.contains("\"recipient_exists\":true"));
            assert!(out.contains("MockBlockhashForTest"));

            // recipient missing -> still builds, but flags the typo footgun.
            let (out2, ok2) = run(&args, &mock_rpc(false));
            assert!(ok2 && out2.contains("\"recipient_exists\":false"));
            assert!(out2.contains("warning") && out2.contains("not found on chain"));
        }

        /// Prepare-transfer keeps the same fail-closed invariant: even live, it only returns
        /// bytes to sign — never a signature, secret, or broadcast result.
        #[test]
        fn prepare_transfer_still_cannot_sign_or_send() {
            let (out, ok) = run(&json!({"op":"prepare_transfer",
                "from":"11111111111111111111111111111112",
                "to":"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PB5tsN","lamports":999999999u64}).to_string(),
                &mock_rpc(true));
            assert!(ok && out.contains("instruction") && out.contains("\"is_signer\":true"));
            for forbidden in ["signature", "signed", "secret", "keypair", "private", "txid", "submitted", "sent"] {
                assert!(!out.to_lowercase().contains(forbidden),
                    "output must never contain '{forbidden}' — the plugin cannot sign or send");
            }
        }
    }
}

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
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct TxBuilder;
    const PLUGIN_NAME: &str = "solana-tx-builder";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    impl PluginInfo for TxBuilder {
        fn plugin_name() -> String { PLUGIN_NAME.to_string() }
        fn plugin_version() -> String { PLUGIN_VERSION.to_string() }
    }

    /// One Solana JSON-RPC POST over wasi:http (TLS host-side; runs only after the
    /// `http_client` grant is validated). Used solely by the `prepare_transfer` op.
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

    impl Tool for TxBuilder {
        fn name() -> String { "solana_tx_builder".to_string() }
        fn description() -> String {
            "Solana instruction & address construction for an AI agent. Ops: \
             'derive_pda' (find_program_address), 'derive_ata' (associated token account), \
             'system_transfer' (a SOL transfer instruction), 'spl_transfer' (an SPL-Token \
             transfer instruction), and 'prepare_transfer' which additionally reads a recent \
             blockhash and checks the recipient exists LIVE from chain (wasi:http) so the \
             transfer is broadcast-ready and typo-safe. Returns the program id, accounts, and \
             instruction data (base64/hex) for a wallet to sign — it never signs or sends. \
             Pass an 'op' plus its fields as JSON."
                .to_string()
        }
        fn parameters_schema() -> String { handler::SCHEMA.to_string() }
        fn execute(args: String) -> Result<ToolResult, String> {
            let (output, ok) = handler::run(&args, &rpc_fetch);
            emit(if ok { PluginAction::Complete } else { PluginAction::Fail },
                 if ok { PluginOutcome::Success } else { PluginOutcome::Failure });
            Ok(ToolResult { success: ok, output, error: None })
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome) {
        log_record(LogLevel::Info, &PluginEvent {
            function_name: "solana_tx_builder::tool::execute".to_string(),
            action, outcome: Some(outcome), duration_ms: None, attrs: None,
            message: "solana-tx-builder".to_string(),
        });
    }

    export!(TxBuilder);
}
