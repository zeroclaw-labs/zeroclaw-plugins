//! Custody guard: nothing this package compiles can sign or broadcast.
//!
//! The claim this plugin rests on is that an agent holding it cannot move
//! funds. That property is easy to state and easy to lose by accident: one
//! dependency, one helper that takes a secret key, one extra RPC method, and
//! the guarantee is gone while every other test still passes. These tests turn
//! that regression red.
//!
//! They read what this package actually compiles, its own `src/` plus the
//! vendored `solana-core/src/`, and its resolved dependency graph. Nothing
//! outside the plugin directory is touched, which is also all the repository
//! validator copies into its build snapshot.
//!
//! The complementary positive assertion lives in the core's own suite:
//! `envelope_has_zero_signatures` decodes a built transaction and proves the
//! signature region is 64 zero bytes.

use std::fs;
use std::path::PathBuf;

/// Crate-name fragments that mean "this graph can produce a signature".
/// `curve25519-dalek` is deliberately not here: it does field arithmetic, which
/// is how `Pubkey::is_on_curve` separates an ed25519 address from a PDA, and it
/// carries no signing API.
const SIGNING_CRATE_FRAGMENTS: &[&str] = &[
    "ed25519",
    "solana-sdk",
    "solana-keypair",
    "solana-signer",
    "secp256k1",
    "signatory",
    "keypair",
    "keyring",
    "mnemonic",
    "bip32",
    "bip39",
    "slip10",
    "nacl",
    "sodium",
    "openssl",
];

/// Crate names too generic to match as fragments, so they match exactly.
const SIGNING_CRATE_NAMES: &[&str] = &[
    "ring",
    "signature",
    "k256",
    "p256",
    "hmac",
    "pbkdf2",
    "aes",
    "chacha20",
];

/// Spellings that only appear in code holding or deriving key material.
const KEY_MATERIAL_SPELLINGS: &[&str] = &[
    "Keypair",
    "SecretKey",
    "secret_key",
    "PrivateKey",
    "private_key",
    "SigningKey",
    "signing_key",
    "sign_message",
    "sign_transaction",
    "partial_sign",
    "try_sign",
    "ed25519_dalek",
    "seed_phrase",
    "from_seed",
];

/// The only JSON-RPC methods this package may send. Anything else, including a
/// method that merely simulates, has to be classified deliberately rather than
/// arrive with a diff.
const READ_ONLY_RPC_METHODS: &[&str] = &[
    "getAccountInfo",
    "getBalance",
    "getGenesisHash",
    "getLatestBlockhash",
    "getMinimumBalanceForRentExemption",
    "getSignatureStatuses",
    "getSignaturesForAddress",
    "getSlot",
    "getTransaction",
];

/// Methods that move value or ask someone else to. None may appear anywhere.
const VALUE_MOVING_RPC_METHODS: &[&str] = &[
    "sendTransaction",
    "sendRawTransaction",
    "sendBundle",
    "requestAirdrop",
    "signTransaction",
    "signAndSendTransaction",
];

fn plugin_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every Rust file this package compiles: its own sources and the vendored
/// core's, which is the whole surface a signing path could hide in.
fn compiled_sources() -> Vec<(PathBuf, String)> {
    let root = plugin_root();
    let mut sources = Vec::new();
    for dir in [root.join("src"), root.join("solana-core").join("src")] {
        let entries =
            fs::read_dir(&dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("cannot read directory entry").path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                let text = fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                sources.push((path, text));
            }
        }
    }
    assert!(
        sources.len() > 5,
        "expected the plugin sources and the vendored core, found {}",
        sources.len()
    );
    sources
}

/// Crate names in the resolved graph, read from the lockfile the validator
/// builds with (`cargo test --locked`).
fn locked_crate_names() -> Vec<String> {
    let lock = plugin_root().join("Cargo.lock");
    let text = fs::read_to_string(&lock).expect("Cargo.lock");
    text.lines()
        .filter_map(|line| line.strip_prefix("name = "))
        .map(|name| name.trim().trim_matches('"').to_string())
        .collect()
}

/// The method literal each `request_body` call sends. The definition site is
/// skipped: it names no method, it takes one.
fn rpc_methods_sent(source: &str) -> Vec<String> {
    let mut methods = Vec::new();
    for (at, hit) in source.match_indices("request_body(") {
        if source[..at].ends_with("fn ") {
            continue;
        }
        let rest = &source[at + hit.len()..];
        let open = rest.find('"').expect("request_body names a method literal");
        let tail = &rest[open + 1..];
        let close = tail.find('"').expect("unterminated method literal");
        methods.push(tail[..close].to_string());
    }
    methods
}

#[test]
fn the_dependency_graph_contains_no_signing_crate() {
    for name in locked_crate_names() {
        let lowered = name.to_lowercase();
        for fragment in SIGNING_CRATE_FRAGMENTS {
            assert!(
                !lowered.contains(fragment),
                "crate {name} matches '{fragment}': this package must not be able to sign"
            );
        }
        assert!(
            !SIGNING_CRATE_NAMES.contains(&lowered.as_str()),
            "crate {name} can sign: this package must not depend on it"
        );
    }
}

#[test]
fn no_compiled_source_names_key_material() {
    for (path, text) in compiled_sources() {
        for spelling in KEY_MATERIAL_SPELLINGS {
            assert!(
                !text.contains(spelling),
                "{} mentions {spelling}: this package accepts no key material",
                path.display()
            );
        }
    }
}

#[test]
fn only_read_only_rpc_methods_are_reachable() {
    let mut sent = Vec::new();
    for (path, text) in compiled_sources() {
        for method in VALUE_MOVING_RPC_METHODS {
            assert!(
                !text.contains(method),
                "{} names {method}: this package cannot broadcast",
                path.display()
            );
        }
        for method in rpc_methods_sent(&text) {
            assert!(
                READ_ONLY_RPC_METHODS.contains(&method.as_str()),
                "{} sends {method}, which is not on the read-only list",
                path.display()
            );
            sent.push(method);
        }
    }
    assert!(
        sent.iter().any(|m| m == "getAccountInfo"),
        "the account reads went missing, so this test stopped checking anything"
    );
}

/// Refuses the call and never reaches the network.
#[derive(Default)]
struct NoRpc {
    calls: usize,
}

impl spl_transfer_build::builder::Lookups for NoRpc {
    fn rpc(&mut self, _body: &str) -> Result<String, String> {
        self.calls += 1;
        Err("this test must never reach the network".into())
    }
}

#[test]
fn neither_arguments_nor_config_can_carry_a_key() {
    const RECIP: &str = "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN";
    let config = serde_json::json!({
        "rpc_url": "https://api.devnet.solana.com",
        "allow_recipients": RECIP,
        "caps": "SOL:0.1:9",
    });

    for key in ["secret_key", "private_key", "keypair", "signer", "sign"] {
        let mut args = serde_json::json!({
            "sender": "9B5XszUGdMaxCZ7uSQhPzdks5ZQSmWxrmzCSvtJ6Ns6g",
            "recipient": RECIP,
            "amount": "0.01",
            "__config": config,
        });
        args[key] = serde_json::json!("does not matter what this holds");
        let mut rpc = NoRpc::default();
        let err = spl_transfer_build::builder::run(&args.to_string(), &mut rpc)
            .expect_err("an argument this tool does not declare must be refused");
        assert!(
            matches!(err, spl_transfer_build::builder::BuildError::BadArgs(_)),
            "argument {key} was not refused as a bad argument: {err}"
        );
        assert_eq!(rpc.calls, 0, "refused after touching the network");

        let mut args = serde_json::json!({
            "sender": "9B5XszUGdMaxCZ7uSQhPzdks5ZQSmWxrmzCSvtJ6Ns6g",
            "recipient": RECIP,
            "amount": "0.01",
            "__config": config,
        });
        args["__config"][key] = serde_json::json!("does not matter what this holds");
        let mut rpc = NoRpc::default();
        let err = spl_transfer_build::builder::run(&args.to_string(), &mut rpc)
            .expect_err("a config key this tool does not declare must be refused");
        assert!(
            err.to_string().contains("unknown config key"),
            "config key {key} was not refused: {err}"
        );
        assert_eq!(rpc.calls, 0, "refused after touching the network");
    }
}
