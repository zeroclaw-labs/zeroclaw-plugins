//! Host-run tests over the pure resolve core against a mock RPC — no wasm
//! toolchain, no live network.

use std::collections::HashMap;

use serde_json::{json, Value};
use sns_resolve::resolve::{resolve_domain, ResolveConfig};
use zeroclaw_solana_core::pubkey::Pubkey;
use zeroclaw_solana_core::rpc::HttpTransport;
use zeroclaw_solana_core::sns::{derive_domain_key, name_program, NAME_HEADER_LEN};

/// Mock node: serves the registry account for `bonfida` owned by a known key.
struct MockRpc {
    account: Option<(Pubkey, Vec<u8>)>,
}

impl MockRpc {
    fn empty() -> Self {
        Self { account: None }
    }

    fn with_registry(owner: [u8; 32]) -> Self {
        let mut data = vec![0u8; NAME_HEADER_LEN];
        data[32..64].copy_from_slice(&owner);
        Self {
            account: Some((name_program(), data)),
        }
    }

    fn with_account(owner_program: Pubkey, data: Vec<u8>) -> Self {
        Self {
            account: Some((owner_program, data)),
        }
    }
}

impl HttpTransport for MockRpc {
    fn post_json(&self, _url: &str, body: &str) -> Result<String, String> {
        let req: Value = serde_json::from_str(body).unwrap();
        assert_eq!(req["method"], "getAccountInfo");
        let value = match &self.account {
            Some((owner, data)) => json!({
                "owner": owner.to_base58(),
                "data": [zeroclaw_solana_core::encoding::to_base64(data), "base64"],
                "lamports": 1_000_000u64
            }),
            None => Value::Null,
        };
        Ok(
            json!({"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": value}})
                .to_string(),
        )
    }
}

fn cfg() -> ResolveConfig {
    ResolveConfig::from_section(&HashMap::new())
}

#[test]
fn resolves_a_registered_domain_to_its_owner() {
    let owner = [9u8; 32];
    let rpc = MockRpc::with_registry(owner);
    let res = resolve_domain(&rpc, "bonfida.sol", &cfg()).unwrap();
    assert_eq!(res.domain, "bonfida.sol");
    assert_eq!(res.owner, Pubkey(owner).to_base58());
    // Non-circular anchor: the registry PDA the resolver derived must equal the
    // real on-chain bonfida.sol key, not merely "derive == derive".
    assert_eq!(res.registry, "Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb");
    assert!(res.text.contains("bonfida.sol →"));
    assert!(res.text.contains(&res.owner)); // full owner address is in the text
    assert!(res.text.len() < 400); // bounded output (address + explorer link)
    assert!(res.text.contains("solscan.io/account/"));
}

#[test]
fn derivation_matches_the_canonical_onchain_bonfida_key() {
    // The derivation itself, isolated from the RPC path: pins the algorithm to
    // a value observed on mainnet, so any drift fails inside the plugin's own
    // `cargo test` (not only in the vendored core's unit tests).
    assert_eq!(
        derive_domain_key(&["bonfida".to_string()])
            .unwrap()
            .to_base58(),
        "Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb"
    );
}

#[test]
fn bare_name_and_case_are_normalized() {
    let rpc = MockRpc::with_registry([1u8; 32]);
    assert_eq!(
        resolve_domain(&rpc, "  BONFIDA  ", &cfg()).unwrap().domain,
        "bonfida.sol"
    );
}

#[test]
fn unregistered_domain_is_a_clean_error() {
    let err = resolve_domain(&MockRpc::empty(), "definitelynotregistered.sol", &cfg()).unwrap_err();
    assert!(err.contains("not registered"), "got: {err}");
}

#[test]
fn derived_collision_with_a_non_registry_account_is_rejected() {
    // The derived address exists but is owned by some other program: must not
    // be treated as a resolution.
    let rpc = MockRpc::with_account(Pubkey([2u8; 32]), vec![0u8; NAME_HEADER_LEN]);
    let err = resolve_domain(&rpc, "bonfida.sol", &cfg()).unwrap_err();
    assert!(
        err.contains("does not resolve to a name registry"),
        "got: {err}"
    );
}

#[test]
fn malformed_inputs_fail_closed() {
    let rpc = MockRpc::with_registry([1u8; 32]);
    for bad in ["", ".sol", "a.b.c.sol", "bad name", &"x".repeat(70)] {
        assert!(
            resolve_domain(&rpc, bad, &cfg()).is_err(),
            "{bad:?} should fail"
        );
    }
}
