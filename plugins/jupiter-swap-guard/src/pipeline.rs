//! The pure orchestration: quote → gate → fetch tables → compile → serialize →
//! summarize. Takes the network boundary as `&dyn SwapApi`/`&dyn Rpc`, so the
//! whole flow is host-tested end to end with mocks fed the real captured
//! fixtures. `execute` in the wasm shim is a thin wrapper that constructs the
//! waki-backed implementations and calls `run_swap`.

#![forbid(unsafe_code)]

use crate::ata::{ATA_PROGRAM_ID, TOKEN_PROGRAM_ID};
use crate::b58::{decode_pubkey, encode_pubkey};
use crate::compile::{compile_v0, AddressLookupTable};
use crate::decode::ATA_CREATE_MINT_INDEX;
use crate::encode::{serialize_unsigned_transaction, Pubkey};
use crate::gate::{evaluate, Programs, SwapRequest};
use crate::http::{Rpc, SwapApi};
use crate::jupiter::{parse_quote, parse_swap_instructions, SwapInstructions};
use crate::policy::{Policy, Reject};
use crate::summary::{approval_summary, guard_json, SummaryView};

/// The successful result of a guarded swap build.
#[derive(Debug)]
pub struct SwapOutput {
    pub summary: String,
    pub unsigned_tx_b64: String,
    pub guard_json: String,
}

/// Run the full guarded build. Every `Err` is a fail-closed refusal — no
/// transaction is emitted.
pub fn run_swap(
    policy: &Policy,
    request: &SwapRequest,
    api: &dyn SwapApi,
    rpc: &dyn Rpc,
) -> Result<SwapOutput, Reject> {
    // 1. Quote.
    let query = format!(
        "inputMint={}&outputMint={}&amount={}&slippageBps={}",
        encode_pubkey(&request.input_mint),
        encode_pubkey(&request.output_mint),
        request.amount_atoms,
        request.slippage_bps,
    );
    let quote_body = api
        .quote(&policy.jupiter_base_url, &query)
        .map_err(Reject::Upstream)?;
    let quote = parse_quote(&quote_body).map_err(Reject::Upstream)?;

    // 2. Swap instructions (NEVER /swap — we rebuild from the instruction list).
    let si_body = format!(
        r#"{{"userPublicKey":"{}","quoteResponse":{},"wrapAndUnwrapSol":true,"dynamicComputeUnitLimit":true}}"#,
        encode_pubkey(&policy.payer),
        quote.raw,
    );
    let si_text = api
        .swap_instructions(&policy.jupiter_base_url, &si_body)
        .map_err(Reject::Upstream)?;
    let swap = parse_swap_instructions(&si_text).map_err(Reject::Upstream)?;

    // 3. Token programs, taken from the route's own ATA-create instructions (the
    //    ATA program validates canonicity on-chain), defaulting to legacy Token.
    let programs = resolve_programs(&swap, &request.input_mint, &request.output_mint)?;

    // 4. The gate: every guardrail. Fails closed on any violation.
    let verdict = evaluate(policy, request, &quote, &swap, &programs)?;

    // 5. Lookup tables from OUR rpc (never Jupiter's echoed contents).
    let tables = fetch_lookup_tables(&swap, policy, rpc)?;

    // 6. Cluster pin (defends against misconfiguration; see threat model).
    let genesis = rpc
        .get_genesis_hash(&policy.rpc_url)
        .map_err(Reject::Upstream)?;
    let cluster_ok = match &policy.expected_genesis_hash {
        Some(pin) if *pin == genesis => true,
        Some(_) => {
            return Err(Reject::Upstream(format!(
                "cluster genesis {genesis} does not match the configured pin"
            )))
        }
        None => false,
    };

    // 7. Our own blockhash.
    let blockhash_b58 = rpc
        .get_latest_blockhash(&policy.rpc_url)
        .map_err(Reject::Upstream)?;
    let blockhash = decode_pubkey(&blockhash_b58).map_err(Reject::Upstream)?;

    // 8. Compile (enforces D5) and serialize the unsigned transaction.
    let msg = compile_v0(
        policy.payer,
        &swap.ordered(),
        &tables,
        blockhash,
        &verdict.must_be_static,
    )
    .map_err(|e| Reject::BuildFailed(format!("{e:?}")))?;
    let tx_bytes = serialize_unsigned_transaction(&msg);
    use base64::Engine;
    let unsigned_tx_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

    // 9. Advisory summary + machine verdict.
    let (in_decimals, out_decimals) = decimals(policy, request)?;
    let summary = approval_summary(&SummaryView {
        request,
        verdict: &verdict,
        quote_out: quote.out_amount,
        in_decimals,
        out_decimals,
        max_slippage_bps: policy.max_slippage_bps,
        payer: &policy.payer,
        cluster_ok,
    });
    let guard_json = guard_json(&verdict, &unsigned_tx_b64);

    Ok(SwapOutput {
        summary,
        unsigned_tx_b64,
        guard_json,
    })
}

fn resolve_programs(
    swap: &SwapInstructions,
    input_mint: &Pubkey,
    output_mint: &Pubkey,
) -> Result<Programs, Reject> {
    let ata_program = decode_pubkey(ATA_PROGRAM_ID).expect("valid ata id");
    let default_token = decode_pubkey(TOKEN_PROGRAM_ID).expect("valid token id");
    let token_for = |mint: &Pubkey| -> Pubkey {
        for ix in &swap.setup {
            if ix.program_id == ata_program {
                if let (Some(m), Some(tp)) =
                    (ix.accounts.get(ATA_CREATE_MINT_INDEX), ix.accounts.get(5))
                {
                    if m.pubkey == *mint {
                        return tp.pubkey;
                    }
                }
            }
        }
        default_token
    };
    Ok(Programs {
        input_token_program: token_for(input_mint),
        output_token_program: token_for(output_mint),
        ata_program,
    })
}

fn fetch_lookup_tables(
    swap: &SwapInstructions,
    policy: &Policy,
    rpc: &dyn Rpc,
) -> Result<Vec<AddressLookupTable>, Reject> {
    use base64::Engine;
    const META: usize = 56;
    let mut tables = Vec::new();
    for key in &swap.address_lookup_tables {
        let b58 = encode_pubkey(key);
        let data_b64 = rpc
            .get_account_base64(&policy.rpc_url, &b58)
            .map_err(Reject::Upstream)?
            .ok_or_else(|| Reject::Upstream(format!("lookup table {b58} not found")))?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&data_b64)
            .map_err(|e| Reject::Upstream(format!("lookup table not base64: {e}")))?;
        if data.len() < META || !(data.len() - META).is_multiple_of(32) {
            return Err(Reject::Upstream(format!("lookup table {b58} malformed")));
        }
        let addresses = data[META..]
            .chunks_exact(32)
            .map(|c| <[u8; 32]>::try_from(c).unwrap())
            .collect();
        tables.push(AddressLookupTable {
            key: *key,
            addresses,
        });
    }
    Ok(tables)
}

fn decimals(policy: &Policy, request: &SwapRequest) -> Result<(u8, u8), Reject> {
    let in_d = policy.require_mint(&request.input_mint)?.decimals;
    let out_d = policy.require_mint(&request.output_mint)?.decimals;
    Ok((in_d, out_d))
}

/// Parse the tool's JSON arguments (minus the injected `__config`) into a request.
pub fn parse_request(args: &serde_json::Value) -> Result<SwapRequest, Reject> {
    let s = |k: &str| -> Result<Pubkey, Reject> {
        args.get(k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| Reject::BadConfig(format!("missing string arg `{k}`")))
            .and_then(|v| decode_pubkey(v).map_err(Reject::BadConfig))
    };
    let amount_atoms: u64 = args
        .get("amount_atoms")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Reject::BadConfig("missing string arg `amount_atoms`".into()))?
        .parse()
        .map_err(|_| Reject::BadConfig("`amount_atoms` is not a u64".into()))?;
    let slippage_bps: u16 = match args.get("slippage_bps") {
        None => 0,
        Some(v) => v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| Reject::BadConfig("`slippage_bps` is not a u16".into()))?,
    };
    Ok(SwapRequest {
        input_mint: s("input_mint")?,
        output_mint: s("output_mint")?,
        amount_atoms,
        slippage_bps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    const WSOL: &str = "So11111111111111111111111111111111111111112";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const PAYER: &str = "4sLWYqVXqQHs7s4PQPrQ2agNVX1y3W4sL5QtzFsuijDz";
    const JUP: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
    const SYS: &str = "11111111111111111111111111111111";
    const CB: &str = "ComputeBudget111111111111111111111111111111";

    /// A mock that replays the captured fixtures — the real quote, the real
    /// swap-instructions, and the real lookup-table account.
    struct FixtureBackend {
        genesis: String,
    }

    impl SwapApi for FixtureBackend {
        fn quote(&self, _: &str, _: &str) -> Result<String, String> {
            Ok(std::fs::read_to_string(format!("{FX}/quote.json")).unwrap())
        }
        fn swap_instructions(&self, _: &str, _: &str) -> Result<String, String> {
            Ok(std::fs::read_to_string(format!("{FX}/swap-instructions.json")).unwrap())
        }
    }
    impl Rpc for FixtureBackend {
        fn get_account_base64(&self, _: &str, _: &str) -> Result<Option<String>, String> {
            let v: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(format!("{FX}/alt_account.json")).unwrap(),
            )
            .unwrap();
            Ok(Some(
                v["result"]["value"]["data"][0]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ))
        }
        fn get_genesis_hash(&self, _: &str) -> Result<String, String> {
            Ok(self.genesis.clone())
        }
        fn get_latest_blockhash(&self, _: &str) -> Result<String, String> {
            // Any valid base58 32-byte value.
            Ok("11111111111111111111111111111112".to_string())
        }
    }

    fn policy(genesis_pin: Option<&str>) -> Policy {
        let mut pairs = vec![
            ("rpc_url", "https://api.mainnet-beta.solana.com".to_string()),
            (
                "jupiter_base_url",
                "https://lite-api.jup.ag/swap/v1".to_string(),
            ),
            ("payer_pubkey", PAYER.to_string()),
            (
                "allowed_mints",
                format!("{WSOL}:9:1000000000,{USDC}:6:500000000"),
            ),
            ("max_slippage_bps", "50".to_string()),
            ("max_priority_fee_lamports", "200000".to_string()),
            (
                "allowed_programs",
                format!("{SYS},{CB},{JUP},{TOKEN_PROGRAM_ID},{ATA_PROGRAM_ID}"),
            ),
        ];
        if let Some(g) = genesis_pin {
            pairs.push(("expected_genesis_hash", g.to_string()));
        }
        let cfg: HashMap<String, String> =
            pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        Policy::parse(&cfg).unwrap()
    }

    fn request() -> SwapRequest {
        SwapRequest {
            input_mint: decode_pubkey(WSOL).unwrap(),
            output_mint: decode_pubkey(USDC).unwrap(),
            amount_atoms: 100_000_000,
            slippage_bps: 50,
        }
    }

    // POSITIVE CONTROL: the whole pipeline over the real fixtures produces a real
    // unsigned transaction whose bytes decode to a versioned message.
    #[test]
    fn full_pipeline_builds_unsigned_tx() {
        const MAINNET: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
        let backend = FixtureBackend {
            genesis: MAINNET.to_string(),
        };
        let out = run_swap(&policy(Some(MAINNET)), &request(), &backend, &backend).unwrap();
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&out.unsigned_tx_b64)
            .unwrap();
        // 1 sig-count byte + 64 empty-sig bytes + 0x80-prefixed v0 message.
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[65], 0x80);
        assert!(out.summary.contains("Output bound to your ATA"));
        assert!(out.summary.contains("mainnet ✓"));
        assert!(out.guard_json.contains("unsigned_tx_b64"));
    }

    // NEGATIVE CONTROL: a genesis pin that does not match the cluster is refused.
    #[test]
    fn wrong_cluster_pin_is_refused() {
        let backend = FixtureBackend {
            genesis: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d".to_string(),
        };
        let devnet_pin = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
        let err = run_swap(&policy(Some(devnet_pin)), &request(), &backend, &backend).unwrap_err();
        assert!(matches!(err, Reject::Upstream(_)));
    }
}
