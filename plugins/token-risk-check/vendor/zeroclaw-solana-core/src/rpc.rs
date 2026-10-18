//! Solana JSON-RPC shaping and zero-copy Token-2022 mint parsing.
//!
//! Networking is behind the `HttpTransport` trait so this module — and every
//! test in it — never depends on an actual socket or on `waki`. Each
//! consuming plugin provides its own `HttpTransport` impl (typically backed
//! by `waki`, gated to the wasm32-wasip2 build only) rather than this crate
//! owning a transport implementation; that keeps `waki` out of this crate's
//! dependency graph entirely; see `crates/zeroclaw-solana-core/Cargo.toml`.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

/// Outbound HTTP, injected so core logic stays testable without a network.
pub trait HttpTransport {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;

    /// GET a URL with custom headers (e.g. a third-party API key). Solana's
    /// own JSON-RPC only ever needs `post_json`; this exists for plugins
    /// that also call a DEX aggregator or similar REST API under the same
    /// `http_client` permission. Default implementation returns a clear
    /// "unsupported" error so existing `post_json`-only implementations
    /// don't need to change to keep compiling.
    ///
    /// Header *names* are `&'static str`: real HTTP header names are always
    /// protocol-level constants (`"x-api-key"`, never a dynamically-built
    /// string), and pinning that at the type level exactly matches what
    /// `waki`'s own request builder requires internally (verified by
    /// compiling against it -- an earlier draft used `&str` here and hit
    /// waki's `K: IntoHeaderName` bound, which the underlying `http` crate
    /// only implements for `&'static str`). Header *values* stay `&str`,
    /// since those genuinely are runtime data (an API key from config).
    fn get_with_headers(
        &self,
        _url: &str,
        _headers: &[(&'static str, &str)],
    ) -> Result<String, String> {
        Err("this transport does not support GET requests".to_string())
    }
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

pub fn build_get_account_info_request(pubkey_base58: &str) -> String {
    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getAccountInfo",
        params: serde_json::json!([pubkey_base58, {"encoding": "base64"}]),
    };
    serde_json::to_string(&req).expect("request shape is always serializable")
}

/// Fetches and unwraps the base64 `data` field of `getAccountInfo`, discarding
/// everything else in the RPC envelope (lamports, owner, rent epoch, ...)
/// since only the raw account bytes are needed downstream.
pub fn fetch_account_data_base64(
    transport: &dyn HttpTransport,
    rpc_url: &str,
    pubkey_base58: &str,
) -> Result<String, String> {
    let body = build_get_account_info_request(pubkey_base58);
    let raw = transport.post_json(rpc_url, &body)?;
    let parsed: JsonRpcResponse =
        serde_json::from_str(&raw).map_err(|e| format!("malformed rpc response: {e}"))?;
    if let Some(err) = parsed.error {
        return Err(format!("rpc error: {err}"));
    }
    let result = parsed.result.ok_or("rpc response missing result")?;
    result
        .get("value")
        .and_then(|v| v.get("data"))
        .and_then(|d| d.get(0))
        .and_then(|d| d.as_str())
        .map(str::to_string)
        .ok_or_else(|| "rpc response missing base64 account data".to_string())
}

/// Decodes a base64 `getAccountInfo`-style payload into raw bytes.
pub fn decode_account_data(data_b64: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(data_b64.as_bytes())
        .map_err(|e| format!("invalid base64 account data: {e}"))
}

pub fn build_get_token_largest_accounts_request(mint_base58: &str) -> String {
    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getTokenLargestAccounts",
        params: serde_json::json!([mint_base58]),
    };
    serde_json::to_string(&req).expect("request shape is always serializable")
}

/// A single entry from `getTokenLargestAccounts`: an owning token account and
/// its raw (not decimal-adjusted) balance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargestAccountEntry {
    pub address: String,
    pub amount: u128,
}

/// Calls `getTokenLargestAccounts` and returns up to the top 20 holder
/// balances the RPC node reports, discarding the rest of the envelope
/// (decimals/uiAmount duplicate what `parse_mint_risk_view` already knows).
pub fn fetch_largest_token_accounts(
    transport: &dyn HttpTransport,
    rpc_url: &str,
    mint_base58: &str,
) -> Result<Vec<LargestAccountEntry>, String> {
    let body = build_get_token_largest_accounts_request(mint_base58);
    let raw = transport.post_json(rpc_url, &body)?;
    let parsed: JsonRpcResponse =
        serde_json::from_str(&raw).map_err(|e| format!("malformed rpc response: {e}"))?;
    if let Some(err) = parsed.error {
        return Err(format!("rpc error: {err}"));
    }
    let result = parsed.result.ok_or("rpc response missing result")?;
    let entries = result
        .get("value")
        .and_then(|v| v.as_array())
        .ok_or("rpc response missing largest-accounts value array")?;

    entries
        .iter()
        .map(|entry| {
            let address = entry
                .get("address")
                .and_then(|a| a.as_str())
                .ok_or("largest-accounts entry missing address")?
                .to_string();
            let amount = entry
                .get("amount")
                .and_then(|a| a.as_str())
                .ok_or("largest-accounts entry missing amount")?
                .parse::<u128>()
                .map_err(|e| format!("invalid largest-accounts amount: {e}"))?;
            Ok(LargestAccountEntry { address, amount })
        })
        .collect()
}

/// SPL Token / Token-2022 base `Mint` account is always 82 bytes. Token-2022
/// accounts additionally reuse `Account::LEN` (165 bytes) as a fixed offset
/// for the account-type tag before any TLV extension data begins, regardless
/// of whether the base struct itself is a Mint (82 bytes) or Account (165
/// bytes) — this lets a reader locate extensions without first knowing which
/// kind of account it's looking at.
pub const MINT_BASE_LEN: usize = 82;
pub const ACCOUNT_TYPE_OFFSET: usize = 165;
const TLV_START: usize = ACCOUNT_TYPE_OFFSET + 1;

/// Token-2022 extension type tags relevant to a risk assessment (values from
/// the `spl_token_2022::extension::ExtensionType` enum; differentially
/// verified against that crate in `spl_differential` below).
pub const EXTENSION_TRANSFER_FEE_CONFIG: u16 = 1;
pub const EXTENSION_MINT_CLOSE_AUTHORITY: u16 = 3;
pub const EXTENSION_DEFAULT_ACCOUNT_STATE: u16 = 6;
pub const EXTENSION_NON_TRANSFERABLE: u16 = 9;
pub const EXTENSION_PERMANENT_DELEGATE: u16 = 12;
pub const EXTENSION_TRANSFER_HOOK: u16 = 14;

#[derive(Debug, Clone, Copy, Default)]
pub struct MintAuthorities {
    pub mint_authority: Option<[u8; 32]>,
    pub freeze_authority: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Default)]
pub struct MintRiskView {
    pub decimals: u8,
    pub is_initialized: bool,
    /// Raw base-unit supply (not decimal-adjusted).
    pub supply: u64,
    pub authorities: MintAuthorities,
    /// Raw Token-2022 extension type tags present on the account (values, not
    /// interpreted contents) — enough to flag e.g. a transfer hook or
    /// permanent delegate without parsing each extension's internal layout.
    pub extension_types: Vec<u16>,
}

/// Reads an SPL `COption<Pubkey>`: a 4-byte LE tag (0 = None, 1 = Some)
/// followed by 32 bytes that are only meaningful when the tag is 1. The
/// full 36-byte slot is bounds-checked in one `.get()` call; every access
/// into the resulting `slot` sub-slice is then provably in range (not just
/// "checked earlier by different arithmetic"), so there is no index or
/// length computation here that adversarial account data can turn into a
/// panic.
fn read_coption_pubkey(data: &[u8], offset: usize) -> Result<(Option<[u8; 32]>, usize), String> {
    let end = offset.checked_add(36).ok_or("pubkey offset overflow")?;
    let slot = data
        .get(offset..end)
        .ok_or_else(|| "truncated COption slot".to_string())?;
    let tag = u32::from_le_bytes(slot[0..4].try_into().unwrap());
    match tag {
        0 => Ok((None, end)),
        1 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&slot[4..36]);
            Ok((Some(key), end))
        }
        other => Err(format!("invalid COption tag: {other}")),
    }
}

/// Parses only the fields needed to assess mint risk directly out of the raw
/// account bytes — no intermediate owned struct for the full mint layout,
/// and unrecognized TLV extensions are skipped by their length prefix
/// without ever being copied out.
///
/// Every read below goes through `.get()`/`checked_add` rather than direct
/// indexing or unchecked arithmetic: `account_data` is attacker-influenced
/// (it's raw on-chain bytes returned by RPC), so a truncated or
/// pathologically-crafted buffer must produce a clean `Err`, never a panic
/// or an integer-overflow trap.
pub fn parse_mint_risk_view(account_data: &[u8]) -> Result<MintRiskView, String> {
    if account_data.len() < MINT_BASE_LEN {
        return Err(format!(
            "account data too short for a token mint: {} bytes",
            account_data.len()
        ));
    }

    let (mint_authority, offset) = read_coption_pubkey(account_data, 0)?;

    let supply_bytes = account_data
        .get(offset..offset + 8)
        .ok_or_else(|| "truncated mint body: missing supply".to_string())?;
    let supply = u64::from_le_bytes(supply_bytes.try_into().unwrap());

    let decimals = *account_data
        .get(offset + 8)
        .ok_or_else(|| "truncated mint body: missing decimals".to_string())?;
    let is_initialized = *account_data
        .get(offset + 9)
        .ok_or_else(|| "truncated mint body: missing is_initialized".to_string())?
        != 0;

    let (freeze_authority, _) = read_coption_pubkey(account_data, offset + 10)?;

    let mut extension_types = Vec::new();
    if account_data.len() > TLV_START {
        let mut cursor = TLV_START;
        while let Some(header_end) = cursor.checked_add(4) {
            let Some(header) = account_data.get(cursor..header_end) else {
                break; // Fewer than 4 bytes left: no complete TLV header, stop scanning.
            };
            let ext_type = u16::from_le_bytes(header[0..2].try_into().unwrap());
            let ext_len = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
            if ext_type == 0 {
                break; // Uninitialized/padding marks the end of the TLV region.
            }
            extension_types.push(ext_type);
            cursor = match header_end.checked_add(ext_len) {
                Some(next) => next,
                None => break, // Pathological length claim; stop rather than overflow.
            };
        }
    }

    Ok(MintRiskView {
        decimals,
        is_initialized,
        supply,
        authorities: MintAuthorities {
            mint_authority,
            freeze_authority,
        },
        extension_types,
    })
}

#[cfg(test)]
pub struct MockTransport(pub String);

#[cfg(test)]
impl HttpTransport for MockTransport {
    fn post_json(&self, _url: &str, _body: &str) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Appends a Token-2022-shaped TLV extension region after a base mint
    /// buffer: pads to `ACCOUNT_TYPE_OFFSET`, writes the account-type tag,
    /// then one `(type: u16 LE, len: u16 LE, value)` entry per extension.
    fn append_tlv_extensions(mut data: Vec<u8>, extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        if extensions.is_empty() {
            return data;
        }
        data.resize(ACCOUNT_TYPE_OFFSET + 1, 0);
        data[ACCOUNT_TYPE_OFFSET] = 1; // AccountType::Mint
        for (ext_type, value) in extensions {
            data.extend_from_slice(&ext_type.to_le_bytes());
            data.extend_from_slice(&(value.len() as u16).to_le_bytes());
            data.extend_from_slice(value);
        }
        data
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Builds a byte-perfect synthetic mint with randomized authorities,
        /// decimals, and a randomized list of TLV extensions, then asserts
        /// the parser extracts *exactly* those inputs back out. This is what
        /// actually stands in for "verify the TLV offsets" without a live
        /// RPC endpoint: hundreds of structurally-varied synthetic accounts
        /// per run, not just the handful of hand-picked cases below.
        #[test]
        fn mint_parsing_round_trips_for_arbitrary_authorities_decimals_and_extensions(
            has_mint_authority in any::<bool>(),
            mint_authority_seed in any::<u8>(),
            has_freeze_authority in any::<bool>(),
            freeze_authority_seed in any::<u8>(),
            decimals in any::<u8>(),
            extensions in prop::collection::vec(
                (1u16..=u16::MAX, prop::collection::vec(any::<u8>(), 0..16)),
                0..6,
            ),
        ) {
            let mint_authority = has_mint_authority.then_some([mint_authority_seed; 32]);
            let freeze_authority = has_freeze_authority.then_some([freeze_authority_seed; 32]);
            let base = synthetic_mint(mint_authority, freeze_authority, decimals);
            let data = append_tlv_extensions(base, &extensions);

            let view = parse_mint_risk_view(&data).unwrap();

            prop_assert_eq!(view.decimals, decimals);
            prop_assert!(view.is_initialized);
            prop_assert_eq!(view.authorities.mint_authority, mint_authority);
            prop_assert_eq!(view.authorities.freeze_authority, freeze_authority);
            prop_assert_eq!(
                view.extension_types,
                extensions.iter().map(|(t, _)| *t).collect::<Vec<_>>()
            );
        }

        /// The zero-copy-parser contract that matters most against
        /// adversarial on-chain data: *no matter what bytes arrive*, this
        /// returns a `Result`, never panics. This is the stable-Rust
        /// substitute for a `cargo-fuzz` campaign in an environment where
        /// libFuzzer/nightly isn't available (see the fuzz feasibility notes
        /// in the README) -- proptest can't explore inputs as fast as a real
        /// coverage-guided fuzzer, but it runs today with no extra tooling.
        #[test]
        fn mint_parsing_never_panics_on_arbitrary_bytes(
            data in prop::collection::vec(any::<u8>(), 0..400),
        ) {
            let _ = parse_mint_risk_view(&data);
        }
    }

    fn synthetic_mint(
        mint_authority: Option<[u8; 32]>,
        freeze_authority: Option<[u8; 32]>,
        decimals: u8,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MINT_BASE_LEN);
        match mint_authority {
            Some(key) => {
                buf.extend_from_slice(&1u32.to_le_bytes());
                buf.extend_from_slice(&key);
            }
            None => {
                buf.extend_from_slice(&0u32.to_le_bytes());
                buf.extend_from_slice(&[0u8; 32]);
            }
        }
        buf.extend_from_slice(&1_000_000u64.to_le_bytes()); // supply
        buf.push(decimals);
        buf.push(1); // is_initialized
        match freeze_authority {
            Some(key) => {
                buf.extend_from_slice(&1u32.to_le_bytes());
                buf.extend_from_slice(&key);
            }
            None => {
                buf.extend_from_slice(&0u32.to_le_bytes());
                buf.extend_from_slice(&[0u8; 32]);
            }
        }
        assert_eq!(buf.len(), MINT_BASE_LEN);
        buf
    }

    #[test]
    fn parses_fully_renounced_mint_with_no_extensions() {
        let data = synthetic_mint(None, None, 6);
        let view = parse_mint_risk_view(&data).unwrap();
        assert_eq!(view.decimals, 6);
        assert!(view.is_initialized);
        assert!(view.authorities.mint_authority.is_none());
        assert!(view.authorities.freeze_authority.is_none());
        assert!(view.extension_types.is_empty());
    }

    #[test]
    fn parses_mint_with_active_authorities() {
        let mint_auth = [11u8; 32];
        let freeze_auth = [22u8; 32];
        let data = synthetic_mint(Some(mint_auth), Some(freeze_auth), 9);
        let view = parse_mint_risk_view(&data).unwrap();
        assert_eq!(view.authorities.mint_authority, Some(mint_auth));
        assert_eq!(view.authorities.freeze_authority, Some(freeze_auth));
    }

    #[test]
    fn scans_tlv_extensions_past_the_base_mint() {
        let mut data = synthetic_mint(None, None, 6);
        data.resize(ACCOUNT_TYPE_OFFSET + 1, 0);
        data[ACCOUNT_TYPE_OFFSET] = 1; // AccountType::Mint

        // A synthetic extension: type=3 (MintCloseAuthority-shaped), len=32, then 32 dummy bytes.
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes());
        data.extend_from_slice(&[7u8; 32]);

        // A second synthetic extension: type=14, len=0.
        data.extend_from_slice(&14u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        let view = parse_mint_risk_view(&data).unwrap();
        assert_eq!(view.extension_types, vec![3, 14]);
    }

    #[test]
    fn rejects_truncated_account_data() {
        let err = parse_mint_risk_view(&[0u8; 10]).unwrap_err();
        assert!(err.contains("too short"));
    }

    #[test]
    fn read_coption_pubkey_rejects_truncated_tag_without_panicking() {
        let err = read_coption_pubkey(&[1, 0, 0], 0).unwrap_err();
        assert!(err.contains("truncated"));
    }

    #[test]
    fn read_coption_pubkey_rejects_truncated_value_without_panicking() {
        // Regression test for a real off-by-one bug: an earlier version
        // bounds-checked only the 4-byte tag and then unconditionally read
        // 32 more bytes when the tag was 1, which could index past the end
        // of a buffer that was truncated right after the tag. The fixed
        // version bounds-checks the full 36-byte slot in one `.get()` call.
        let mut buf = vec![1, 0, 0, 0]; // tag = Some(..), but no pubkey bytes follow
        buf.extend_from_slice(&[7u8; 20]); // only 20 of the required 32 value bytes
        let err = read_coption_pubkey(&buf, 0).unwrap_err();
        assert!(err.contains("truncated"));
    }

    #[test]
    fn tlv_scan_stops_cleanly_on_a_pathological_length_claim_instead_of_overflowing() {
        let mut data = synthetic_mint(None, None, 6);
        data.resize(ACCOUNT_TYPE_OFFSET + 1, 0);
        data[ACCOUNT_TYPE_OFFSET] = 1;
        // A single extension header claiming an absurd length (close to
        // usize::MAX once combined with the cursor), with no value bytes
        // actually present.
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0xFFFFu16.to_le_bytes());

        // Must return a clean result (the malformed extension is simply not
        // recorded past this point), never panic or hang.
        let view = parse_mint_risk_view(&data).unwrap();
        assert_eq!(view.extension_types, vec![3]);
    }

    #[test]
    fn fetch_account_data_base64_extracts_and_discards_the_rest() {
        let fixture = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"data":["ZGF0YQ==","base64"],"executable":false,"lamports":1,"owner":"x","rentEpoch":0}},"id":1}"#;
        let transport = MockTransport(fixture.to_string());
        let data = fetch_account_data_base64(&transport, "http://example.invalid", "mint").unwrap();
        assert_eq!(data, "ZGF0YQ==");
    }

    #[test]
    fn fetch_account_data_base64_surfaces_rpc_errors() {
        let fixture =
            r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"invalid params"},"id":1}"#;
        let transport = MockTransport(fixture.to_string());
        let err =
            fetch_account_data_base64(&transport, "http://example.invalid", "mint").unwrap_err();
        assert!(err.contains("invalid params"));
    }

    #[test]
    fn fetch_largest_token_accounts_parses_amounts() {
        let fixture = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":[
            {"address":"Holder1","amount":"600000","decimals":6,"uiAmount":0.6,"uiAmountString":"0.6"},
            {"address":"Holder2","amount":"400000","decimals":6,"uiAmount":0.4,"uiAmountString":"0.4"}
        ]},"id":1}"#;
        let transport = MockTransport(fixture.to_string());
        let entries =
            fetch_largest_token_accounts(&transport, "http://example.invalid", "mint").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].address, "Holder1");
        assert_eq!(entries[0].amount, 600_000);
    }
}

/// Differential tests against the canonical `spl-token-2022`/`solana-program`
/// crates: dev-only dependencies (see `Cargo.toml`) that verify our
/// hand-rolled, zero-solana-sdk parser against ground truth instead of only
/// against synthetic buffers we built by hand ourselves. This is what
/// actually resolves the "TLV offsets are unverified against a live
/// endpoint" caveat -- it doesn't need a network, just the same on-chain
/// serialization logic the real network uses.
#[cfg(test)]
mod spl_differential {
    use super::*;
    use solana_program::program_option::COption;
    use solana_program::program_pack::Pack;
    use spl_token_2022::state::{Account as SplAccount, Mint as SplMint};

    #[test]
    fn constants_match_canonical_spl_token_2022_layout() {
        assert_eq!(
            MINT_BASE_LEN,
            SplMint::LEN,
            "MINT_BASE_LEN must match spl_token_2022::state::Mint::LEN"
        );
        assert_eq!(
            ACCOUNT_TYPE_OFFSET,
            SplAccount::LEN,
            "ACCOUNT_TYPE_OFFSET must match spl_token_2022::state::Account::LEN"
        );
    }

    #[test]
    fn extension_type_constants_match_canonical_crate() {
        use spl_token_2022::extension::ExtensionType;
        assert_eq!(
            EXTENSION_TRANSFER_FEE_CONFIG,
            ExtensionType::TransferFeeConfig as u16
        );
        assert_eq!(
            EXTENSION_MINT_CLOSE_AUTHORITY,
            ExtensionType::MintCloseAuthority as u16
        );
        assert_eq!(
            EXTENSION_DEFAULT_ACCOUNT_STATE,
            ExtensionType::DefaultAccountState as u16
        );
        assert_eq!(
            EXTENSION_NON_TRANSFERABLE,
            ExtensionType::NonTransferable as u16
        );
        assert_eq!(
            EXTENSION_PERMANENT_DELEGATE,
            ExtensionType::PermanentDelegate as u16
        );
        assert_eq!(EXTENSION_TRANSFER_HOOK, ExtensionType::TransferHook as u16);
    }

    #[test]
    fn parses_a_real_spl_token_2022_packed_mint_with_authorities() {
        let mint_authority = solana_program::pubkey::Pubkey::new_from_array([11u8; 32]);
        let freeze_authority = solana_program::pubkey::Pubkey::new_from_array([22u8; 32]);
        let mint = SplMint {
            mint_authority: COption::Some(mint_authority),
            supply: 1_000_000,
            decimals: 9,
            is_initialized: true,
            freeze_authority: COption::Some(freeze_authority),
        };
        let mut buf = vec![0u8; SplMint::LEN];
        SplMint::pack(mint, &mut buf).unwrap();

        let view = parse_mint_risk_view(&buf).unwrap();
        assert_eq!(view.decimals, 9);
        assert!(view.is_initialized);
        assert_eq!(view.supply, 1_000_000);
        assert_eq!(
            view.authorities.mint_authority,
            Some(mint_authority.to_bytes())
        );
        assert_eq!(
            view.authorities.freeze_authority,
            Some(freeze_authority.to_bytes())
        );
    }

    #[test]
    fn parses_a_real_spl_token_2022_packed_mint_with_no_authorities() {
        let mint = SplMint {
            mint_authority: COption::None,
            supply: 0,
            decimals: 6,
            is_initialized: true,
            freeze_authority: COption::None,
        };
        let mut buf = vec![0u8; SplMint::LEN];
        SplMint::pack(mint, &mut buf).unwrap();

        let view = parse_mint_risk_view(&buf).unwrap();
        assert_eq!(view.decimals, 6);
        assert_eq!(view.supply, 0);
        assert!(view.authorities.mint_authority.is_none());
        assert!(view.authorities.freeze_authority.is_none());
    }

    #[test]
    fn parses_real_extension_type_ids_from_a_real_token_2022_extension_mint() {
        use spl_token_2022::extension::{
            mint_close_authority::MintCloseAuthority, BaseStateWithExtensionsMut, ExtensionType,
            StateWithExtensionsMut,
        };

        let account_size = ExtensionType::try_calculate_account_len::<SplMint>(&[
            ExtensionType::MintCloseAuthority,
        ])
        .unwrap();
        let mut buf = vec![0u8; account_size];

        let mut state = StateWithExtensionsMut::<SplMint>::unpack_uninitialized(&mut buf).unwrap();
        state.base = SplMint {
            mint_authority: COption::None,
            supply: 0,
            decimals: 6,
            is_initialized: true,
            freeze_authority: COption::None,
        };
        state.pack_base();
        state.init_account_type().unwrap();
        // `init_extension` zero-initializes the extension's storage, which
        // for `OptionalNonZeroPubkey` already represents "no authority set" --
        // no further field assignment needed for this test's purposes.
        let _extension = state.init_extension::<MintCloseAuthority>(true).unwrap();

        let view = parse_mint_risk_view(&buf).unwrap();
        assert_eq!(
            view.extension_types,
            vec![ExtensionType::MintCloseAuthority as u16],
            "our TLV scan must recover exactly the extension type id the canonical crate assigned"
        );
    }
}
