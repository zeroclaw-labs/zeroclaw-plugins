//! End-to-end pipeline tests: drive `guard::run` against a `MockTransport`
//! keyed by request content (URL for GET, body for POST/JSON-RPC), on the
//! committed `kamino-types`/`rescue` fixtures. Proves the wiring, the
//! closed endpoint/method set, fail-closed rescue gating, and stale-data
//! degradation — never the pure math those modules already cover in their
//! own test suites.

use liquidation_guard::guard::{run, HttpRequest, HttpResponse, Transport};
use liquidation_guard::kamino::{encode_snapshot, Snapshot};

const OBLIGATIONS_JSON: &str = include_str!("fixtures/obligations.json");
const PRICES_JSON: &str = include_str!("fixtures/prices.json");
const RESERVES_METRICS_JSON: &str = include_str!("fixtures/reserves_metrics.json");
const RESERVE_ACCOUNTS_JSON: &str = include_str!("fixtures/reserve_accounts.json");

const WALLET: &str = "AcNSmd5CxwLs21TYUmhWt7CW2v159TdYRkvQxb1iBYRj";
/// The obligation's cbBTC deposit reserve — absent from
/// `reserve_accounts.json` (that fixture was captured for the `rescue`
/// slice's own golden test against a different reserve set); see
/// `account_data_body`.
const CBBTC_RESERVE: &str = "37Jk2zkz23vkAYBT66HM2gaqJuNg2nYLsCreQAVt5MWK";
/// Stand-in "blockhash": `rescue::build_repay_tx` only needs a valid
/// base58 32-byte value, so any real pubkey works.
const FAKE_BLOCKHASH: &str = WALLET;

/// A `Date` header ~60s after the price fixture's timestamps — inside
/// every row's `maxAgeInSeconds` (120s/180s), so nothing is stale.
const FRESH_DATE: &str = "Sun, 19 Jul 2026 06:54:07 GMT";
/// A `Date` header ~1 year after the price fixture's timestamps — every
/// row is stale.
const FAR_FUTURE_DATE: &str = "Mon, 19 Jul 2027 06:54:07 GMT";

/// Builds the `/kamino-market/reserves/account-data` response body: the
/// committed `reserve_accounts.json` fixture plus one synthetic entry for
/// the cbBTC deposit reserve. Reusing a real account blob under a new
/// pubkey label decodes fine — `extract_reserve_accounts` only checks
/// length/discriminator/`lending_market`, all shared by every reserve in
/// one market — and this pipeline never reads a non-repay reserve's own
/// decimals/mint, only its pubkey (for the `refresh_reserve`/
/// `refresh_obligation` account lists).
fn account_data_body() -> String {
    let mut v: serde_json::Value = serde_json::from_str(RESERVE_ACCOUNTS_JSON).unwrap();
    let filler = v[0]["reserves"][0]["data"].as_str().unwrap().to_string();
    v[0]["reserves"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({ "pubkey": CBBTC_RESERVE, "data": filler }));
    v.to_string()
}

fn blockhash_response() -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"blockhash":"{FAKE_BLOCKHASH}","lastValidBlockHeight":1}}}}}}"#
    )
}

/// Solana mainnet-beta genesis hash — the only value the tx paths accept.
const MAINNET_GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

fn genesis_response(hash: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{hash}"}}"#)
}

/// A fully-wired happy transport whose `getGenesisHash` answer is replaced
/// by `body`. Routes match first-wins, so the override is registered
/// *ahead* of the default rather than appended behind it.
fn transport_with_genesis(body: impl Into<String>) -> MockTransport {
    let mut t = MockTransport::new().route("getGenesisHash", 200, body);
    t.routes.extend(rescue_transport(1_000_000.0).routes);
    t
}

fn balance_response(ui_amount: f64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"amount":"0","decimals":6,"uiAmount":{ui_amount}}}}}}}"#
    )
}

struct MockRoute {
    key: String,
    status: u16,
    body: String,
    date_header: Option<String>,
}

/// Canned-response transport keyed by request content: GET calls route on
/// their URL; POST (JSON-RPC) calls all share one URL (`rpc_url`), so they
/// route on the body, which names the RPC method. Records every request
/// made, in order, for assertions (retry counting, closed-endpoint-set
/// checks).
struct MockTransport {
    routes: Vec<MockRoute>,
    log: Vec<(String, Option<String>)>,
}

impl MockTransport {
    fn new() -> Self {
        Self {
            routes: Vec::new(),
            log: Vec::new(),
        }
    }

    fn route(mut self, key: &str, status: u16, body: impl Into<String>) -> Self {
        self.routes.push(MockRoute {
            key: key.to_string(),
            status,
            body: body.into(),
            date_header: None,
        });
        self
    }

    fn route_dated(
        mut self,
        key: &str,
        status: u16,
        body: impl Into<String>,
        date_header: &str,
    ) -> Self {
        self.routes.push(MockRoute {
            key: key.to_string(),
            status,
            body: body.into(),
            date_header: Some(date_header.to_string()),
        });
        self
    }

    fn count(&self, key: &str) -> usize {
        self.log
            .iter()
            .filter(|(url, body)| format!("{url} {}", body.as_deref().unwrap_or("")).contains(key))
            .count()
    }
}

impl Transport for MockTransport {
    fn fetch(&mut self, req: &HttpRequest) -> Result<HttpResponse, String> {
        self.log.push((req.url.clone(), req.body.clone()));
        let haystack = format!("{} {}", req.url, req.body.as_deref().unwrap_or(""));
        let route = self
            .routes
            .iter()
            .find(|r| haystack.contains(r.key.as_str()))
            .ok_or_else(|| format!("MockTransport: no route matches request: {haystack}"))?;
        Ok(HttpResponse {
            status: route.status,
            body: route.body.clone(),
            date_header: route.date_header.clone(),
        })
    }
}

/// A transport with every endpoint wired to succeed, parameterized on the
/// wallet's token balance so callers can force the optional balance cap to
/// bind (or not).
fn rescue_transport(balance_ui: f64) -> MockTransport {
    MockTransport::new()
        .route_dated("/oracles/prices", 200, PRICES_JSON, FRESH_DATE)
        .route("/obligations", 200, OBLIGATIONS_JSON)
        .route("/reserves/metrics", 200, RESERVES_METRICS_JSON)
        .route("/reserves/account-data", 200, account_data_body())
        .route("getGenesisHash", 200, genesis_response(MAINNET_GENESIS))
        .route("getLatestBlockhash", 200, blockhash_response())
        .route("getTokenAccountBalance", 200, balance_response(balance_ui))
}

/// A transport with every endpoint wired to succeed (fresh prices, full
/// reserve account data, a blockhash, and a large token balance so the
/// optional balance cap never binds by accident).
fn happy_transport() -> MockTransport {
    rescue_transport(1_000_000.0)
}

fn check_args(config: serde_json::Value) -> String {
    serde_json::json!({
        "action": "check",
        "wallet": WALLET,
        "__config": config,
    })
    .to_string()
}

fn portfolio_args(config: serde_json::Value) -> String {
    serde_json::json!({
        "action": "portfolio",
        "wallet": WALLET,
        "__config": config,
    })
    .to_string()
}

fn rescue_args(config: serde_json::Value, extra: serde_json::Value) -> String {
    let mut obj = serde_json::json!({
        "action": "rescue",
        "wallet": WALLET,
        "__config": config,
    });
    if let (Some(o), Some(e)) = (obj.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    obj.to_string()
}

fn deposit_args(config: serde_json::Value, extra: serde_json::Value) -> String {
    let mut obj = serde_json::json!({
        "action": "deposit",
        "wallet": WALLET,
        "__config": config,
    });
    if let (Some(o), Some(e)) = (obj.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    obj.to_string()
}

#[test]
fn check_happy_path() {
    let mut t = happy_transport();
    let out = run(&check_args(serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    let first_line = out.text.lines().next().unwrap_or_default();
    assert!(
        first_line.contains("buffer"),
        "missing tier line: {}",
        out.text
    );
    assert!(
        out.text.contains("snapshot:"),
        "missing snapshot line: {}",
        out.text
    );
}

/// harden F4: the committed obligations fixture has `market.state.
/// autodeleverageEnabled: 1`, so a real `check` call against it must
/// render the ADL warning end to end — not just parse the flag.
#[test]
fn adl_warning_fires_on_fixture() {
    let mut t = happy_transport();
    let out = run(&check_args(serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text
            .contains("ADL WARNING: autodeleverage enabled on: cbBTC, USDG"),
        "missing ADL warning: {}",
        out.text
    );
}

#[test]
fn stale_data_renders_warning() {
    let mut t = MockTransport::new()
        .route_dated("/oracles/prices", 200, PRICES_JSON, FAR_FUTURE_DATE)
        .route("/obligations", 200, OBLIGATIONS_JSON)
        .route("/reserves/metrics", 200, RESERVES_METRICS_JSON);
    let out = run(&check_args(serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text.contains("STALE DATA:"),
        "missing stale warning: {}",
        out.text
    );
}

#[test]
fn rescue_disabled_without_max_repay() {
    // No routes registered: the max_repay_ui gate must fire before any
    // network call, so an unmatched route would otherwise surface as a
    // *different* failure and this test would still (wrongly) pass on
    // `!out.success` alone — the log-is-empty assertion below closes that
    // gap.
    let mut t = MockTransport::new();
    let out = run(
        &rescue_args(serde_json::json!({}), serde_json::json!({})),
        &mut t,
    );
    assert!(!out.success);
    assert!(
        out.text.contains("rescue disabled"),
        "unexpected refusal text: {}",
        out.text
    );
    assert!(
        t.log.is_empty(),
        "must fail before any network call, log: {:?}",
        t.log
    );
}

/// Cluster gate: a `rpc_url` serving any cluster but mainnet-beta must
/// refuse to build. Every account address in the plan comes from Kamino's
/// mainnet API, so a devnet endpoint would pair mainnet addresses with a
/// foreign blockhash — the mistake has to surface here, named, rather than
/// as an opaque failure when the user tries to sign.
#[test]
fn wrong_cluster_refuses_to_build_a_transaction() {
    const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

    for (label, args) in [
        (
            "rescue",
            rescue_args(
                serde_json::json!({ "max_repay_ui": "100000" }),
                serde_json::json!({}),
            ),
        ),
        (
            "deposit",
            deposit_args(
                serde_json::json!({ "max_deposit_ui": "100000" }),
                serde_json::json!({}),
            ),
        ),
    ] {
        let mut t = transport_with_genesis(genesis_response(DEVNET_GENESIS));
        let out = run(&args, &mut t);
        assert!(!out.success, "{label}: expected refusal, got: {}", out.text);
        assert!(
            out.text.contains("not Solana mainnet-beta"),
            "{label}: refusal must name the cluster mismatch: {}",
            out.text
        );
        assert_eq!(
            t.count("getLatestBlockhash"),
            0,
            "{label}: must refuse before fetching a blockhash, log: {:?}",
            t.log
        );
        assert!(
            !out.text.contains("Unsigned."),
            "{label}: no transaction may be rendered: {}",
            out.text
        );
    }
}

/// The cluster gate never degrades to "assume mainnet": an erroring or
/// unreadable `getGenesisHash` is a hard refusal, not a shrug. Without
/// this, a node that 200s a JSON-RPC error object would silently reopen
/// the exact hole the gate exists to close.
#[test]
fn unreadable_genesis_hash_fails_closed() {
    for (label, body) in [
        (
            "rpc error object",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}"#,
        ),
        ("missing result", r#"{"jsonrpc":"2.0","id":1}"#),
        ("not json", "<html>502</html>"),
    ] {
        let mut t = transport_with_genesis(body);
        let out = run(
            &rescue_args(
                serde_json::json!({ "max_repay_ui": "100000" }),
                serde_json::json!({}),
            ),
            &mut t,
        );
        assert!(!out.success, "{label}: expected refusal, got: {}", out.text);
        assert_eq!(
            t.count("getLatestBlockhash"),
            0,
            "{label}: must refuse before fetching a blockhash, log: {:?}",
            t.log
        );
    }
}

/// v11-deposit-encoder: same fail-closed shape as
/// `rescue_disabled_without_max_repay`, for the deposit action's
/// `max_deposit_ui` gate.
#[test]
fn deposit_disabled_without_max_deposit_ui() {
    let mut t = MockTransport::new();
    let out = run(
        &deposit_args(serde_json::json!({}), serde_json::json!({})),
        &mut t,
    );
    assert!(!out.success);
    assert!(
        out.text.contains("deposit disabled"),
        "unexpected refusal text: {}",
        out.text
    );
    assert!(
        t.log.is_empty(),
        "must fail before any network call, log: {:?}",
        t.log
    );
}

/// v11-deposit-encoder: mirrors `amount_capping` (max_deposit_ui binds) and
/// `balance_cap_labeled_and_warned` (wallet balance binds) for the deposit
/// action's cap-candidate mechanism.
#[test]
fn deposit_caps_and_balance_label() {
    let mut t = happy_transport();
    let cfg = serde_json::json!({ "max_deposit_ui": "0.001" });
    let out = run(&deposit_args(cfg, serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text.contains("capped by max_deposit_ui"),
        "expected cap note: {}",
        out.text
    );

    let mut t2 = rescue_transport(0.0001);
    let cfg2 = serde_json::json!({ "max_deposit_ui": "100000" });
    let out2 = run(&deposit_args(cfg2, serde_json::json!({})), &mut t2);
    assert!(out2.success, "expected success, got: {}", out2.text);
    assert!(
        out2.text.contains("capped by balance"),
        "expected balance cap label: {}",
        out2.text
    );
    assert!(
        out2.text.contains("does NOT restore the WATCH boundary"),
        "expected balance-cap warning line: {}",
        out2.text
    );
}

#[test]
fn rescue_happy_path() {
    let mut t = happy_transport();
    let cfg = serde_json::json!({ "max_repay_ui": "100000" });
    let out = run(&rescue_args(cfg, serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text.contains(
            "Unsigned. Nothing here can sign or broadcast. Inspect and sign in your own wallet."
        ),
        "missing custody sentence: {}",
        out.text
    );
    assert!(
        out.text.contains("tx (base64):"),
        "missing tx: {}",
        out.text
    );
}

/// Like [`rescue_transport`] but parameterized on the obligations body and
/// the prices `Date` header. `MockTransport::fetch` takes the *first*
/// matching route, so an extra `.route("/obligations", …)` on top of
/// `happy_transport()` would be ignored — these have to be built in order.
fn transport_with(obligations: String, date: &str) -> MockTransport {
    MockTransport::new()
        .route_dated("/oracles/prices", 200, PRICES_JSON, date)
        .route("/obligations", 200, obligations)
        .route("/reserves/metrics", 200, RESERVES_METRICS_JSON)
        .route("/reserves/account-data", 200, account_data_body())
        .route("getGenesisHash", 200, genesis_response(MAINNET_GENESIS))
        .route("getLatestBlockhash", 200, blockhash_response())
        .route("getTokenAccountBalance", 200, balance_response(1_000_000.0))
}

/// The two transaction paths carry the same stale-price warning `check`
/// does.
///
/// They previously hard-coded an empty stale list, so `render_rescue`'s
/// freshness channel was dead on exactly the outputs that move money — a
/// repay sized from a year-old oracle printed as a confident number with no
/// warning at all. The prices that decide staleness are the same prices that
/// size the amount.
#[test]
fn transaction_paths_warn_on_stale_prices() {
    for (action, cap) in [("rescue", "max_repay_ui"), ("deposit", "max_deposit_ui")] {
        let mut t = transport_with(OBLIGATIONS_JSON.to_string(), FAR_FUTURE_DATE);
        let args = serde_json::json!({
            "action": action,
            "wallet": WALLET,
            "__config": { cap: "100000" },
        })
        .to_string();
        let out = run(&args, &mut t);
        assert!(out.success, "{action}: expected success, got: {}", out.text);
        assert!(
            out.text.contains("STALE DATA:"),
            "{action}: built a transaction off stale prices with no warning: {}",
            out.text
        );
    }
}

/// The obligation the API returns is bound to the configured wallet locally.
///
/// `/obligations` is already wallet-scoped, so this only fires when the
/// response disagrees with the request — but every transaction built
/// downstream spends *this* wallet's tokens into *that* obligation, so a
/// response naming someone else's position must never become a transaction.
/// `state.owner` was parsed and read nowhere before this.
#[test]
fn foreign_owner_obligation_is_never_a_candidate() {
    const FOREIGN: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    let mut obligations: serde_json::Value = serde_json::from_str(OBLIGATIONS_JSON).unwrap();
    for row in obligations.as_array_mut().unwrap() {
        row["state"]["owner"] = serde_json::Value::String(FOREIGN.to_string());
    }
    let body = obligations.to_string();

    let mut t = transport_with(body.clone(), FRESH_DATE);
    let out = run(&check_args(serde_json::json!({})), &mut t);
    assert!(
        !out.success,
        "check accepted an obligation the wallet does not own: {}",
        out.text
    );

    let mut t = transport_with(body, FRESH_DATE);
    let args = serde_json::json!({
        "action": "rescue",
        "wallet": WALLET,
        "__config": { "max_repay_ui": "100000" },
    })
    .to_string();
    let out = run(&args, &mut t);
    assert!(
        !out.success,
        "rescue accepted an obligation the wallet does not own: {}",
        out.text
    );
    assert!(
        !out.text.contains("tx (base64):"),
        "built a transaction into a foreign obligation: {}",
        out.text
    );
}

/// v11-priority-fee: end to end, a `priority_fee_microlamports` config
/// value produces both the report line and a tx whose first two
/// instructions are the compute-budget ixs.
#[test]
fn rescue_priority_fee_applied() {
    let mut t = happy_transport();
    let cfg = serde_json::json!({
        "max_repay_ui": "100000",
        "priority_fee_microlamports": "10000",
    });
    let out = run(&rescue_args(cfg, serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text
            .contains("priority fee: 10000 microlamports/CU (compute limit"),
        "missing priority fee line: {}",
        out.text
    );

    let tx_line = out
        .text
        .lines()
        .find(|l| l.starts_with("tx (base64):"))
        .expect("missing tx line");
    let b64 = tx_line.trim_start_matches("tx (base64):").trim();
    let wire = liquidation_guard::rescue::base64_decode(b64).expect("tx must decode as base64");

    let mut pos = 0;
    let sig_count = read_compact_u16(&wire, &mut pos);
    assert_eq!(sig_count, 1);
    pos += 64; // zeroed signature slot
    pos += 3; // header (num_required_signatures, num_readonly_signed, num_readonly_unsigned)
    let key_count = read_compact_u16(&wire, &mut pos) as usize;
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        keys.push(bs58::encode(&wire[pos..pos + 32]).into_string());
        pos += 32;
    }
    pos += 32; // blockhash

    let ix_count = read_compact_u16(&wire, &mut pos);
    assert!(
        ix_count >= 2,
        "expected at least 2 leading compute-budget ixs, got {ix_count}"
    );

    let (program0, data0) = read_ix(&wire, &mut pos, &keys);
    assert_eq!(program0, "ComputeBudget111111111111111111111111111111");
    assert_eq!(data0[0], 2, "ix 0 must be SetComputeUnitLimit");

    let (program1, data1) = read_ix(&wire, &mut pos, &keys);
    assert_eq!(program1, "ComputeBudget111111111111111111111111111111");
    assert_eq!(data1[0], 3, "ix 1 must be SetComputeUnitPrice");
    assert_eq!(
        u64::from_le_bytes(data1[1..9].try_into().unwrap()),
        10_000,
        "SetComputeUnitPrice payload must carry the configured fee"
    );
}

/// v11-durable-nonce: any valid base58 32-byte pubkey works as the
/// configured nonce account — this test never reads/writes a real
/// on-chain account, `MockTransport` serves the `getAccountInfo` response.
const NONCE_ACCOUNT: &str = "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD";
/// Another valid base58 32-byte pubkey, used as the synthesized nonce
/// account's stored durable-nonce value.
const STORED_NONCE_VALUE: &str = CBBTC_RESERVE;
const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// Builds the `getAccountInfo` JSON-RPC response body for a synthesized,
/// valid 80-byte system-nonce-account blob owned by the system program,
/// with `authority` as its authority and `stored_value` (base58) as its
/// stored durable-nonce value.
fn nonce_account_info_body(authority: &str, stored_value: &str) -> String {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(&1u32.to_le_bytes()); // version
    data.extend_from_slice(&1u32.to_le_bytes()); // state: initialized
    data.extend_from_slice(&bs58::decode(authority).into_vec().unwrap());
    data.extend_from_slice(&bs58::decode(stored_value).into_vec().unwrap());
    data.extend_from_slice(&5000u64.to_le_bytes());
    let b64 = liquidation_guard::rescue::base64_encode(&data);
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"owner":"{SYSTEM_PROGRAM_ID}","lamports":1000000,"data":["{b64}","base64"],"executable":false,"rentEpoch":0}}}}}}"#
    )
}

/// v11-durable-nonce: end to end, a `nonce_account` config value skips
/// `getLatestBlockhash` entirely, reads the nonce account via
/// `getAccountInfo`, and produces both the report line and a tx whose
/// first instruction is `AdvanceNonceAccount` with the message blockhash
/// stamped to the account's stored nonce value.
#[test]
fn rescue_nonce_account_applied() {
    let mut t = happy_transport().route(
        "getAccountInfo",
        200,
        nonce_account_info_body(WALLET, STORED_NONCE_VALUE),
    );
    let cfg = serde_json::json!({
        "max_repay_ui": "100000",
        "nonce_account": NONCE_ACCOUNT,
    });
    let out = run(&rescue_args(cfg, serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text.contains(&format!(
            "durable nonce: {NONCE_ACCOUNT} (transaction does not expire until the nonce advances)"
        )),
        "missing durable nonce report line: {}",
        out.text
    );
    assert_eq!(
        t.count("getLatestBlockhash"),
        0,
        "nonce configured: getLatestBlockhash must never be called, log: {:?}",
        t.log
    );

    let tx_line = out
        .text
        .lines()
        .find(|l| l.starts_with("tx (base64):"))
        .expect("missing tx line");
    let b64 = tx_line.trim_start_matches("tx (base64):").trim();
    let wire = liquidation_guard::rescue::base64_decode(b64).expect("tx must decode as base64");

    let mut pos = 0;
    let sig_count = read_compact_u16(&wire, &mut pos);
    assert_eq!(sig_count, 1);
    pos += 64; // zeroed signature slot
    pos += 3; // header
    let key_count = read_compact_u16(&wire, &mut pos) as usize;
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        keys.push(bs58::encode(&wire[pos..pos + 32]).into_string());
        pos += 32;
    }
    let blockhash = bs58::encode(&wire[pos..pos + 32]).into_string();
    assert_eq!(
        blockhash, STORED_NONCE_VALUE,
        "message blockhash must be the stored nonce value"
    );
    pos += 32;

    let ix_count = read_compact_u16(&wire, &mut pos);
    assert!(ix_count >= 1, "expected at least the advance-nonce ix");
    let (program0, data0) = read_ix(&wire, &mut pos, &keys);
    assert_eq!(
        program0, SYSTEM_PROGRAM_ID,
        "ix 0 must be the system program (AdvanceNonceAccount)"
    );
    assert_eq!(data0, vec![4, 0, 0, 0], "ix 0 data must be u32 LE tag 4");
}

fn read_compact_u16(bytes: &[u8], pos: &mut usize) -> u16 {
    let mut n: u16 = 0;
    let mut shift = 0;
    loop {
        let byte = bytes[*pos];
        *pos += 1;
        n |= ((byte & 0x7f) as u16) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    n
}

/// Reads one instruction (program id, ix data) out of a decoded legacy-tx
/// message at `*pos`, advancing `*pos` past it.
fn read_ix(wire: &[u8], pos: &mut usize, keys: &[String]) -> (String, Vec<u8>) {
    let program_idx = wire[*pos] as usize;
    *pos += 1;
    let acc_count = read_compact_u16(wire, pos) as usize;
    *pos += acc_count; // account indexes, one byte each
    let data_len = read_compact_u16(wire, pos) as usize;
    let data = wire[*pos..*pos + data_len].to_vec();
    *pos += data_len;
    (keys[program_idx].clone(), data)
}

#[test]
fn amount_capping() {
    let mut t = happy_transport();
    let cfg = serde_json::json!({ "max_repay_ui": "1" });
    let extra = serde_json::json!({ "repay_ui_amount": 1000.0 });
    let out = run(&rescue_args(cfg, extra), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text.contains("capped by max_repay_ui"),
        "expected cap note: {}",
        out.text
    );
}

#[test]
fn non_200_reported_once() {
    let mut t = MockTransport::new().route("/obligations", 429, r#"{"error":"rate limited"}"#);
    let out = run(&check_args(serde_json::json!({})), &mut t);
    assert!(!out.success);
    assert_eq!(
        t.count("/obligations"),
        1,
        "expected exactly one attempt, log: {:?}",
        t.log
    );
}

#[test]
fn portfolio_happy_path() {
    let mut t = happy_transport();
    let out = run(&portfolio_args(serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text.contains("snapshot:"),
        "missing snapshot line: {}",
        out.text
    );
}

/// harden F6: a `prev_snapshot` decoded successfully but taken from a
/// *different* obligation must never be diffed against the fixture's real
/// obligation — it degrades to "no prior snapshot", same as any garbled
/// input, never a spurious `PARAM ALERT`/`Drift` line. The snapshot below
/// is deliberately built to trigger both lines (a changed `liq_ltv` and
/// `elevation_group`, plus a `collateral_price` within 1% of the real one)
/// if it were wrongly accepted.
#[test]
fn mismatched_obligation_snapshot_ignored() {
    let foreign = encode_snapshot(&Snapshot {
        v: 1,
        obligation: "SomeOtherObligation1111111111111111111111".to_string(),
        ltv: 0.5,
        liq_ltv: 0.5, // real fixture liq_ltv is ~0.799 -> would param-alert
        collateral_price: 64_673.0, // within 1% of the real ~64673.91 price
        elevation_group: 7, // real fixture is 0 -> would param-alert
        taken_unix: 1,
    });
    let mut t = happy_transport();
    let args = serde_json::json!({
        "action": "check",
        "wallet": WALLET,
        "prev_snapshot": foreign,
        "__config": {},
    })
    .to_string();
    let out = run(&args, &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        !out.text.contains("PARAM ALERT"),
        "cross-obligation snapshot must never produce a PARAM ALERT: {}",
        out.text
    );
    assert!(
        !out.text.contains("Drift since"),
        "cross-obligation snapshot must never produce a drift line: {}",
        out.text
    );
}

/// fx-lst-sol-level (ruling A): a collateral mint in the pinned LST table
/// (`src/guard.rs::PINNED_LST_MINTS`) gets its forecast quoted at the
/// underlying SOL level, via `stake_rate = lst_price_usd / sol_price_usd`
/// from the *same* `/oracles/prices` response — never a payload
/// name/symbol match (safety invariant 6). Synthesizes an LST-collateral
/// obligation from the committed fixtures: the real obligation's dominant
/// deposit (cbBTC) is retargeted at the JitoSOL reserve that's already
/// present in `reserves_metrics.json`/`prices.json`, keeping its
/// `marketValueSf` so it's still the dominant deposit.
///
/// Proves two things: end-to-end wiring (`guard::run` renders the
/// "(underlying SOL level via stake rate)" annotation), and the exact math
/// — the quoted level on both forecast lines equals `forecast_price /
/// stake_rate` within 1e-6, computed independently via the public
/// `kamino`/`health` APIs against the same synthesized facts (never
/// re-deriving the number from the rendered/rounded display text).
#[test]
fn lst_forecast_quotes_sol_level() {
    const CBBTC_DEPOSIT_RESERVE: &str = "37Jk2zkz23vkAYBT66HM2gaqJuNg2nYLsCreQAVt5MWK";
    const JITOSOL_RESERVE: &str = "EVbyPKrHG6WBfm4dLxLMJpUDY43cCAcHSpV3KYjKsktW";
    const JITOSOL_MINT: &str = "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn";
    const SOL_MINT: &str = "So11111111111111111111111111111111111111112";
    const USDG_MINT: &str = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH";

    let mut obligations_value: serde_json::Value = serde_json::from_str(OBLIGATIONS_JSON).unwrap();
    for d in obligations_value[0]["state"]["deposits"]
        .as_array_mut()
        .unwrap()
    {
        if d["depositReserve"] == CBBTC_DEPOSIT_RESERVE {
            d["depositReserve"] = serde_json::json!(JITOSOL_RESERVE);
        }
    }
    let obligations_body = obligations_value.to_string();

    let mut t = MockTransport::new()
        .route_dated("/oracles/prices", 200, PRICES_JSON, FRESH_DATE)
        .route("/obligations", 200, obligations_body.clone())
        .route("/reserves/metrics", 200, RESERVES_METRICS_JSON);
    let out = run(&check_args(serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text.contains("(underlying SOL level via stake rate)"),
        "missing SOL-level annotation: {}",
        out.text
    );

    // Independently recompute the exact math on the same synthesized facts
    // via the public kamino/health APIs.
    use liquidation_guard::health::{self, PositionFacts, Thresholds};
    use liquidation_guard::kamino::{parse_obligations, parse_prices, parse_reserves_metrics};

    let obligation = parse_obligations(&obligations_body)
        .expect("obligations parse")
        .remove(0);
    let prices = parse_prices(PRICES_JSON).expect("prices parse");
    let metrics = parse_reserves_metrics(RESERVES_METRICS_JSON).expect("metrics parse");

    let jitosol_price = prices
        .iter()
        .find(|p| p.mint == JITOSOL_MINT)
        .unwrap()
        .price;
    let sol_price = prices.iter().find(|p| p.mint == SOL_MINT).unwrap().price;
    let stake_rate = jitosol_price / sol_price;
    let debt_price = prices.iter().find(|p| p.mint == USDG_MINT).unwrap().price;
    assert!(
        metrics.iter().any(|m| m.mint == USDG_MINT),
        "USDG reserve missing from the metrics fixture"
    );

    let facts = PositionFacts {
        ltv: obligation.ltv,
        liq_ltv: obligation.liq_ltv,
        borrow_usd: obligation.borrow_usd,
        deposit_usd: obligation.deposit_usd,
        collateral_symbol: "JITOSOL".to_string(),
        debt_symbol: "USDG".to_string(),
        collateral_price: jitosol_price,
        debt_price,
        lst_stake_rate: Some(stake_rate),
        multi_volatile_collateral: obligation.deposits.len() > 1,
        elevation_group: obligation.elevation_group,
        adl_assets: Vec::new(),
        position_value_usd: obligation.deposit_usd,
        min_full_liquidation_value_usd: obligation.min_full_liquidation_value_usd,
        borrow_apy: None,
        utilization: None,
    };
    let thresholds = Thresholds {
        watch: 0.25,
        warn: 0.15,
        critical: 0.07,
    };
    let health_report = health::assess(&facts, None, &thresholds);
    assert!(
        (health_report.sol_spot_price.unwrap() - sol_price).abs() < 1e-6,
        "SOL spot must be the real SOL oracle price: got {:?}, expected {sol_price}",
        health_report.sol_spot_price
    );

    // Collateral-drop converts to the SOL level; debt-rise stays in the
    // debt asset's own price (DEFECT-1: it was divided by the collateral's
    // stake rate, which is dimensionally unrelated to a USDG threshold).
    let expected_collateral_drop = (jitosol_price * facts.ltv / facts.liq_ltv) / stake_rate;
    let expected_debt_rise = debt_price * facts.liq_ltv / facts.ltv;
    assert!(
        (health_report.liq_price_collateral_drop.unwrap() - expected_collateral_drop).abs() < 1e-6,
        "collateral-drop forecast mismatch: got {:?}, expected {}",
        health_report.liq_price_collateral_drop,
        expected_collateral_drop
    );
    assert!(
        (health_report.liq_price_debt_rise.unwrap() - expected_debt_rise).abs() < 1e-6,
        "debt-rise forecast mismatch: got {:?}, expected {}",
        health_report.liq_price_debt_rise,
        expected_debt_rise
    );

    // End-to-end denomination check on the RENDERED text: the SOL-level
    // line's own "now" value must be the SOL spot, never the JitoSOL spot.
    let sol_line = out
        .text
        .lines()
        .find(|l| l.contains("(underlying SOL level via stake rate)"))
        .expect("SOL-level forecast line present");
    assert!(
        sol_line.contains("Liquidated if SOL <"),
        "SOL-level line must be quoted in SOL, not the LST symbol: {sol_line}"
    );
    assert!(
        sol_line.contains(&format!("(now ${sol_price:.2},")),
        "SOL-level line must quote the SOL spot ${sol_price:.2}: {sol_line}"
    );
    assert_eq!(
        out.text
            .lines()
            .filter(|l| l.contains("(underlying SOL level via stake rate)"))
            .count(),
        1,
        "only the collateral line may be SOL-annotated:\n{}",
        out.text
    );
}

/// harden F7: when the wallet-balance read is the binding constraint, the
/// rescue output truthfully labels it `capped by balance` (not
/// `"computed"`) and adds the plain warning that the repay does not restore
/// the WATCH boundary.
#[test]
fn balance_cap_labeled_and_warned() {
    let mut t = rescue_transport(1.0);
    let cfg = serde_json::json!({ "max_repay_ui": "100000" });
    let out = run(&rescue_args(cfg, serde_json::json!({})), &mut t);
    assert!(out.success, "expected success, got: {}", out.text);
    assert!(
        out.text.contains("capped by balance"),
        "expected balance cap label: {}",
        out.text
    );
    assert!(
        out.text.contains("does NOT restore the WATCH boundary"),
        "expected balance-cap warning line: {}",
        out.text
    );
}

/// The three actions must not contradict each other about the same position.
///
/// When `liquidationLtv` is zero with debt outstanding — the state `check`
/// calls CRITICAL — the target LTV `t` is zero, so `remedy::rank` omits the
/// deposit remedy (no amount of a zero-threshold collateral moves the buffer).
/// `run_deposit` then found no deposit remedy and reported "position is
/// already healthy at/above the WATCH threshold", the opposite of the truth,
/// while `check` said CRITICAL and `rescue` still built a repay tx.
#[test]
fn deposit_never_reports_healthy_for_a_critical_position() {
    let mut obligations: serde_json::Value = serde_json::from_str(OBLIGATIONS_JSON).unwrap();
    obligations[0]["refreshedStats"]["liquidationLtv"] = serde_json::Value::String("0".to_string());
    let body = obligations.to_string();

    // check: CRITICAL.
    let mut t = transport_with(body.clone(), FRESH_DATE);
    let check = run(&check_args(serde_json::json!({})), &mut t);
    assert!(check.success, "check failed: {}", check.text);
    assert!(
        check.text.starts_with("CRITICAL"),
        "expected a CRITICAL verdict, got: {}",
        check.text
    );

    // deposit: must refuse, and must NOT claim the position is healthy.
    let mut t = transport_with(body, FRESH_DATE);
    let args = serde_json::json!({
        "action": "deposit",
        "wallet": WALLET,
        "__config": { "max_deposit_ui": "100000" },
    })
    .to_string();
    let deposit = run(&args, &mut t);
    assert!(
        !deposit.text.contains("already healthy"),
        "deposit called a CRITICAL position healthy: {}",
        deposit.text
    );
    assert!(
        !deposit.text.contains("tx (base64):"),
        "a zero-threshold collateral cannot be a remedy, so no tx may be built: {}",
        deposit.text
    );
}
