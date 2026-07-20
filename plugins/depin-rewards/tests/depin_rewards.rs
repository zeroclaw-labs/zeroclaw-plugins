// depin-rewards host integration tests over the pure core (MockHttp).
//
// Slice A (RED → GREEN): `HttpClient` trait dispatch + `MockHttp` scripted
// responses + `HttpError` / `RewardsError` variants. Drives the minimal API in
// src/depin_rewards.rs. Subsequent slices add config / Relay fetch / watch /
// claim-tx tests.
//
// Import path = `<crate>::<module>::*` = `depin_rewards::depin_rewards::*`
// (crate `depin-rewards` → lib `depin_rewards`; module `depin_rewards`).
use depin_rewards::depin_rewards::{
  do_status, do_summary, do_watch, enforce_hotspot_allowlist, fetch_hotspot, fetch_rewards,
  format_amount, HttpError, HttpClient, HotspotInfo, MockHttp, RewardSummary,
  RewardsConfig, RewardsError, send_telegram,
};
use std::collections::HashMap;

#[test]
fn mock_http_get_returns_scripted() {
  // A scripted GET response is returned verbatim for the registered URL.
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/abc".to_string(),
    b"{\"owner\":\"base58pk\"}".to_vec(),
  );

  let h: &dyn HttpClient = &mock;
  let body = h
    .get(
      "https://api.relaywireless.com/v1/helium/l2/hotspots/abc",
      "Bearer test-key",
    )
    .expect("registered GET must return its scripted body");

  assert_eq!(body, b"{\"owner\":\"base58pk\"}");
}

#[test]
fn mock_http_get_unregistered_is_err() {
  // An unregistered URL fails closed — never silently returns empty.
  let mock = MockHttp::new();
  let h: &dyn HttpClient = &mock;
  let res = h.get("https://unregistered.example/", "Bearer x");
  assert!(res.is_err(), "GET on an unregistered URL must error");
}

#[test]
fn mock_http_post_records_call_and_returns_scripted() {
  // post_form records (url, fields) for later assertion AND returns the
  // scripted response body (e.g. a Telegram sendMessage ack).
  let mut mock = MockHttp::new();
  mock.set_post(
    "https://api.telegram.org/bot<TOKEN>/sendMessage".to_string(),
    b"{\"ok\":true}".to_vec(),
  );

  let h: &dyn HttpClient = &mock;
  let fields = vec![
    ("chat_id".to_string(), "123456".to_string()),
    ("text".to_string(), "offline!".to_string()),
  ];
  let resp = h
    .post_form("https://api.telegram.org/bot<TOKEN>/sendMessage", &fields)
    .expect("registered POST must return its scripted body");
  assert_eq!(resp, b"{\"ok\":true}");

  let posts = mock.posts();
  assert_eq!(posts.len(), 1, "exactly one POST recorded");
  assert_eq!(posts[0].0, "https://api.telegram.org/bot<TOKEN>/sendMessage");
  assert_eq!(posts[0].1.len(), 2);
  assert_eq!(posts[0].1[0].0, "chat_id");
  assert_eq!(posts[0].1[1].1, "offline!");
}

#[test]
fn http_client_is_object_safe() {
  // The trait must be usable as `&dyn HttpClient` (dynamic dispatch) — the
  // pure core takes `&dyn HttpClient` so the shim can swap MockHttp (host
  // tests) for a real waki impl (wasm) without touching call sites.
  fn run_through(h: &dyn HttpClient) {
    let _ = h.get("https://x/", "Bearer y");
    let _ = h.post_form("https://x/", &[]);
  }
  let mock = MockHttp::new();
  run_through(&mock);
}

#[test]
fn http_error_variants_debug() {
  // Errors are specific + traceable (Debug) — never opaque.
  let e = HttpError::Status(404, "hotspot not found".to_string());
  let s = format!("{e:?}");
  assert!(s.contains("404"), "Debug must carry the status code");
  assert!(s.contains("hotspot not found"));
}

#[test]
fn rewards_error_variants_debug() {
  // The top-level error enum carries actionable, specific messages.
  let cfg = RewardsError::Config("missing required key: relay_api_key".to_string());
  assert!(format!("{cfg:?}").contains("relay_api_key"));

  let relay = RewardsError::Relay("402 quota exhausted".to_string());
  assert!(format!("{relay:?}").contains("402"));

  // Http wraps the transport error.
  let http = RewardsError::Http(HttpError::Status(429, "too many requests".to_string()));
  let h = format!("{http:?}");
  assert!(h.contains("429"));
}

// ── Slice B: RewardsConfig::from_section + enforce_hotspot_allowlist ──────────

fn cfg(keys: &[(&str, &str)]) -> HashMap<String, String> {
  keys
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

#[test]
fn config_valid_minimal() {
  let c = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"ecc-1\"]"),
    ("telegram_bot_token", "tgk"),
    ("telegram_chat_id", "123"),
  ]))
  .expect("valid minimal config");
  assert_eq!(c.relay_api_key, "rk");
  assert_eq!(c.hotspots, vec!["ecc-1".to_string()]);
  assert_eq!(c.telegram_bot_token, "tgk");
  assert_eq!(c.telegram_chat_id, "123");
}

#[test]
fn config_defaults_applied() {
  let c = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"a\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap();
  assert_eq!(c.relay_base_url, "https://api.relaywireless.com/v1");
  assert_eq!(c.poll_interval_minutes, 120);
  assert_eq!(c.network, "mainnet-beta");
}

#[test]
fn config_hotspots_json_array_parses() {
  let c = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"a\",\"b\",\"c\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap();
  assert_eq!(
    c.hotspots,
    vec!["a".to_string(), "b".to_string(), "c".to_string()]
  );
}

#[test]
fn config_overrides_applied() {
  let c = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"a\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
    ("relay_base_url", "https://custom.example/v2"),
    ("poll_interval_minutes", "30"),
    ("network", "devnet"),
  ]))
  .unwrap();
  assert_eq!(c.relay_base_url, "https://custom.example/v2");
  assert_eq!(c.poll_interval_minutes, 30);
  assert_eq!(c.network, "devnet");
}

#[test]
fn config_empty_section_fails_closed() {
  let m: HashMap<String, String> = HashMap::new();
  let err = RewardsConfig::from_section(&m).unwrap_err();
  assert!(matches!(err, RewardsError::Config(_)));
  assert!(format!("{err:?}").contains("not configured"));
}

#[test]
fn config_missing_relay_api_key() {
  let err = RewardsConfig::from_section(&cfg(&[
    ("hotspots", "[\"a\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap_err();
  assert!(format!("{err:?}").contains("relay_api_key"));
}

#[test]
fn config_empty_relay_api_key_treated_as_missing() {
  // An empty string is treated as missing (fail closed).
  let err = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", ""),
    ("hotspots", "[\"a\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap_err();
  assert!(format!("{err:?}").contains("relay_api_key"));
}

#[test]
fn config_missing_hotspots() {
  let err = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap_err();
  assert!(format!("{err:?}").contains("hotspots"));
}

#[test]
fn config_hotspots_malformed_json() {
  let err = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "a,b,c"), // not a JSON array
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap_err();
  assert!(format!("{err:?}").contains("hotspots"));
}

#[test]
fn config_hotspots_empty_array() {
  let err = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap_err();
  assert!(format!("{err:?}").contains("hotspots"));
}

#[test]
fn config_missing_telegram_bot_token() {
  let err = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"a\"]"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap_err();
  assert!(format!("{err:?}").contains("telegram_bot_token"));
}

#[test]
fn config_missing_telegram_chat_id() {
  let err = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"a\"]"),
    ("telegram_bot_token", "t"),
  ]))
  .unwrap_err();
  assert!(format!("{err:?}").contains("telegram_chat_id"));
}

#[test]
fn config_bad_network_rejected() {
  let err = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"a\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
    ("network", "testnet"),
  ]))
  .unwrap_err();
  assert!(format!("{err:?}").contains("network"));
}

#[test]
fn config_bad_poll_interval_rejected() {
  let err = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"a\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
    ("poll_interval_minutes", "not-a-number"),
  ]))
  .unwrap_err();
  assert!(format!("{err:?}").contains("poll_interval_minutes"));
}

#[test]
fn allowlist_allows_configured_hotspot() {
  let c = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"ecc-1\",\"ecc-2\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap();
  assert!(enforce_hotspot_allowlist(&c, "ecc-1").is_ok());
  assert!(enforce_hotspot_allowlist(&c, "ecc-2").is_ok());
}

#[test]
fn allowlist_rejects_unknown_hotspot() {
  let c = RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"ecc-1\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap();
  let err = enforce_hotspot_allowlist(&c, "evil-id").unwrap_err();
  assert!(matches!(err, RewardsError::Config(_)));
  assert!(format!("{err:?}").contains("allowlist"));
}

// ── Slice C: HotspotInfo parse + fetch_hotspot + do_status ───────────────────

const HOTSPOT_IOT_ONLINE: &str = include_str!("fixtures/hotspot-iot-online.json");

fn base_cfg() -> RewardsConfig {
  RewardsConfig::from_section(&cfg(&[
    ("relay_api_key", "rk"),
    ("hotspots", "[\"ecc-1\"]"),
    ("telegram_bot_token", "t"),
    ("telegram_chat_id", "1"),
  ]))
  .unwrap()
}

#[test]
fn hotspot_info_parses_fixture() {
  let info = HotspotInfo::parse(HOTSPOT_IOT_ONLINE.as_bytes()).expect("fixture parses");
  assert_eq!(info.owner, "BcJzP2hEYgzjUwpHEtS6RhuqGfEJVx8Rq3MejujAAWrR");
  assert_eq!(info.name, "tall-plum-ocelot");
  assert_eq!(info.networks, vec!["iot".to_string()]);
  assert_eq!(info.iot_is_active, Some(true));
  assert_eq!(info.mobile_is_active, Some(false));
  assert_eq!(info.iot_location, Some(631842973910616063));
  assert_eq!(info.maker_name.as_deref(), Some("SenseCAP"));
}

#[test]
fn hotspot_info_is_active_reduction() {
  let mk = |iot: Option<bool>, mob: Option<bool>| HotspotInfo {
    owner: "BcJzP2hEYgzjUwpHEtS6RhuqGfEJVx8Rq3MejujAAWrR".into(),
    name: "x".into(),
    networks: vec![],
    iot_is_active: iot,
    mobile_is_active: mob,
    iot_location: None,
    maker_name: None,
  };
  // active if ANY joined network reports active
  assert_eq!(mk(Some(true), Some(false)).is_active(), Some(true));
  assert_eq!(mk(Some(false), Some(true)).is_active(), Some(true));
  assert_eq!(mk(Some(true), None).is_active(), Some(true));
  assert_eq!(mk(None, Some(true)).is_active(), Some(true));
  // inactive only if all known networks inactive
  assert_eq!(mk(Some(false), Some(false)).is_active(), Some(false));
  assert_eq!(mk(Some(false), None).is_active(), Some(false));
  assert_eq!(mk(None, Some(false)).is_active(), Some(false));
  // unknown only if both unknown
  assert_eq!(mk(None, None).is_active(), None);
}

#[test]
fn hotspot_info_primary_network() {
  let info = HotspotInfo::parse(HOTSPOT_IOT_ONLINE.as_bytes()).unwrap();
  assert_eq!(info.primary_network(), "iot");
}

#[test]
fn fetch_hotspot_200_returns_info() {
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/ecc-1".to_string(),
    HOTSPOT_IOT_ONLINE.as_bytes().to_vec(),
  );
  let cfg = base_cfg();
  let info = fetch_hotspot(&mock, &cfg, "ecc-1").expect("200 fetch");
  assert_eq!(info.name, "tall-plum-ocelot");
  assert_eq!(info.iot_is_active, Some(true));
}

#[test]
fn fetch_hotspot_404_maps_to_relay_error() {
  let mut mock = MockHttp::new();
  mock.set_get_err(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/missing".to_string(),
    HttpError::Status(404, "not found".into()),
  );
  let cfg = base_cfg();
  let err = fetch_hotspot(&mock, &cfg, "missing").unwrap_err();
  assert!(matches!(err, RewardsError::Relay(_)));
  assert!(format!("{err:?}").contains("not found"));
}

#[test]
fn fetch_hotspot_402_maps_to_relay_quota() {
  let mut mock = MockHttp::new();
  mock.set_get_err(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/ecc-1".to_string(),
    HttpError::Status(402, "quota exhausted".into()),
  );
  let cfg = base_cfg();
  let err = fetch_hotspot(&mock, &cfg, "ecc-1").unwrap_err();
  assert!(matches!(err, RewardsError::Relay(_)));
  assert!(format!("{err:?}").contains("quota") || format!("{err:?}").contains("402"));
}

#[test]
fn do_status_online_shape() {
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/ecc-1".to_string(),
    HOTSPOT_IOT_ONLINE.as_bytes().to_vec(),
  );
  let cfg = base_cfg();
  let out = do_status(&mock, &cfg, "ecc-1").expect("status ok");
  assert_eq!(out.is_active, Some(true));
  assert!(out.summary.contains("ONLINE"), "summary: {}", out.summary);
  assert!(out.summary.contains("tall-plum-ocelot"));
  // ≤200 tokens (chars/4) and ≤800 chars (SPEC-3 §7)
  assert!(out.summary.len() <= 800, "summary too long: {} chars", out.summary.len());
  assert!(out.summary.len() / 4 <= 200);
}

#[test]
fn do_status_rejects_unknown_hotspot() {
  let mock = MockHttp::new();
  let cfg = base_cfg();
  let err = do_status(&mock, &cfg, "evil-id").unwrap_err();
  assert!(matches!(err, RewardsError::Config(_)));
  assert!(format!("{err:?}").contains("allowlist"));
}

// ── Slice D: RewardSummary + fetch_rewards + do_summary ───────────────────────

const REWARD_TOTALS: &str = r#"{"total_beacon_amount":1100000,"total_witness_amount":2200000,"total_dc_transfer_amount":120000,"total_amount":3420000}"#;

#[test]
fn reward_summary_parses_totals() {
  let s = RewardSummary::parse_totals(
    REWARD_TOTALS.as_bytes(),
    "2026-07-20T00:00:00Z",
    "2026-07-20T17:00:00Z",
  )
  .unwrap();
  assert_eq!(s.total_amount, 3_420_000);
  assert_eq!(s.beacon_amount, 1_100_000);
  assert_eq!(s.witness_amount, 2_200_000);
  assert_eq!(s.dc_transfer_amount, 120_000);
  assert_eq!(s.from_iso, "2026-07-20T00:00:00Z");
}

#[test]
fn fetch_rewards_200_returns_summary() {
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/iot-reward-shares/totals\
?from=2026-07-20T00:00:00Z&to=2026-07-20T17:00:00Z&hotspot_key=ecc-1"
      .to_string(),
    REWARD_TOTALS.as_bytes().to_vec(),
  );
  let cfg = base_cfg();
  let s = fetch_rewards(
    &mock,
    &cfg,
    "iot",
    "ecc-1",
    "2026-07-20T00:00:00Z",
    "2026-07-20T17:00:00Z",
  )
  .unwrap();
  assert_eq!(s.total_amount, 3_420_000);
}

#[test]
fn format_amount_rounds_to_2dp() {
  assert_eq!(format_amount(3_420_000, 6), "3.42");
  assert_eq!(format_amount(0, 6), "0.00");
  assert_eq!(format_amount(1_234_567, 6), "1.23");
  assert_eq!(format_amount(1_500_000, 6), "1.50");
  assert_eq!(format_amount(999_999, 6), "1.00"); // 0.999999 rounds up
  assert_eq!(format_amount(5_000_000, 6), "5.00");
}

#[test]
fn do_summary_shape_contains_amount_and_name() {
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/ecc-1".to_string(),
    HOTSPOT_IOT_ONLINE.as_bytes().to_vec(),
  );
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/iot-reward-shares/totals\
?from=f&to=t&hotspot_key=ecc-1"
      .to_string(),
    REWARD_TOTALS.as_bytes().to_vec(),
  );
  let cfg = base_cfg();
  let out = do_summary(&mock, &cfg, "ecc-1", "f", "t").unwrap();
  assert!(out.summary.contains("earned"), "summary: {}", out.summary);
  assert!(out.summary.contains("3.42"), "summary: {}", out.summary);
  assert!(out.summary.contains("tall-plum-ocelot"));
  assert!(out.summary.len() <= 800, "too long: {}", out.summary.len());
}

// ── Slice E: send_telegram + do_watch (the workhorse) ─────────────────────────

// Offline variant of the online fixture (iot+mobile both is_active=false).
const HOTSPOT_IOT_OFFLINE: &str = r#"{"owner":"BcJzP2hEYgzjUwpHEtS6RhuqGfEJVx8Rq3MejujAAWrR","name":"tall-plum-ocelot","networks":["iot"],"iot_info":{"is_active":false,"location":123},"mobile_info":{"is_active":false}}"#;

const TG_OK: &str = r#"{"ok":true}"#;
const TG_URL: &str = "https://api.telegram.org/bott/sendMessage";

fn tg_mock_with_online_hotspot() -> MockHttp {
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/ecc-1".to_string(),
    HOTSPOT_IOT_ONLINE.as_bytes().to_vec(),
  );
  mock.set_post(TG_URL.to_string(), TG_OK.as_bytes().to_vec());
  mock
}

#[test]
fn send_telegram_ok_records_post() {
  let mut mock = MockHttp::new();
  mock.set_post(TG_URL.to_string(), TG_OK.as_bytes().to_vec());
  let cfg = base_cfg();
  send_telegram(&mock, &cfg, "offline!").expect("ok sends");
  let posts = mock.posts();
  let tg = posts.iter().find(|(u, _)| u == TG_URL).expect("POST recorded");
  assert!(tg.1.iter().any(|(k, v)| k == "chat_id" && v == "1"));
  assert!(tg.1.iter().any(|(k, v)| k == "text" && v == "offline!"));
}

#[test]
fn send_telegram_failure_returns_error() {
  let mut mock = MockHttp::new();
  mock.set_post(
    TG_URL.to_string(),
    r#"{"ok":false,"description":"chat not found"}"#.as_bytes().to_vec(),
  );
  let cfg = base_cfg();
  let err = send_telegram(&mock, &cfg, "x").unwrap_err();
  assert!(matches!(err, RewardsError::Telegram(_)));
  assert!(format!("{err:?}").contains("chat not found"));
}

#[test]
fn watch_no_flip_no_alert() {
  let mock = tg_mock_with_online_hotspot();
  let cfg = base_cfg();
  let out = do_watch(&mock, &cfg, "ecc-1", Some(true), false, "f", "t").unwrap();
  assert_eq!(out.is_active, Some(true));
  assert!(out.alerts_sent.is_empty(), "no alert expected");
  assert!(out.summary.contains("ONLINE"));
}

#[test]
fn watch_offline_flip_sends_alert() {
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/ecc-1".to_string(),
    HOTSPOT_IOT_OFFLINE.as_bytes().to_vec(),
  );
  mock.set_post(TG_URL.to_string(), TG_OK.as_bytes().to_vec());
  let cfg = base_cfg();
  let out = do_watch(&mock, &cfg, "ecc-1", Some(true), false, "f", "t").unwrap();
  assert_eq!(out.is_active, Some(false));
  assert_eq!(out.alerts_sent.len(), 1, "offline-flip alert expected");
  // the Telegram POST text contains OFFLINE
  let posts = mock.posts();
  let tg = posts
    .iter()
    .find(|(u, _)| u == TG_URL)
    .expect("telegram POST recorded");
  assert!(tg.1.iter().any(|(_, v)| v.contains("OFFLINE")));
  assert!(out.summary.len() <= 800);
}

#[test]
fn watch_first_tick_no_flip_even_if_offline() {
  // prev_active=None (first tick) → never fire a flip alert, even if currently offline.
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/ecc-1".to_string(),
    HOTSPOT_IOT_OFFLINE.as_bytes().to_vec(),
  );
  mock.set_post(TG_URL.to_string(), TG_OK.as_bytes().to_vec());
  let cfg = base_cfg();
  let out = do_watch(&mock, &cfg, "ecc-1", None, false, "f", "t").unwrap();
  assert!(out.alerts_sent.is_empty(), "first tick must not fire flip alert");
}

#[test]
fn watch_send_summary_sends_summary() {
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/ecc-1".to_string(),
    HOTSPOT_IOT_ONLINE.as_bytes().to_vec(),
  );
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/iot-reward-shares/totals\
?from=f&to=t&hotspot_key=ecc-1"
      .to_string(),
    REWARD_TOTALS.as_bytes().to_vec(),
  );
  mock.set_post(TG_URL.to_string(), TG_OK.as_bytes().to_vec());
  let cfg = base_cfg();
  let out = do_watch(&mock, &cfg, "ecc-1", Some(true), true, "f", "t").unwrap();
  // online (no flip) + summary requested → exactly the summary alert
  assert_eq!(out.alerts_sent.len(), 1);
  assert!(out.alerts_sent[0].contains("summary"));
}

#[test]
fn watch_flip_and_summary_both_sent() {
  let mut mock = MockHttp::new();
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/hotspots/ecc-1".to_string(),
    HOTSPOT_IOT_OFFLINE.as_bytes().to_vec(),
  );
  mock.set_get(
    "https://api.relaywireless.com/v1/helium/l2/iot-reward-shares/totals\
?from=f&to=t&hotspot_key=ecc-1"
      .to_string(),
    REWARD_TOTALS.as_bytes().to_vec(),
  );
  mock.set_post(TG_URL.to_string(), TG_OK.as_bytes().to_vec());
  let cfg = base_cfg();
  let out = do_watch(&mock, &cfg, "ecc-1", Some(true), true, "f", "t").unwrap();
  assert_eq!(out.alerts_sent.len(), 2, "flip + summary");
}

#[test]
fn watch_rejects_unknown_hotspot() {
  let mock = MockHttp::new();
  let cfg = base_cfg();
  let err = do_watch(&mock, &cfg, "evil-id", None, false, "f", "t").unwrap_err();
  assert!(matches!(err, RewardsError::Config(_)));
  assert!(format!("{err:?}").contains("allowlist"));
}
