//! Palinurus demo driver — rewards beat (chunks 2-5 of the recording guide).
//!
//! `cargo run --features demo --bin palinurus-demo -- [step]`
//!
//! Runs the *shipped* `depin-rewards` pure core over a real reqwest HTTP client
//! against live Relay (+ Telegram for `watch`). The logic is the tested plugin
//! core; this binary is glue (env -> config -> action -> printed line). It is
//! the on-camera harness for the Superteam demo video.
//!
//! Steps (match the recording-guide shot list):
//!   status   — chunk 2: hotspot online/offline now
//!   summary  — chunk 3: 30d rewards total + breakdown
//!   watch    — chunk 4: offline-flip -> REAL Telegram alert (needs real bot env)
//!   custody  — chunk 5: the no-signing-key custody one-liner
//!   all      — status + summary + custody (NO watch — safe smoke check; default)
//!
//! Env (the recording-guide pre-flight covers these):
//!   RELAY_API_KEY        (required)  free Relay Community key
//!   TELEGRAM_BOT_TOKEN   (watch)     @BotFather token; placeholder OK for non-watch
//!   TELEGRAM_CHAT_ID     (watch)     destination chat id; placeholder OK for non-watch
//!   HOTSPOT              (optional)  default = Fit Pine Capybara (the demo hotspot)
//!   RELAY_BASE_URL       (optional)  default https://api.relaywireless.com/v1
//!   NETWORK              (optional)  mainnet-beta | devnet
//!   FROM / TO            (optional)  ISO-8601 window for summary; default last 30d
//!
//! The attest beat (chunk 6) is a SEPARATE driver in plugins/depin-attest
//! (`depin-attest-demo`) — the two plugins are standalone [workspace] crates
//! and each carries its own demo driver. See the recording guide.

#![cfg(feature = "demo")]

use std::collections::HashMap;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use depin_rewards::demo_http::ReqwestHttp;
use depin_rewards::depin_rewards::{
  do_status, do_summary, do_watch, RewardsConfig, RewardsOutput,
};

const CAPYBARA: &str = "11bUUcCTeMYS4iqtf7DoQAEvmwswsZBSRc3Nt53aBQZ2ZYG8346";

fn env_or(key: &str, default: &str) -> String {
  env::var(key).unwrap_or_else(|_| default.to_string())
}

fn require_env(key: &str) -> String {
  env::var(key).unwrap_or_else(|_| {
    eprintln!("✗ missing required env: {key}");
    std::process::exit(2);
  })
}

/// Build the RewardsConfig the same way the WIT shim does — from a flat
/// string→string section — so the demo exercises the real config-validation
/// path (fail-closed on missing/malformed keys).
fn build_cfg() -> RewardsConfig {
  let relay_api_key = require_env("RELAY_API_KEY");
  // Telegram is only USED by `watch`, but from_section requires the keys
  // non-empty (it validates the whole section). Placeholder is fine for the
  // read-only steps; `watch` will fail loudly at the Telegram call if unset.
  let telegram_bot_token = env_or("TELEGRAM_BOT_TOKEN", "NOT_SET_PLACEHOLDER");
  let telegram_chat_id = env_or("TELEGRAM_CHAT_ID", "0");
  let hotspots = env_or("HOTSPOT", CAPYBARA);
  let relay_base_url = env_or("RELAY_BASE_URL", "https://api.relaywireless.com/v1");
  let network = env_or("NETWORK", "mainnet-beta");

  let mut section = HashMap::new();
  section.insert("relay_api_key".to_string(), relay_api_key);
  section.insert("telegram_bot_token".to_string(), telegram_bot_token);
  section.insert("telegram_chat_id".to_string(), telegram_chat_id);
  section.insert("hotspots".to_string(), format!("[\"{hotspots}\"]"));
  section.insert("relay_base_url".to_string(), relay_base_url);
  section.insert("network".to_string(), network);
  section.insert("poll_interval_minutes".to_string(), "120".to_string());

  RewardsConfig::from_section(&section).unwrap_or_else(|e| {
    eprintln!("✗ config invalid: {e:?}");
    std::process::exit(2);
  })
}

fn print_step(label: &str, out: &RewardsOutput) {
  println!("── {label} ──");
  println!("{}", out.summary);
  println!();
}

fn iso_days_ago(days: u64) -> String {
  let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
  let then = now - days * 86_400;
  // Relay wants UTC ISO-8601 (e.g. "2026-06-21T00:00:00Z"). Build from epoch.
  let (y, mo, d, h, mi) = epoch_to_ymdhm(then);
  format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:00Z")
}

/// Minimal civil-calendar UTC breakdown (good enough for a 30d window label).
fn epoch_to_ymdhm(epoch: u64) -> (u32, u32, u32, u32, u32) {
  let days = (epoch / 86_400) as i64;
  let secs_of_day = (epoch % 86_400) as u32;
  let h = secs_of_day / 3600;
  let mi = (secs_of_day % 3600) / 60;
  // Days since 1970-01-01 → civil date (Howard Hinnant's algorithm).
  let z = days + 719_468;
  let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
  let doe = (z - era * 146_097) as u64;
  let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
  let y = yoe as u32 + (era as u32) * 400;
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  let mp = (5 * doy + 2) / 153;
  let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
  let mo = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
  let y = if mo <= 2 { y + 1 } else { y };
  (y, mo, d, h, mi)
}

fn main() {
  // Auto-load per-repo `.env` (symlinked into the plugin dir) so the demo runs
  // without manual `source`/`export` — vars already in the real env win.
  let _ = dotenvy::dotenv();
  let step = env::args().nth(1).unwrap_or_else(|| "all".to_string());
  let cfg = build_cfg();
  let http = ReqwestHttp::default();
  let hotspot = env_or("HOTSPOT", CAPYBARA);
  let from = env_or("FROM", &iso_days_ago(30));
  let to = env_or("TO", &iso_days_ago(0));

  match step.as_str() {
    "status" => match do_status(&http, &cfg, &hotspot) {
      Ok(o) => print_step("status", &o),
      Err(e) => eprintln!("✗ status failed: {e:?}"),
    },
    "summary" => match do_summary(&http, &cfg, &hotspot, &from, &to) {
      Ok(o) => print_step("summary (30d)", &o),
      Err(e) => eprintln!("✗ summary failed: {e:?}"),
    },
    "watch" => {
      // The money shot: prev_active=true forces the offline-flip detection
      // (Capybara is offline), firing the real Telegram alert.
      match do_watch(&http, &cfg, &hotspot, Some(true), false, &from, &to) {
        Ok(o) => print_step("watch", &o),
        Err(e) => eprintln!("✗ watch failed: {e:?}"),
      }
    }
    "custody" => {
      println!("── custody ──");
      println!("depin-rewards holds no key of any kind. No ed25519 dependency,");
      println!("no signing code path anywhere in the crate (test-asserted).");
      println!("T0 reads + T1 unsigned claim (roadmap). Agent proposes, multisig disposes.");
      println!();
    }
    "all" => {
      // Safe smoke (no Telegram): status + summary + custody.
      match do_status(&http, &cfg, &hotspot) {
        Ok(o) => print_step("status", &o),
        Err(e) => eprintln!("✗ status failed: {e:?}"),
      }
      match do_summary(&http, &cfg, &hotspot, &from, &to) {
        Ok(o) => print_step("summary (30d)", &o),
        Err(e) => eprintln!("✗ summary failed: {e:?}"),
      }
      println!("── custody ──");
      println!("depin-rewards: no signing key anywhere in the crate. T0/T1 only.");
      println!();
    }
    other => {
      eprintln!("✗ unknown step: {other}");
      eprintln!("  usage: palinurus-demo [status|summary|watch|custody|all]");
      std::process::exit(2);
    }
  }
}