//! Prompt-injection defense — fail-closed transcripts (bounty hard req #8).
//!
//! Each test runs an attack vector through **`execute_entry`** — the same
//! dispatch seam the WIT `execute()` shim calls (the C2 wiring). This proves the
//! wired path enforces the guards end-to-end, not just the guards in isolation.
//!
//! Granular coverage (secrets never echoed in output/Debug, `chat_id` always
//! from config not message text) lives in `tests/depin_rewards.rs`; this file is
//! the curated transcript of the README's attack vectors through the entry point.

use depin_rewards::depin_rewards::{execute_entry, MockHttp, RewardsConfig, RewardsError, RewardsRequest};

fn cfg() -> RewardsConfig {
    RewardsConfig {
        relay_api_key: "configured-key".into(),
        relay_base_url: "https://api.relaywireless.com/v1".into(),
        hotspots: vec!["configured-hotspot".into()],
        telegram_bot_token: "configured-token".into(),
        telegram_chat_id: "1".into(),
        poll_interval_minutes: 120,
        network: "mainnet-beta".into(),
    }
}

fn req<'a>(action: &'a str, hotspot_id: &'a str) -> RewardsRequest<'a> {
    RewardsRequest { action, hotspot_id, from: "", to: "", prev_active: None, send_summary: false }
}

/// Attack 1 (README): a crafted message tells the agent to watch/alert an
/// attacker's hotspot. The allowlist (wired into `execute_entry` → `do_status`)
/// rejects any hotspot not in config — **before any network call**.
#[test]
fn prompt_injection_unconfigured_hotspot_rejected() {
    let http = MockHttp::new(); // never reached: allowlist fires first
    let err = execute_entry(&req("status", "attacker-hotspot"), &http, &cfg()).unwrap_err();
    assert!(matches!(err, RewardsError::Config(_)));
}

/// The claim path is NOT shipped (Helium cNFT compression + DAS merkle proof —
/// next milestone). Rather than silently no-op or pretend to move value, the
/// wired dispatch returns an honest, specific error. No value can move through
/// this plugin under any message.
#[test]
fn prompt_injection_claim_tx_fails_closed_honestly() {
    let http = MockHttp::new();
    let err = execute_entry(&req("claim_tx", "configured-hotspot"), &http, &cfg()).unwrap_err();
    assert!(matches!(err, RewardsError::Config(_)));
}

/// Attack: the LLM is coaxed into invoking a hidden/dangerous action
/// ("drain_wallet", "send_all"). The dispatch only routes
/// `status | summary | watch | claim_tx`; anything else fails closed — there is
/// no undocumented action an injection can reach.
#[test]
fn prompt_injection_unknown_action_rejected() {
    let http = MockHttp::new();
    let err = execute_entry(&req("drain_wallet", "configured-hotspot"), &http, &cfg()).unwrap_err();
    assert!(matches!(err, RewardsError::Config(_)));
}
