//! A ZeroClaw WIT **tool plugin**: `depin-rewards`.
//!
//! Palinurus Track C (DePIN) — the "daily-useful" plugin. Watches
//! Helium/Hivemapper-class hotspots on the public Solana network via the Relay
//! API: online/offline status + reward earnings, fires Telegram alerts (instant
//! on offline, daily rewards summary at 08:00), and optionally drafts an
//! unsigned rewards-claim transaction (`lazy-distributor` `distribute_rewards_v0`)
//! for the watched hotspot's public owner. Custody **T0/T1 only** — the plugin
//! holds NO key of any kind; it reads and drafts, never signs. The owner or a
//! Squads multisig signs any claim.
//!
//! The pure rewards core lives in [`depin_rewards`] with no wasm dependency, so
//! it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod depin_rewards;

// Host-only demo driver (`--features demo`): reqwest-backed HttpClient + Rpc
// impls that run the shipped pure core against live services on camera.
// Excluded from the wasm component build entirely (no feature → no module).
#[cfg(feature = "demo")]
pub mod demo_http;
#[cfg(feature = "demo")]
pub mod demo_rpc;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct DepinRewards;

    const PLUGIN_NAME: &str = "depin-rewards";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "depin_rewards";

    impl PluginInfo for DepinRewards {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for DepinRewards {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Watch a Helium hotspot's online/offline status and rewards on the public \
             Solana network, fire Telegram alerts (instant on offline, daily rewards \
             summary), and optionally draft an unsigned rewards-claim transaction for \
             the hotspot's owner. Reads public data via the Relay API. The plugin holds \
             no key — it can read and draft, never sign. The owner or a Squads multisig \
             signs any claim."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["status", "summary", "watch", "claim_tx"],
                        "description": "status = read one hotspot's online/offline now; summary = rewards for a time range; watch = cron-tick check + alert if offline-flip / send daily summary; claim_tx = draft an unsigned rewards-claim tx (T1)."
                    },
                    "hotspot_id": {
                        "type": "string",
                        "description": "Helium hotspot identifier: ECC compact key, Solana asset id, or UUID."
                    },
                    "from": {
                        "type": "string",
                        "description": "[summary] ISO8601 start (default: 00:00 today UTC)."
                    },
                    "to": {
                        "type": "string",
                        "description": "[summary] ISO8601 end (default: now)."
                    },
                    "prev_active": {
                        "type": "boolean",
                        "description": "[watch] the hotspot's last-known active state (SOP persists it). Omit on first tick."
                    },
                    "send_summary": {
                        "type": "boolean",
                        "description": "[watch] if true, send the 08:00 daily-summary Telegram message (SOP sets this on the 08:00 tick)."
                    }
                },
                "required": ["action", "hotspot_id"]
            })
            .to_string()
        }

        fn execute(_args: String) -> Result<ToolResult, String> {
            // Slice A scaffold: the pure-core actions (status / summary / watch /
            // claim_tx) are wired in slices C–G. Until then, fail closed with a
            // clear message — no half-wired behavior.
            emit(PluginAction::Start, None, "execute received (scaffold)");
            emit(
                PluginAction::Fail,
                Some(PluginOutcome::Failure),
                "execute not wired (slice A scaffold)",
            );
            Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(
                    "depin-rewards scaffold: execute not wired yet (lands in slices C–G)"
                        .to_string(),
                ),
            })
        }
    }

    fn emit(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "depin_rewards::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(DepinRewards);
}
