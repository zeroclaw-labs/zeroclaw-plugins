//! `jupiter-swap-guard` — a ZeroClaw WIT tool plugin (custody tier T1: build-only).
//!
//! Given a swap request, it quotes Jupiter, rebuilds the transaction itself from
//! `/swap-instructions` (it never relays the aggregator's bytes), and — before
//! emitting an UNSIGNED transaction — proves that the output can only reach the
//! payer's own account and that no instruction can divert funds. The guarantee
//! lives in the signed bytes, not in the human-facing summary (which transits the
//! LLM and is therefore advisory). The plugin holds no keys and never signs.
//!
//! The pure policy/encode core lives in modules with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through the shim below.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
//!
//! Status: encoder verified byte-exact against the Anza crates (KT-1). The full
//! quote -> gate -> rebuild pipeline is being wired; `execute` fails closed until
//! it lands.
//!
//! `unsafe` is forbidden in every pure module (`encode`, `b58`, and the policy
//! core to come); the only `unsafe` in the crate is the FFI glue that
//! wit-bindgen's `export!` macro generates in the wasm shim, which cannot be
//! avoided.

// `ata` (curve25519-dalek/sha2) and `jupiter`/`instruction` (serde_json) are
// compiled very slowly by the Kani backend and the proofs never exercise them;
// exclude them from verification builds only so `cargo kani` stays fast on the
// scalar core it actually checks.
#[cfg(not(kani))]
pub mod ata;
pub mod b58;
pub mod decode;
pub mod encode;
#[cfg(not(kani))]
pub mod gate;
#[cfg(not(kani))]
pub mod instruction;
#[cfg(not(kani))]
pub mod jupiter;
pub mod policy;
#[cfg(not(kani))]
pub mod summary;

#[cfg(kani)]
mod proofs;

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

    struct JupiterSwapGuard;

    const PLUGIN_NAME: &str = env!("CARGO_PKG_NAME");
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    // The exported WIT tool name (what the LLM calls) intentionally differs from
    // the package id `jupiter-swap-guard`: WIT tool names are snake_case.
    const TOOL_NAME: &str = "jupiter_swap_guard";

    impl PluginInfo for JupiterSwapGuard {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for JupiterSwapGuard {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an UNSIGNED Solana swap via Jupiter, policy-checked so the output can only \
             reach your own account. Enforces a mint allowlist, per-transaction caps, max \
             slippage, a program allowlist, and a priority-fee cap inside the plugin, so the \
             model cannot talk its way past them. Returns an unsigned transaction for a human \
             to review and sign; it never signs or holds keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "input_mint": {"type": "string", "description": "Base58 mint being sold."},
                    "output_mint": {"type": "string", "description": "Base58 mint being bought."},
                    "amount_atoms": {"type": "string", "description": "Amount of input_mint to sell, in base units (atoms), as a decimal string."},
                    "slippage_bps": {"type": "integer", "description": "Max slippage in basis points; rejected if above the configured maximum."},
                    "mode": {"type": "string", "enum": ["blockhash", "durable-nonce"], "description": "Transaction lifetime source. Defaults to blockhash."}
                },
                "required": ["input_mint", "output_mint", "amount_atoms"]
            })
            .to_string()
        }

        fn execute(_args: String) -> Result<ToolResult, String> {
            // Fail closed while the quote -> gate -> rebuild pipeline is being
            // wired. The encoder (src/encode.rs) is verified; policy + HTTP land
            // next. A build-only tool that cannot yet prove its safety
            // properties must refuse, never emit an unchecked transaction.
            emit(
                PluginAction::Fail,
                PluginOutcome::Failure,
                "pipeline under construction: refusing to build until policy gate is wired",
            );
            Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(
                    "jupiter-swap-guard is under construction: the encoder is verified but the \
                     policy gate is not yet wired, so it refuses to build a transaction."
                        .to_string(),
                ),
            })
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "jupiter_swap_guard::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(JupiterSwapGuard);
}
