# Local demo and <=3 minute video script

## Setup

1. Install/build ZeroClaw according to its repository README, then start a local agent runtime.
2. Build this component:
   `cd plugins/token-risk-check && cargo build --locked --target wasm32-wasip2 --release`
3. Keep `manifest.toml` beside `target/wasm32-wasip2/release/token_risk_check.wasm` (or package the plugin directory according to the ZeroClaw plugin-install flow).
4. Register/install the local plugin in the ZeroClaw runtime using its local plugin/registry configuration. Grant only `http_client` and `config_read`.
5. In the plugin config, optionally set `helius_api_key`; never put it in the manifest, source, video, or terminal recording. Configure Telegram with the runtime's existing Telegram channel setup, then message the agent normally.

## Video flow (<=3 minutes)

1. **0:00-0:25**: show manifest permissions and say: “This is T0/read-only; it cannot sign or move funds.”
2. **0:25-0:55**: ask for USDC. Explain that the plugin is intentionally conservative and reports active authority information rather than maintaining a trusted-token allowlist.
3. **0:55-1:30**: scan `6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN`; point out top-holder concentration and the short red verdict.
4. **1:30-2:05**: scan `CKfatsPMUf8SkiURsDXs7eK6GWb4Jsd6UDbs7twMCWxo`; point out the Token-2022 transfer-fee signal. Use a configured Helius key if available to show `mint_extensions` too.
5. **2:05-2:35**: show malformed/injection args being rejected and explain that unknown fields and any write action are unavailable.
6. **2:35-3:00**: show `cargo test --locked` and the wasm build output; close with the README's risk disclaimer.
