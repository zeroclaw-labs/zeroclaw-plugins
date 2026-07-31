# Operator kit — run Caixa tonight

Goal: another person can stand up the same Telegram payment terminal in an evening.

## 0) What you need

- A machine that can build ZeroClaw from source with WASM plugins
- Telegram bot token + an OpenAI-compatible (or other) model key
- Your Solana merchant address (USDC ATA owner)
- Optional: durable nonce account if you use transfer-build

## 1) ZeroClaw host (plugins-wasm)

Stock “lean” binaries often **omit** the WASM plugin host. Build:

```bash
git clone https://github.com/zeroclaw-labs/zeroclaw.git
cd zeroclaw && git checkout v0.8.3   # or current tag you trust
cargo build --release --features plugins-wasm,plugins-wasm-cranelift,channel-telegram,agent-runtime,gateway
```

Confirm: `./target/release/zeroclaw plugin list` works.

## 2) Build Caixa plugins

```bash
git clone https://github.com/thesithunyein/zeroclaw-plugins.git
cd zeroclaw-plugins && git checkout feat/caixa-payment-terminal
rustup target add wasm32-wasip2

(cd plugins/caixa-charge && cargo test && cargo build --target wasm32-wasip2 --release \
  && cp target/wasm32-wasip2/release/caixa_charge.wasm ./caixa_charge.wasm)
(cd plugins/caixa-transfer-build && cargo test && cargo build --target wasm32-wasip2 --release \
  && cp target/wasm32-wasip2/release/caixa_transfer_build.wasm ./caixa_transfer_build.wasm)
(cd plugins/caixa-watch && cargo test && cargo build --target wasm32-wasip2 --release \
  && cp target/wasm32-wasip2/release/caixa_watch.wasm ./caixa_watch.wasm)

mkdir -p ~/.zeroclaw/plugins
cp -a plugins/caixa-charge plugins/caixa-transfer-build plugins/caixa-watch ~/.zeroclaw/plugins/
```

## 3) Config

Merge the shapes in [`config.example.toml`](config.example.toml) into `~/.zeroclaw/config.toml`:

- Set `recipient` to **your** merchant pubkey
- Set `brl_per_usdc` if CoinGecko is flaky in your region
- Wire Telegram + model provider through normal `zeroclaw` / quickstart (never commit bot tokens)

ZeroClaw 0.8+ plugin settings use `[[plugins.entries]]`, not `[plugins.caixa-charge]`.

## 4) Agent soul

Copy [`SOUL.md`](SOUL.md) into your agent workspace (e.g. `~/.zeroclaw/agents/caixa/workspace/SOUL.md`).

## 5) Run

```bash
zeroclaw plugin list          # should list caixa-*
zeroclaw daemon -v
```

In Telegram (bound peer):

```
Cobra mesa 9: R$ 25
```

You should get:

1. HTTPS **Pay QR** link (opens a QR image — scan with Phantom)
2. Raw `solana:…` URL

Optional: install [`../plugins/caixa-watch/sop-payment-watch.yaml`](../plugins/caixa-watch/sop-payment-watch.yaml) as a cron SOP to poll unpaid invoices.

## Safety checklist

- No private keys in config
- `auto_approve` includes `caixa_charge` / `caixa_watch` only as you trust
- Exclude `shell` / `http_request` if the model keeps bypassing the plugin
