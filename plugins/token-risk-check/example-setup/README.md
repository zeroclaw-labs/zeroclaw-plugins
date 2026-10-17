# Example setup — Token Guardian on Telegram

This is the exact setup behind the *Token Guardian* showcase: a ZeroClaw agent
on Telegram that assesses any Solana token you send it and replies with a
red / amber / green verdict, using the `token-risk-check` plugin.

Reproduce it in an evening.

## What you need

- Rust >= 1.96 with the `wasm32-wasip2` target (`rustup target add wasm32-wasip2`)
- A Telegram bot token (create one via @BotFather)
- An LLM provider key (OpenAI `gpt-4o-mini` is plenty and cheap)
- A Solana mainnet RPC URL (public works; a keyed endpoint like Helius is faster)

## 1. Build the host with the plugin backend

The release binaries do NOT include the plugin host. Build from source:

    git clone https://github.com/zeroclaw-labs/zeroclaw.git
    cd zeroclaw
    cargo build --release --features plugins-wasm-cranelift,agent-runtime,channel-telegram

`plugins-wasm-cranelift` pulls in the JIT backend. Without it, plugins are
discovered but silently never register.

## 2. Build the plugin

    cd plugins/token-risk-check
    cargo build --target wasm32-wasip2 --release
    cp target/wasm32-wasip2/release/token_risk_check.wasm token_risk_check.wasm

## 3. Create the agent

    zeroclaw quickstart

Choose: OpenAI / `gpt-4o-mini`, risk profile `balanced` (keeps the approval
gate), sqlite memory, Telegram channel (paste your BotFather token), agent alias
e.g. `clawverdict_bot`. You can skip the personality files here; step 5 adds them.

## 4. Install the plugin and point it at an RPC

    zeroclaw plugin install <path-to>/plugins/token-risk-check
    zeroclaw config set plugins.entries.token-risk-check.config.rpc_url
    # (interactive, masked - paste your mainnet RPC URL)
    zeroclaw config set plugins.enabled true

`plugins.enabled` defaults to false and `plugin install` does not set it -
without this the plugin is installed but invisible.

## 5. Give the agent its persona

On every start the agent loop injects the workspace identity files into the
system prompt. Copy the two files from this directory into your agent workspace:

    cp SOUL.md TOOLS.md ~/.zeroclaw/agents/<your-agent-alias>/workspace/

- `SOUL.md` gives the agent its "token guardian" identity.
- `TOOLS.md` tells it to always use `token-risk-check` (never web search) for
  token-safety questions. Without these, the agent falls back to web search.

## 6. Run it

    zeroclaw daemon

Use `daemon`, NOT `agent` - the interactive `agent` command does not process
channels. On first run the terminal prints a one-time bind code; send
`/bind <code>` to your bot from Telegram to pair. Then DM the bot:

    Is this token safe? So11111111111111111111111111111111111111112

## Try these (real mainnet tokens, spanning the verdicts)

| Verdict | Mint |
|---|---|
| GREEN | `So11111111111111111111111111111111111111112` (Wrapped SOL) |
| AMBER | `PESdyahTpCsveNXARTDLxSg6H2jYmEni61QY6rQpump` (Subway - concentration) |
| RED | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` (USDC - freeze authority) |
| RED | `FFwQVD66BhhmU2LaSaguXjyzx2NUxyLcfXQrruN2ThS5` (BTC Down - permanent delegate) |

## Notes

- Custody: T0. The plugin only reads the chain. No keys, no transactions, no
  funds. The only secret it holds is the RPC URL, stored encrypted at rest.
- Secrets (bot token, LLM key, RPC URL) are stored encrypted by ZeroClaw - never
  commit them; the `config set` commands store them for you.
- If the plugin fails to instantiate with a WIT/enum type-mismatch, your vendored
  `wit/v0` has drifted from the host's - align it and rebuild (see the showcase
  write-up for the `logging.wit` drift on host v0.8.3).
