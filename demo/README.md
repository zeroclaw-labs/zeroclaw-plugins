# DePIN demo (local)

Reproduce the Superteam Brasil bounty flow: Telegram → `depin_attest` (T1) → human sign/submit → Explorer → `depin_uptime_watch` (T0).

**Demo video:** https://github.com/darkty0x/zeroclaw-plugins/releases/download/demo-depin-2026-07-22/zeroclaw-depin-demo-2min.mp4

## Layout

| Path | Purpose |
|---|---|
| `runner/` | Host e2e: build unsigned tx → sign with payer keypair → submit → uptime |
| `config.example.toml` | Plugin config fragment (public pubkeys only) |
| `.env.example` | Env template — copy to `demo/.env` / `demo/keys/env.sh` |
| `zeroclaw-config/agents/depin/workspace/` | `SOUL.md` / `TOOLS.md` for reliable tool cards |

Local-only (gitignored): `keys/`, `zeroclaw-config/config.toml`, `recording/`, plugin `.wasm` installs.

## Quick start

```bash
# Keys + env (gitignored)
cp demo/.env.example demo/.env   # fill DEPIN_* + TELEGRAM_BOT_TOKEN
# place payer.json + create durable nonce → demo/keys/

source demo/keys/env.sh
cargo +1.96.1 run --manifest-path demo/runner/Cargo.toml --release
```

Telegram (with your own ZeroClaw channel + bot token):

```text
Attest device pi-greenhouse-7 metric temperature reading 21.4 unit celsius
```

Expect `✅ DePIN attestation ready (T1)`. Then human-submit and:

```text
Check uptime for pi-greenhouse-7
```

## Agent knobs

- `channels.show_tool_calls = false`
- `agents.depin.precheck.enabled = false`
- Ollama `llama3.2:3b`, `temperature = 0`
- Workspace `SOUL.md` / `TOOLS.md` — one tool per turn, reply with the card verbatim

## Custody

Plugins are **T0/T1 only**: no keys in the agent, no `sendTransaction` from WASM.
