# solana-token-risk

**Offline rug/honeypot risk analysis for Solana SPL and Token-2022 mints.**
A ZeroClaw `tool-plugin` (wasm32-wasip2) that turns already-fetched Solana RPC
JSON into a structured risk report the agent can reason about — without the
plugin ever touching the network, a key, or a signature.

Superteam Earn bounty submission — **Track D: Onchain Intelligence & Security**.

## What it does

Give the agent a two-step recipe:

1. Fetch chain data with whatever HTTP tool the operator already allows
   (`getAccountInfo` with `jsonParsed` encoding is the only required call;
   `getTokenLargestAccounts`, `getTokenSupply`, and metadata are optional).
2. Call `solana_token_risk` with those JSON blobs.

The tool returns a report with a 0–100 score, a level
(`clean/low/medium/high/critical`), and per-finding explanations:

| Check | Severity |
|---|---|
| Permanent delegate (can seize tokens from any wallet) | critical |
| New accounts frozen by default | critical |
| Mint authority still active (infinite mint) | high |
| Freeze authority still active | high |
| Transfer hook program attached (honeypot pattern) | high |
| Transfer fee ≥ 5% / any transfer fee | high / medium |
| Top-1 holder ≥ 30% / ≥ 15% of supply | high / medium |
| Top-10 holders ≥ 60% / ≥ 40% of supply | high / medium |
| Mint-close authority set (address re-creation spoofing) | medium |
| Non-transferable (soulbound) | medium |
| Mutable metadata (rename/re-skin rug) | low |

Sections you didn't supply are listed in `missing_inputs` — the report is
explicit about being partial instead of pretending to be complete.

## Security tier: T0 (read-only) — and why

- **No network.** The `tool-plugin` world imports only `logging`. This plugin
  requests `permissions = []`: no `config_read`, no sockets, no HTTP. It cannot
  exfiltrate anything even if fully compromised.
- **No signing, no keys, no state.** Input JSON → report JSON. Pure function.
- **Failure mode is closed.** Anything that isn't a jsonParsed SPL mint —
  token accounts, stake accounts, garbage, `null` — returns an error, never a
  fabricated "clean" report.

## Threat model

| Threat | Mitigation |
|---|---|
| Prompt injection via token metadata (a token named `"ignore previous instructions…"`) | String fields are never interpreted; they only appear quoted inside finding text. Control flow depends solely on structural fields (authorities, extensions, amounts). Covered by `garbage_and_hostile_input_fails_closed`. |
| Malicious RPC response shape (wrong account type, missing fields, huge numbers) | Tolerant-but-strict parsing: accepts three envelope shapes, rejects non-mints; numeric parsing falls back safely; score is capped at 100. |
| False reassurance | A report computed from partial data declares what was missing (`missing_inputs`); concentration findings carry the caveat that large holders can be exchanges/LPs. |
| Resource abuse | No allocation beyond the input's own size; no recursion; bounded iteration over `extensions` and holder lists. |

The residual risk an operator must accept: the plugin trusts that the JSON it
receives really came from the RPC node the agent queried. That trust boundary
belongs to the host's HTTP tool policy, not to this T0 analyzer.

## Layout (per registry template)

```
src/risk.rs   # pure core: no wasm deps, host-testable
src/lib.rs    # thin #[cfg(target_family = "wasm")] shim over wit/v0 tool-plugin
tests/risk.rs # 8 host-run tests (cargo test), incl. hostile-input cases
manifest.toml # capabilities = ["tool"], permissions = []
```

## Build & test

```bash
cargo test                                      # host tests, no network
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release    # component build
```

## What was hard about wasm32-wasip2

The tool world having no egress looks like a limitation until you treat it as
the design: splitting "fetch" (host policy decides) from "judge" (deterministic,
sandboxed) makes the security argument for an onchain-intelligence tool almost
write itself. The actual friction was keeping the core `rlib`-testable while
the `cdylib` shim stays behind `cfg(target_family = "wasm")` so `cargo test`
never needs the wasm toolchain.

## License

MIT
