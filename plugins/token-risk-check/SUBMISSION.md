# token-risk-check — one-page bounty write-up

Demo video: pending the required real Telegram-channel capture; the earlier
slide-based draft is not part of this submission.

Upstream pull request: https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/93

## Problem

An agent can be handed a Solana mint that looks normal while the token still has
an active mint authority, a freeze authority, a controlling Token-2022 transfer
hook or permanent delegate, concentrated ownership, or no meaningful market
liquidity. Letting the model improvise this check is hard to audit and exposes
the system to prompt injection and incomplete evidence.

## Solution

`token-risk-check` is a T0 read-only ZeroClaw tool plugin. The model supplies one
Solana mint public key. The component validates it before network access, reads
public mint/account data through Solana JSON-RPC and public DEX-pair liquidity,
then applies deterministic rules in a pure Rust core. It returns a compact
red/amber/green JSON report with a score, completeness flag, findings, and facts.

The check covers mint/freeze authority, owner-aggregated concentration,
liquidity presence, Token-2022 fees, transfer hooks, permanent delegate,
default-frozen accounts, non-transferable tokens, and confidential-transfer
extensions. Missing or partial holder/market evidence fails closed as red.

## Why it fits ZeroClaw

- Native `wasm32-wasip2` WIT component using the repository's canonical
  pure-core/thin-shim layout.
- Host-testable core with adversarial fixtures; no live network is needed for
  deterministic CI.
- Structured ZeroClaw logging instead of stdout.
- Manifest requests only `tool`, `http_client`, and `config_read`.
- Operator-owned endpoints and thresholds arrive through the jailed `__config`
  section; the field is excluded from the model-visible schema.
- Remote endpoints require HTTPS, and only exact loopback hosts may use HTTP.

## Safety and custody

Custody tier **T0**. There is no key, seed phrase, wallet connector, transaction
builder, signer, simulator, or submission path. It cannot move funds. The
single LLM input must decode to an exact 32-byte base58 public key before any
HTTP request. Upstream responses are parsed into bounded typed facts and are
never interpreted as instructions. Logs exclude raw responses and config.

The README includes the full threat model, prompt-injection transcript,
permission rationale, limitations, install/configuration instructions, and a
worked output example.

## Validation

The host test suite covers invalid/prompt-injected mint input, endpoint SSRF
lookalikes, threshold validation, legacy authorities, malicious Token-2022
extensions, owner aggregation, chain filtering and label sanitization, green
and red rating paths, incomplete evidence, bounded RPC errors, and sub-2KB
output. The required release component is built with:

```bash
cargo test --locked
cargo build --locked --target wasm32-wasip2 --release
```

A live ZeroClaw 0.8.3 host run also registered the release WASM, gave the agent
only this tool, produced exactly one native tool call, executed live Solana RPC
and DexScreener requests, and returned the bounded evidence for the agent's
second-turn summary. When the primary public RPC rate-limited the second holder
request, the configured HTTPS fallback completed it. The verified report
included owner-aggregated top-holder concentration and `complete: true`; if
both endpoints fail, the plugin still fails closed rather than inventing data.

## Honest boundary

The tool is a risk screen, not an audit. Largest-account sampling cannot label
every exchange, bridge, burn address, or LP, and reported pair liquidity does
not prove LP tokens are locked. Those limits are explicit so agents and users
do not mistake a green result for a guarantee.

## Next extension

Without raising the custody tier, a follow-up can add provider-pluggable
metadata/reputation and independently verified LP-lock evidence. The current
version deliberately prioritizes a small, auditable, zero-secret T0 surface.
