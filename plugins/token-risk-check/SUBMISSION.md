# token-risk-check — one-page bounty write-up

Demo video: pending a new continuous capture of the already-verified real
Telegram flow; the earlier slide-based draft is not part of this submission.
The release digest and post-hardening ZeroClaw host trace below come from the
same final build.

Upstream pull request: https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/93

## Problem

An agent can be handed a Solana mint that looks normal while the token still has
an active mint authority, a freeze authority, a controlling Token-2022 transfer
hook or permanent delegate, concentrated ownership, or no meaningful market
liquidity. A visible pool can also have unlocked, only partially locked, or
otherwise unverifiable LP control. Letting the model improvise these checks is
hard to audit and exposes the system to prompt injection, cross-mint responses,
truncated data, and incomplete evidence.

## Solution

`token-risk-check` is a T0 read-only ZeroClaw tool plugin. The model supplies one
Solana mint public key. The component validates it before network access, reads
public mint/account data through Solana JSON-RPC and public DEX-pair liquidity,
queries the configured Solana token-security source for LP lock/burn evidence,
then applies deterministic rules in a pure Rust core. It returns a compact
red/amber/green JSON report with a score, completeness flag, findings, and
facts.

The check covers mint/freeze authority, owner-aggregated concentration,
liquidity presence, Token-2022 fees, transfer hooks, permanent delegate,
default-frozen accounts, non-transferable tokens, and confidential-transfer
extensions. It also evaluates pausable, permissioned-burn, and scaled-UI-amount
controls. Unassessed Token-2022 extensions prevent a complete green result.
Missing required holder, market, or LP evidence fails closed as red.

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
- Every outbound request has a 10-second connection timeout, and every upstream
  HTTP body is capped at 1 MiB before JSON parsing.
- Largest-account addresses are validated and unique; holder response count,
  holder mint, market-pair mint, and LP-security result key are all bound to the
  original requested mint.
- Locked LP share is derived from holder balances and the exact single standard
  pool's `lp_amount`. Ambiguous multi-pool holder evidence, unknown pool types,
  and malformed Token-2022 extension records fail closed.

## Safety and custody

Custody tier **T0**. There is no key, seed phrase, wallet connector, transaction
builder, signer, simulator, or submission path. It cannot move funds. The
single LLM input must decode to an exact 32-byte base58 public key before any
HTTP request. Upstream responses are parsed into bounded typed facts and are
never interpreted as instructions. Raw upstream error text is discarded rather
than exposed to the model. Logs exclude raw responses and config.

The README includes the full threat model, prompt-injection transcript,
permission rationale, limitations, install/configuration instructions, and a
worked output example.

## Validation

The 18-test host suite covers invalid/prompt-injected mint input, endpoint SSRF
lookalikes, threshold validation, legacy authorities, malicious and unknown
Token-2022 extensions, owner aggregation, malformed/duplicate largest-account
lists, truncated and cross-mint holder responses, cross-mint market pairs,
GoPlus LP status parsing and mint binding, the 1 MiB body limit, deterministic
rating paths, incomplete evidence, bounded errors, and compact output. The
required release component is built and linted with:

```bash
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo clippy --target wasm32-wasip2 -- -D warnings
cargo build --locked --target wasm32-wasip2 --release
```

The post-hardening release was built and loaded in a ZeroClaw 0.8.3 host on
2026-07-22. The model selected one native tool call, ZeroClaw parsed one tool
call, the WASM component queried live Solana RPC, DexScreener, and GoPlus
evidence, and the exact result was returned to the agent on its second turn.

- release WASM: **442,725 bytes**;
- SHA-256:
  `537A0D594A4308DE66B5C3F1C7D336671D8E75EA9D1386441BD29A3DF09F64A5`;
- runtime log summary: `{"complete":false,"rating":"red","score":70}`;
- returned evidence for the USDC mint included active mint/freeze authorities,
  top-one concentration of 11.6%, top-ten concentration of 33.9%, $14,994,072
  PumpSwap liquidity, and `lp_status: concentrated_position` from GoPlus.

The Telegram channel was authenticated and exercised end to end on 2026-07-22:
a real Telegram request reached ZeroClaw, the model selected this WASM tool,
live evidence returned, and the second-turn answer was delivered to Telegram.
The remaining artifact is a new continuous public recording no longer than
three minutes that visibly proves that full sequence. Live market and holder
values can change between runs.

If the primary and fallback RPCs, market endpoint, or required LP source fail,
the plugin fails closed rather than inventing data.

## Honest boundary

The tool is a risk screen, not an audit. Largest-account sampling cannot label
every exchange, bridge, burn address, or LP, and reported pair liquidity does
not itself prove LP control. The default GoPlus Solana token-security endpoint
is a third-party beta source; the plugin evaluates its highest-TVL reported
pool, and concentrated-liquidity control remains explicitly unverified. Those
limits are visible so agents and users do not mistake a green result for a
guarantee.

## Next extension

Without raising the custody tier, a follow-up can add provider-pluggable
metadata/reputation, multi-provider LP corroboration, and deeper concentrated-
position analysis. The current version deliberately prioritizes a small,
auditable, zero-secret T0 surface.
