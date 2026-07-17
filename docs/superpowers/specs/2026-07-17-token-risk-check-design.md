# Token Risk Check Plugin Design

## Objective

Add a merge-ready ZeroClaw tool plugin that evaluates a Solana mint without holding keys or constructing transactions. The tool returns a compact red/amber/green assessment with evidence, while failing closed when required RPC evidence is unavailable or contradictory.

## Scope

The first release is one T0 component named `token-risk-check`. It accepts a mint address and queries an operator-configured Solana JSON-RPC endpoint over host-mediated HTTPS.

It evaluates:

- mint validity and owning token program;
- mint and freeze authority state;
- supply, decimals, and largest-holder concentration;
- Token-2022 extensions exposed by parsed RPC data, including transfer fees, transfer hooks, permanent delegate, default account state, confidential transfer, and non-transferable state;
- incomplete or malformed RPC evidence.

LP/liquidity verification is explicitly excluded because standard Solana RPC cannot establish it reliably without a third-party indexer. The output must say `not_checked` rather than infer safety.

## Architecture

The plugin follows the repository's pure-core/thin-shim pattern.

- `src/risk.rs`: pure Rust types, RPC-response parsing, deterministic rules, score aggregation, and bounded output shaping. It has no WIT or HTTP dependency.
- `src/lib.rs`: the WASM component shim. It validates arguments, reads `rpc_url` from the jailed plugin config, sends bounded JSON-RPC requests with `waki`, passes responses to the core, and emits structured logs.
- `tests/risk.rs`: host-run fixture tests for every rule and failure mode. No live network is used.
- `manifest.toml`: declares only `tool`, `http_client`, and `config_read`.
- `README.md`: setup, custody tier, threat model, worked example, prompt-injection transcript, limitations, and WASM build notes.

## Data Flow

1. Validate the mint as a base58 public key before any network call.
2. Read `rpc_url` from `__config`; reject missing, non-HTTPS, credential-bearing, or malformed URLs.
3. Call `getAccountInfo` with `jsonParsed` and `getTokenLargestAccounts` using fixed request bodies and response-size expectations.
4. Parse only documented fields into internal evidence types. Unknown Token-2022 extensions are preserved as warnings.
5. Apply deterministic rules and produce a bounded JSON result containing verdict, reasons, evidence, limitations, and RPC slot.
6. Log only the action outcome and verdict. Never log the configured endpoint, raw response, or user-supplied text.

## Risk Rules

- Red: invalid mint account, unsupported owner, active permanent delegate, transfer hook, non-transferable token, confidential transfer, or required evidence unavailable.
- Amber: active mint authority, active freeze authority, transfer fees, default frozen account state, top-holder concentration above the documented threshold, unknown extension, or partial evidence.
- Green: required evidence is complete and no red or amber rule fires.

The core returns `unknown` instead of green whenever required evidence is missing. Thresholds are constants documented in the README, not LLM-controlled arguments.

## Security And Failure Handling

This is custody tier T0. It accepts no secret key, signature, transaction, arbitrary RPC method, or arbitrary URL. Prompt text cannot change the RPC endpoint, thresholds, or rule set. The tool never labels a token safe solely because parsing failed.

HTTP status errors, JSON-RPC errors, oversized or malformed responses, slot mismatches, and unsupported account structures return a structured unsuccessful result. Network retries are omitted in the first release to keep invocation latency and duplicate traffic predictable.

## Testing

Implementation proceeds test-first. Fixtures cover:

- invalid input rejected before RPC work;
- legacy SPL mint with revoked authorities and dispersed holders;
- active mint/freeze authorities;
- concentrated ownership boundary values;
- each high-risk Token-2022 extension;
- unknown extensions and missing fields;
- malformed and JSON-RPC error responses;
- prompt-injection-shaped arguments that attempt to override policy or endpoint;
- deterministic, bounded output.

Acceptance requires clean `cargo test`, `cargo build --target wasm32-wasip2 --release`, manifest validation, and no stdout logging.

## Delivery

Open an early PR to `zeroclaw-labs/zeroclaw-plugins` from a public `tzwkb` fork. Keep the PR limited to this plugin and its documentation. After review feedback is addressed, run it in a real ZeroClaw agent and channel, record a demonstration under three minutes, publish the required links, and submit them to the global Superteam bounty before 2026-08-07.
