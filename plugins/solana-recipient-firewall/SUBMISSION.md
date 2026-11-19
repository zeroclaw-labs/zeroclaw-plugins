# Superteam Earn Submission: solana-recipient-firewall

## Bounty
**Build Solana-native plugins for ZeroClaw**

## Plugin Name
`solana-recipient-firewall`

## Category / Track
Security / Recipient Verification (T0 custody tier)

## Summary

A ZeroClaw T0 tool plugin that sits at the trust boundary BEFORE any
Solana transaction is built. It verifies a candidate recipient address
against an operator-pinned address book and detects address poisoning
attacks where an attacker creates a lookalike address with matching
prefix and suffix characters.

## Problem

AI agents and human users can be tricked into sending funds to the wrong
address through **address poisoning** or **recipient spoofing**. An attacker:

1. Creates a Solana address with the same first 4 and last 4 characters
   as a trusted contact (e.g. the treasury)
2. Sends a dust transaction from this address to the victim's wallet
3. When the victim (or their AI agent) copies the address from transaction
   history, they send funds to the attacker instead

Existing plugins in this bounty build transactions, simulate them, or check
token risk — but **none protect the recipient trust boundary**.

## Solution

The plugin checks a `candidate` address against the operator's address book:

| Check | Result |
|---|---|
| Invalid base58 / wrong byte length | REJECT |
| On blocked list | REJECT |
| Exact match with pinned contact | ALLOW |
| `claimed_contact` mismatches pinned address | REJECT |
| Prefix+suffix collision with known contact | REJECT (poisoning) |
| Unknown address (default) | REJECT |
| Unknown address (`allow_unknown=true`) | HOLD |

## Value Proposition

- **Trust boundary**: Runs before any transaction-building plugin, preventing
  poisoned addresses from reaching the signing stage
- **Fail-closed**: Unknown = REJECT by default. The operator must opt into
  HOLD mode explicitly.
- **Defence in depth**: Even if `allow_unknown=true`, blocked and poisoned
  addresses are still REJECTED.
- **No false poisoning on exact matches**: An exact match with a contact is
  ALLOW, never flagged as poisoning.
- **Prompt injection resistant**: Candidate and claimed_contact are sanitized
  against injection attacks.

## Architecture

Standard ZeroClaw plugin layout following `plugins/redact-text` as template:

- Pure core in `src/firewall.rs` (no wasm deps — `cargo test` on host)
- Thin WIT component shim in `src/lib.rs` (`#[cfg(target_family = "wasm")]`)
- `manifest.toml` with `config_schema` (Draft 2020-12, `additionalProperties: false`)
- `config_read` permission only — T0 custody

## Dependencies

- `wit-bindgen = "0.46"`
- `serde` + `serde_json` (for JSON parsing)
- No external Solana SDK — base58 validation is implemented in pure Rust

## Test Coverage

All tests run on the host with `cargo test` (no wasm toolchain required):

- Exact contact match (with and without claimed_contact)
- Wrong claimed_contact rejection
- Non-existent claimed_contact rejection
- Blocked address rejection (including blocked-overrides-contact)
- Invalid base58 rejection
- Non-32-byte pubkey rejection
- Unknown recipient rejection (default)
- Unknown recipient HOLD (allow_unknown=true)
- HOLD never becomes ALLOW
- Address poisoning prefix+suffix detection
- Exact match not misclassified as poisoning
- Empty/oversized candidate rejection
- Control characters and injection characters rejection
- Unicode rejection
- Reserved prefix rejection
- Config: duplicate label, duplicate address, duplicate blocked
- Config: unknown field, out-of-range values, missing optional fields
- Config: invalid addresses in contacts
- Large config rejection
- Trailing semicolons and whitespace handling
- Output size cap

## AI Assistance Disclosure

This plugin was developed with AI assistance (DeepSeek/OpenClaw) for code
generation and iteration. All code has been reviewed, tested, and validated.
The core logic (address book verification, base58 decoding, lookalike
detection) was designed and structured by the human author.

## Author

- GitHub: [infser](https://github.com/infser)
