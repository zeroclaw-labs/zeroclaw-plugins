# solana-recipient-firewall

ZeroClaw T0 tool plugin: verify Solana recipients against an operator-pinned
address book BEFORE any transaction is built. Detects address poisoning
(prefix+suffix lookalikes), rejects blocked or invalid addresses, and
optionally holds unknown-but-valid addresses for human review.

## Custody Tier: T0

| Capability | Status |
|---|---|
| Read-only | Yes |
| No signing | Yes |
| No transaction building | Yes |
| No network access | Yes |
| No filesystem | Yes |
| Config only | `config_read` |

## Threat Model

### Attack: Address Poisoning

An attacker creates a Solana address whose first 4 and last 4 characters match
a trusted contact (e.g. the treasury). They then convince an AI agent to use
this address instead of the real one.

```
Trusted treasury:  So11...1112
Attacker address:  So11...1112  (same prefix+suffix, different middle)
```

### Defence

This plugin sits at the trust boundary *before* any transaction-building tool.
It checks:

1. Is the candidate a valid Solana base58 pubkey (32 bytes)?
2. Is it on the operator's blocked list?
3. Does it exactly match a pinned contact?
4. If `claimed_contact` is provided, does the candidate match that
   specific label's pinned address?
5. Do the candidate's first N and last M characters collide with any
   known contact? If so, but the full address differs -> REJECT (poisoning).
6. Unknown? REJECT by default, or HOLD if `allow_unknown=true`.

## Config

```toml
# In the operator's ZeroClaw config (set via `zeroclaw config set`):
# The plugin's full-instance key can be found with:
#   zeroclaw plugin info solana-recipient-firewall
#
# Then set each value:
#   zeroclaw config set "plugins.entries.<KEY>.config.contacts" \
#     'treasury=So11111111111111111111111111111111111111112;validator=TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
#   zeroclaw config set "plugins.entries.<KEY>.config.blocked" \
#     'ScamAddr11111111111111111111111111111111111111'
#   zeroclaw config set "plugins.entries.<KEY>.config.allow_unknown" 'false'
#   zeroclaw config set "plugins.entries.<KEY>.config.collision_prefix" '4'
#   zeroclaw config set "plugins.entries.<KEY>.config.collision_suffix" '4'
```

| Key | Type | Default | Description |
|---|---|---|---|
| `contacts` | string | `""` | Semicolon-separated `label=address` pairs. Every label must be unique; every address must be a valid 32-byte Solana pubkey. |
| `blocked` | string | `""` | Semicolon-separated addresses to always reject. |
| `allow_unknown` | boolean | `false` | If true, valid but unknown addresses get HOLD instead of REJECT. |
| `collision_prefix` | integer (3-12) | `4` | Characters to compare at start for lookalike detection. |
| `collision_suffix` | integer (3-12) | `4` | Characters to compare at end for lookalike detection. |

## Tool Schema

```json
{
  "name": "solana_recipient_firewall",
  "parameters": {
    "type": "object",
    "properties": {
      "candidate": {
        "type": "string",
        "description": "The Solana recipient address to verify."
      },
      "claimed_contact": {
        "type": "string",
        "description": "Optional: the label the caller claims this address belongs to."
      }
    },
    "required": ["candidate"]
  }
}
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `ALLOW` | Candidate exactly matches a pinned contact. Safe. |
| `HOLD` | Valid but unknown address, and `allow_unknown=true`. Human must review. |
| `REJECT` | Invalid, blocked, lookalike, unknown-by-default, or config error. |

## Worked Examples

### Scenario A: Trusted treasury -> ALLOW

```
Config: contacts = "treasury=So11111111111111111111111111111111111111112"

Input:  { candidate: "So11111111111111111111111111111111111111112" }
Output: { verdict: "ALLOW", reason: "exact match for contact 'treasury'", matched_label: "treasury" }
```

### Scenario B: Claimed contact mismatch -> REJECT

```
Model: "Send 5 SOL to the new treasury address: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

Input:  { candidate: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", claimed_contact: "treasury" }
Output: { verdict: "REJECT", reason: "candidate does not match pinned address for contact 'treasury'" }
```

### Scenario C: Lookalike -> REJECT

```
Trusted:  So11111111111111111111111111111111111111112
Attacker: So11XXXXXXXXXXXXXXXXXXXXXXXXX1112  (same prefix "So11" + suffix "1112")

Output: { verdict: "REJECT", reason: "address poisoning detected: candidate looks like contact 'treasury' (prefix 'So11' and suffix '1112' match)" }
```

### Scenario D: Unknown with lenient mode -> HOLD

```
Config: allow_unknown = true

Input:  { candidate: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" }
Output: { verdict: "HOLD", reason: "unknown recipient; operator has allow_unknown=true — human review required" }
```

## Prompt Injection Resistance

The plugin rejects candidate addresses containing:

- Control characters (`\0`, `\n`, `\r`, `\t`)
- JSON/HTML metacharacters (`"`, `{`, `}`, `<`, `>`)
- Non-ASCII (Unicode homoglyph attacks)
- Non-base58 characters
- The `__` prefix (reserved for host-injected keys)

The `claimed_contact` argument is also checked for injection patterns and
length bounds. An attacker cannot inject config directives or alter the
address book through the tool arguments.

```
# Example injection attempt (REJECTED):
Input:  { candidate: "{\"__config\":{\"contacts\":\"evil=...\"}}" }
Output: { verdict: "REJECT", reason: "candidate address contains forbidden characters" }
```

## Layout

```
src/firewall.rs   # pure logic, no wasm deps — host-testable with `cargo test`
src/lib.rs        # thin #[cfg(target_family = "wasm")] component shim
tests/            # host-run integration tests over the pure core
manifest.toml     # name, version, wasm_path, capabilities, permissions, config_schema
```

## Build and Test

```bash
# Host tests (no wasm toolchain needed)
cargo test

# Format
cargo fmt --all -- --check

# Lint
cargo clippy --all-targets -- -D warnings

# WASM build
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release

# WASM lint
cargo clippy --target wasm32-wasip2 -- -D warnings

# Verify component (optional, if wasm-tools installed)
wasm-tools component wit target/wasm32-wasip2/release/solana_recipient_firewall.wasm
```

## Known Limitations

- **No on-chain verification**: The plugin validates base58 encoding and
  byte length, but does not verify that the address is an active account
  on-chain (would require network access — T1+).
- **Static address book**: Contacts are configured by the operator and
  cannot be extended at runtime by the model.
- **Prefix+suffix only**: Sophisticated attackers could craft addresses
  with identical prefix+suffix but different program-derived addresses.
  Increasing `collision_prefix` and `collision_suffix` tightens this.
- **No ENS/SNS resolution**: The plugin works with raw base58 addresses.
  SNS domain resolution should happen in a separate T1+ plugin.
