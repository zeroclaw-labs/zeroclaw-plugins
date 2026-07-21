# realms-proposal-firewall

`realms-proposal-firewall` is a read-only ZeroClaw tool plugin that analyzes the
executable instructions in one SPL Governance V2 proposal. It reads finalized
Solana accounts, validates their relationships and canonical PDAs, decodes a
bounded set of security-sensitive instructions, and returns deterministic JSON.
It never votes, signs, submits transactions, discovers proposals, or fetches
proposal names, descriptions, or metadata URLs.

## Tool

Tool name: `realms_proposal_firewall`

```json
{
  "proposal_address": "6wR1jdhhJ31bbdRNXva8MxqsgsNLKTxargcdAyZ7FcRj"
}
```

The model can supply only `proposal_address`. Unknown fields are rejected. RPC
credentials, allowlists, thresholds, and resource limits come from the
operator-owned config section injected by the host.

## Configuration

Configure the section named `realms-proposal-firewall` using the host's plugin
configuration mechanism. Values are flat strings.

| Key | Required | Default | Meaning |
|---|---|---|---|
| `rpc_url` | yes | none | HTTPS Solana JSON-RPC endpoint. Query-string API keys are accepted; URL userinfo and fragments are rejected. |
| `expected_genesis_hash` | yes | none | Expected cluster genesis hash. Mainnet beta is `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`. |
| `governance_program_ids` | no | shared SPL Governance | Comma-separated governance program allowlist. |
| `allowed_destination_owners` | no | empty | Comma-separated destination-owner policy allowlist. |
| `allowed_mints` | no | empty | Comma-separated accepted mints. Empty reports every transferred mint as unapproved; it does not trust every mint. |
| `max_transactions` | no | `32` | PDA high-water limit, from 1 through the hard maximum 64. |
| `max_instructions` | no | `64` | Instruction limit, from 1 through the hard maximum 128. |
| `large_outflow_bps` | no | `2500` | Large aggregate outflow threshold in basis points of the current source balance. |
| `critical_outflow_bps` | no | `9000` | Critical aggregate outflow threshold; must be at least `large_outflow_bps`. |

Malformed config fails the call. Empty or malformed policy never silently
broadens trust.

## Detection

The initial release decodes:

- System Program SOL transfers.
- Classic SPL Token `Transfer`, `TransferChecked`, `Approve`, `SetAuthority`,
  `MintTo`, `Burn`, and `CloseAccount`.
- Associated Token Account `Create` and `CreateIdempotent`.
- Upgradeable Loader `Upgrade`, `SetAuthority`, and `SetAuthorityChecked`.
- SPL Governance `SetGovernanceConfig` and `SetRealmAuthority`.

Token-2022, custom programs, unknown tags, and multisig token authorities are
not guessed. Unknown executable instructions force a `CRITICAL` verdict.
Malformed instructions or missing, contradictory, oversized, or changing
evidence force `INCOMPLETE`.

Transfers are aggregated by source and asset before policy thresholds are
applied. Amounts, slots, timestamps, and vote weights are emitted as decimal
strings where JavaScript integer precision could be exceeded. Findings are
sorted by severity, code, and instruction location. Output is capped at 32 KiB.

## BIP #76

`tests/fixtures/bip76` contains a finalized mainnet capture, the signed execution
transaction returned as base64, request provenance, and SHA-256 hashes. The
capture is live account state at its recorded slot, not a cryptographic proof of
historical state. The regression identifies the 4,426,104,450,305.966 BONK
transfer, external recipient, fresh destination account, 1% threshold, barely
passing vote, zero hold-up, and unsupported metadata instructions.

## Security Model

Custody tier: **T0**. The component has no key, signing, voting, transaction
construction, transaction submission, file, socket, or memory permission. Its
manifest grants exactly `http_client` and `config_read`.

Trust and limitations:

- The configured RPC provider is a trust dependency. Solana JSON-RPC does not
  return cryptographic account proofs. HTTPS protects transport, not provider
  honesty.
- Every account request uses `finalized`, later calls use `minContextSlot`, and
  proposal plus transaction bytes are re-read before reporting. A detected
  change returns `SNAPSHOT_RACE` and `INCOMPLETE`.
- Current source balances are used for ratio policy. A completed historical
  proposal may have already changed those balances; exact encoded transfer
  amounts remain authoritative, but historical percentages are not reconstructed.
- Voting deadlines and hold-up values come from the current finalized governance
  account because SPL Governance does not capture those settings in ProposalV2.
  For old completed proposals they may differ from the settings at execution.
- Only SPL Governance V2 layouts are supported. V1, custom governance layouts,
  relevant voter-weight add-ins, Token-2022, custom DeFi programs, and token
  multisig authorities fail closed.
- Proposal prose and remote metadata are excluded from analysis and output.
  They cannot suppress findings or cause URL fetches.
- The plugin analyzes one explicitly supplied address. Scheduling, discovery,
  deduplication, alert delivery, and persistent checkpoints belong to ZeroClaw
  SOPs or an external service.

## Build And Test

Use the toolchain pinned by repository CI:

```bash
cargo +1.96.1 fmt --all -- --check
cargo +1.96.1 test --locked
cargo +1.96.1 clippy --locked --all-targets -- -D warnings
cargo +1.96.1 clippy --locked --target wasm32-wasip2 -- -D warnings
cargo +1.96.1 build --locked --target wasm32-wasip2 --release
```

The component is written to
`target/wasm32-wasip2/release/realms_proposal_firewall.wasm`.
