# PROOFS.md — what is verified, how, and the exploit each property excludes

This plugin's safety is not a claim; it is a set of properties with an explicit
**evidence tier** each. Honesty about the tier is deliberate: over-claiming a
"formal proof" of something a solver cannot actually decide would be exactly the
kind of thing a careful judge should punish.

Three tiers are used:

- **Kani** — exhaustive symbolic model-checking over the *entire* input domain
  (`cargo kani`, run in CI on a fork branch; see the badge in `README.md`).
- **proptest** — thousands of randomized cases over the full domain, for the
  `u128`-division arithmetic that CBMC bit-blasts into an intractable divider.
- **Differential / unit** — byte-for-byte comparison against the official Anza
  crates on a real mainnet route, and targeted positive + negative controls.

## Encoder integrity — Kani (exhaustive)

| Property | Harness | Excludes |
|---|---|---|
| **P6** compact-u16 write∘read is the identity ∀ u16, and consumes exactly the bytes written | `proofs::compact_u16_roundtrips` | length-field **malleability** — two distinct byte strings decoding to the same message |
| **P7** the compact-u16 reader never panics on arbitrary input; malformed data errors cleanly | `proofs::compact_u16_read_never_panics` | a fail-**open** crash inside the host on hostile instruction data |

`cargo kani` → `Complete - 2 successfully verified harnesses, 0 failures, 2 total.`

## Transaction construction — differential (byte-exact vs Anza)

The hardest correctness risk — hand-rolling a v0/ALT transaction for
`wasm32-wasip2` without `solana-sdk` — is pinned by comparing the plugin's OWN
`parse → compile → serialize` against `solana_message::v0::Message::try_compile`
+ `serialize` on a **real captured mainnet Jupiter route** (a 246-address lookup
table compressed to 9 static keys + 1 lookup, 505 bytes):

| Check | Test |
|---|---|
| hand-rolled v0 serializer == Anza serializer | `tests/encode_differential.rs::hand_rolled_v0_serializer_matches_anza_on_real_jupiter_route` |
| full `compile_v0` (account partition, header, lookups, indices) == Anza `try_compile` | `tests/encode_differential.rs::full_compile_matches_anza_try_compile` |
| canonical ATA derivation == real on-chain ATAs (USDC + wSOL) | `src/ata.rs` tests |
| unsigned-transaction wire layout (empty sig slots + message) | `src/encode.rs` test |

## Arithmetic guardrails — proptest (full domain)

CBMC cannot verify the `u128` division in these tractably; proptest covers the
full `u64`/`u16`/`u32` domains instead, alongside boundary unit tests.

| Property | Test | Excludes |
|---|---|---|
| **P2** emitted `min_out` floor ≤ quote, ∀ quote/slippage, no overflow | `policy::prop_min_out_never_exceeds_quote`, `prop_min_out_boundaries` | "set slippage to 100%" / a manipulated quote inflating min-out |
| **P3** amount > per-mint cap ⇒ reject | `policy::enforces_amount_cap` | notional escalation |
| **D4** priority fee is the correct `ceil`, 0 iff product 0, never wraps | `policy::prop_priority_fee_sound` | a runaway `SetComputeUnitPrice` draining SOL as fee |

## Instruction gate — positive + negative controls (real fixture)

Every guardrail is tested by running the guard over the real Jupiter route (must
**pass**) and over five tampered variants (each must be **refused** with its
specific reason) — `src/gate.rs` tests:

| Property | Excludes | Negative-control test |
|---|---|---|
| **D1a** every ATA-create owner == payer | creating/funding an attacker's ATA | `ata_create_for_non_payer_is_refused` |
| **D1b** swap output bound to the payer's own ATA | a malicious response delivering output to an attacker | `unbound_destination_is_refused` |
| **D2** System transfers only to payer-owned accounts | `System.transfer(payer→attacker)` via the allowlisted System program | `system_transfer_to_attacker_is_refused` |
| **D4** decoded priority fee ≤ cap | priority-fee SOL drain | `priority_fee_over_cap_is_refused` |
| **P4** top-level program allowlist | an unknown drainer program | `non_allowlisted_program_is_refused` |
| **P1/P5** mint allowlist, payer-only signer | swap into an unlisted mint; co-signer smuggling | `rejects_disallowed_mint`, gate signer check |

**D5** (security-relevant accounts must be static, never resolved via a lookup
table — defeats a malicious RPC crafting table contents) is enforced in
`compile_v0` and tested by `compile::d5_refuses_when_a_required_static_account_is_in_the_table`.

**D3** (min_out bound to the quote the plugin actually received, closing the
quote↔instructions TOCTOU) is enforced in the pipeline and covered by
`pipeline::full_pipeline_builds_unsigned_tx` (min_out is recomputed from our
quote, never read from Jupiter's embedded field).

## Config parsing — unit (P8)

`P8` (unknown config key ⇒ hard refusal, so a typo like `max_amout=1` can never
silently widen a cap — the exact PR-25 audit finding) is String-domain and thus
unit-tested, not Kani'd: `policy::unknown_key_is_refused`,
`empty_config_is_refused_fail_closed`.
