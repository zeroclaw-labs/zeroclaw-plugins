# The proofs, run

`just prove` — Kani 0.67.0, Ubuntu 22.04, against `libs/safe-hands-core`.

```text
SUMMARY:
 ** 0 of 414 failed

VERIFICATION:- SUCCESSFUL
Verification Time: 1.0791016s

Manual Harness Summary:
Complete - 12 successfully verified harnesses, 0 failures, 12 total.
```

## What each harness establishes

These are not tests over chosen inputs. Kani explores the whole input space of
the model and reports a counterexample if one exists. "Can never" below means
*no assignment of the model's inputs produces that outcome*, not *we tried and
did not find one*.

| harness | the property |
|---|---|
| `allow_requires_every_hard_check_to_pass` | ALLOW is unreachable unless every hard check passed |
| `the_decision_is_total` | there is no input for which the engine has no verdict |
| `deny_overrides_every_other_outcome` | nothing can upgrade a DENY |
| `an_unlisted_recipient_can_never_be_allowed` | an off-allowlist destination cannot be ALLOWed |
| `over_cap_can_never_be_allowed` | over the operator's cap cannot be ALLOWed |
| `an_intent_mismatch_can_never_be_allowed` | bytes that contradict the declared intent cannot be ALLOWed |
| `missing_simulation_is_never_downgraded_to_review` | absent simulation evidence denies, it does not soften to REVIEW |
| `durable_nonce_requires_both_opt_ins` | a durable-nonce path needs both opt-ins, never one |
| `an_over_cap_effect_can_never_be_allowed` | a *measured effect* over the bound cannot be ALLOWed |
| `an_unlisted_asset_can_never_leave` | an asset the operator never named cannot leave a guarded account |
| `missing_effect_evidence_is_never_downgraded_to_review` | an effect we could not measure is not assumed to be zero |
| `an_effect_intent_mismatch_can_never_be_allowed` | measured movement contradicting intent cannot be ALLOWed |

The last four cover effects-based authorization — the part that admits programs
the decoder has never seen. That admission is the most dangerous thing this
project does — and it is the one rule the proof model does **not** implement.

**Correction.** This paragraph previously claimed the admission was "held to a
proof rather than a test". The opposite is true. `evaluate()` forgives an
admitted `unknown:` program when effects are required and present
(`policy.rs:435-441`); `resolve()` has no such carve-out
(`policy/resolved.rs:307-310`) and cannot express one — `ResolvedFacts` has no
field for it. On that path the model returns `Deny` where the engine returns
`Allow`, so the harnesses below say nothing about the shipped engine there.
The admission is held to a test.

Found by an independent adversarial review, not by us, and not by the agreement
suite that exists to catch exactly this. See `ROADMAP.md` §1 for why the
agreement tests are structurally incapable of seeing it, and what the fix is.

## The honest reading

These are proofs about **the model in `policy/resolved.rs`**, not about the
whole plugin. The model is heap-free, which is why it terminates in about a
second where the same obligations against `evaluate()` never finished at all.
`policy/tests.rs` is what holds the model and the real engine together; if those
two drift, the proofs stop describing the shipped code. That coupling is a test
obligation, not a proved one, and it is the weakest link in this chain.

Everything else here — the arena, the receipts, the log — exists because a proof
about a model is not the same as a guarantee about a running system.

## Reproduce

```sh
just prove            # Linux/macOS, or WSL on Windows
```

`just judge` runs this automatically when Kani is reachable, including through
WSL, and prints SKIP with the reason when it is not.
