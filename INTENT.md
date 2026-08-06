# What "authorized" means here

The ROADMAP calls intent semantics the problem this project did not solve. That
is true of the whole problem and lazy about the half that is tractable. This
document separates them, because the tractable half is already proven and the
proofs have never been given their meaning.

## The three things that must agree

Authorization has three objects, not two:

| | | who controls it |
|---|---|---|
| **M** | what the operator *meant* | a human mind |
| **P** | the policy they wrote | operator, via host config |
| **T** | the transaction, and what it does | the agent, and whoever is talking to it |

The industry usually checks `T` against a declaration the agent supplies. That
is the weakest of the three comparisons, because the declaration and the
transaction come from the same place: an agent that has been compromised
supplies both, and they agree.

Safe Hands checks `T ⊨ P`. It does not check `P ⊨ M`. Saying only "we do
intent binding" hides which of those is which.

## The tractable half, stated

Let a policy `P` be the operator's document: an asset table with a per-transfer
cap, a recipient allowlist, an instruction allowlist, and outcomes for the
unknown cases.

Let the **observed effects** of a transaction be what `effects.rs` produces —
for each account, net movement per asset, derived from simulated
before/after balances rather than from the instruction list:

```
Movement { owner, asset, out_raw, in_raw }
```

This distinction is the whole point. An instruction list says what a
transaction *claims* to do. Net balance movement says what it *did*. Only the
second survives a program that does something other than its name suggests.

Define the **denotation of a policy**, `⟦P⟧`, as the set of effect-vectors in
which every outflow from a guarded owner is permitted:

```
E ∈ ⟦P⟧   ⟺   ∀ m ∈ E where m.owner is guarded ∧ m.out_raw > 0 :
                  m.asset ∈ P.assets
                ∧ m.out_raw ≤ P.assets[m.asset].max_per_tx_raw
                ∧ the counterparty ∈ P.allowed_recipients
```

The property Safe Hands actually establishes is then:

> **Soundness.** `evaluate(P, T) = ALLOW` ⟹ `effects(T) ∈ ⟦P⟧`
>
> Nothing that reaches ALLOW moves value outside what the policy permits.

Note what is *not* claimed: completeness. Plenty of transactions inside `⟦P⟧`
are still refused — an unresolved lookup table, a Token-2022 hook, a missing
simulation. Refusing something permissible is a usability cost. Allowing
something impermissible is the failure this project exists to prevent, so the
asymmetry is deliberate.

## Where the proof of it lives

Soundness is not asserted here. It is the conjunction of four of the twelve
Kani harnesses in `libs/safe-hands-core/src/policy/resolved/proofs.rs`, each
exhaustive over all 42 fields of `ResolvedFacts`:

| Harness | Clause it discharges |
|---|---|
| `an_over_cap_effect_can_never_be_allowed` | the `out_raw ≤ cap` conjunct |
| `an_unlisted_asset_can_never_leave` | the `asset ∈ P.assets` conjunct |
| `missing_effect_evidence_is_never_downgraded_to_review` | `E` must exist — absent evidence is not an empty `E` |
| `an_effect_intent_mismatch_can_never_be_allowed` | the observed `E` must match the declared one |

The third is the one that matters most and reads as the least interesting.
"No effects observed" and "no effects occurred" are different propositions, and
a system that conflates them authorizes anything it failed to look at.

The remaining eight harnesses discharge the instruction-level rules —
recipient, unknown program, durable nonce, authority change, the Token-2022
extensions — which constrain `T` directly rather than through `E`.

## The half that is still open

`P ⊨ M` — that the written policy captures what the operator meant.

This is not a gap that more code closes. `M` exists only in someone's head;
formalizing it requires a language for authorization that a non-programmer can
write correctly and a machine can check, and the failure mode is not a bug but
a misunderstanding. The current answer is the Squads approval: a second human
reads the proposal before it executes. That is a process control, and process
controls fail when people are busy.

Two things would make it better without solving it:

1. **Render `⟦P⟧` back to the operator in their own terms.** "This policy
   permits up to 25 USDC per transfer to one address" is checkable by a shop
   owner. A JSON document is not.
2. **Make the approval show effects, not instructions.** A human approving a
   Squads proposal should see "0.05 SOL leaves the vault, arrives at X", which
   is the same thing the engine checked, rather than an instruction list they
   must mentally execute.

Neither is verification. Both narrow the distance between what the human
believes and what the policy says, which is where the remaining risk lives.

## Why this is written down

A reader can now say precisely which of the three comparisons this project
makes, and hold it to that rather than to a vaguer claim. `T ⊨ P` is proven.
`P ⊨ M` is not attempted, and no amount of testing would make it so.
