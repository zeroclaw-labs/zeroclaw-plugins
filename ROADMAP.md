# What is not finished

Safe Hands v0.1 makes one claim and defends it: **an agent that cannot sign
cannot steal.** That claim holds. Everything below is what the project does
*not* yet establish, written down at the level of precision we would want from
someone else's security tool.

Nothing here is a to-do list padded for effect. Each item is either a boundary
we can point at in the source, or a problem we believe is genuinely open.

---

## 1. Exactly where the proof stops

A decision travels this path:

```
raw transaction bytes
   │  decode.rs                     ← fuzzed
   ▼
TxFacts
   │  policy::evaluate()            ← 67 tests, 512-case proptest agreement
   ▼                                   with the model
ResolvedFacts  (42 fields, Copy, heap-free)
   │  resolved::verdict()           ← 12 Kani proofs, EXHAUSTIVE
   ▼
Verdict
```

**Proven:** `verdict()`. All 12 harnesses in
`libs/safe-hands-core/src/policy/resolved/proofs.rs` run `kani::any()` over
every one of the 42 fields simultaneously, so they cover the entire decision
space rather than a sample of it. "ALLOW requires every hard check to pass" is
a theorem here, not a test result.

**Not proven, only tested:** that `resolve()` produces the right
`ResolvedFacts` from a given `TxFacts`. This is checked against the real engine
on 9 shaped cases and 512 generated ones
(`policy/tests.rs::the_model_agrees_with_the_engine_on_every_shaped_case` and
the proptest below it). If the model ever drifts from the engine, **every proof
above becomes worthless** — which is why the agreement is re-checked on every
run, and why we are saying so here rather than quietly relying on it.

**Not proven, only fuzzed:** that `decode()` turns adversarial bytes into
honest `TxFacts`. An attacker who could make the decoder mis-describe a
transaction would defeat all twelve proofs without ever touching them. This is
the single most valuable place to spend verification effort next, and it is
currently the weakest link in the chain.

*Partly addressed.* `tests/decode_hostile.rs` adds structure-aware adversarial
input that runs wherever `cargo test` does — every truncation of a real
message, single-byte corruption, a shortvec claiming 65,535 elements in front
of a valid body, every versioned-prefix byte, and arbitrary runs spliced in
behind a well-formed head. Two invariants: never panic (a panic is a trap in
the component, and a caller reading a trap as anything but *refuse* has failed
open) and decode-twice-agrees (`decision_id` binds a verdict to exactly these
bytes). Green at 200k cases, no findings. This narrows the gap; it does not
close it. Proving the decoder, or shrinking it until it can be proven, remains
the top item in §8.

Kani does not run on Windows, so contributors on that platform cannot
reproduce the proofs locally — `just prove` is Linux/macOS only. *Addressed
where it matters:* the proofs now run in CI on every push
(`prove-safety.yml`, job `machine-checked proofs (kani)`), so "proven" is a
result anyone can check in the Actions tab rather than a claim resting on
someone having run it locally, once.

---

## 2. The problem we did not solve

**We verify that a transaction matches the declared intent. We do not verify
that the declared intent matches what the human actually wanted.**

`solana-tx-authorize` re-derives the transaction's effects and checks them
against an intent record. If they disagree, it denies. That closes the gap
between "what the agent said it was doing" and "what the bytes do".

It does not close the gap between "what the agent said it was doing" and "what
the operator meant." An agent that is talked into declaring a *coherent but
wrong* intent produces a transaction that matches it, and both layers agree.
The human then sees an internally consistent lie.

Today that gap is covered by the Squads approval — a second human reads the
proposal. That is a process control, not a technical one, and process controls
fail when people are busy.

We think closing it properly needs a formal semantics for authorization intent
and a proof that the signed bytes lie inside its denotation. We do not have
that, nobody in this space appears to have it, and we would rather name it than
imply our layering has solved it.

*Half of it is done, and was already done before this was written down.*
[`INTENT.md`](INTENT.md) separates the three objects — what the operator meant
(`M`), the policy they wrote (`P`), and the transaction (`T`) — defines the
denotation `⟦P⟧` as a set of permitted **effect** vectors taken from simulated
before/after balances rather than the instruction list, and shows that

    evaluate(P, T) = ALLOW  ⟹  effects(T) ∈ ⟦P⟧

is the conjunction of four existing Kani harnesses rather than a new claim.
So `T ⊨ P` is proven and now says what it means. **`P ⊨ M` remains open**, and
is the part no amount of testing reaches: `M` exists only in a human's head.
The current answer to it is a second human reading the Squads proposal, which
is a process control and fails when people are busy.

---

## 3. Surfaces we refuse instead of handle

These fail closed today. Failing closed is correct, but it is not the same as
support, and an operator should know which is which.

| Surface | Today | Why it is hard |
|---|---|---|
| **Token-2022 transfer hooks** | denied | A hook is an arbitrary program that runs on every transfer. Authorizing one means reasoning about code we did not decode. |
| **Transfer fees / permanent delegate / default-frozen** | denied | Each changes what "transfer 25 USDC" means. The intent model has no vocabulary for "and the mint may also take a cut, or claw it back." |
| **Confidential transfers** | denied | Amounts are hidden by construction. A cap cannot be enforced on a number the guard cannot see. |
| **Unresolved address lookup tables** | denied | Resolving an ALT means trusting a second account's contents at authorization time — a new trust edge, mid-decision. |
| **Durable nonce pools** | one nonce, one in-flight approval | Parallel pending approvals need a nonce per approval, plus a lifecycle that cannot double-spend a slot. |

---

## 4. Verification debt, named

- **Fuzzing is minutes, not weeks.** The CI budget is a gate, not a campaign.
  The decode corpus should outlive individual releases and run continuously.
  Windows contributors cannot run it at all — `cargo-fuzz` needs libFuzzer.

  *Partly addressed.* The property-test budget is now `SH_PROPTEST_CASES`
  rather than a hard-coded 512, and running the suite at 200,000 immediately
  found that `split_aggregate_over_cap_never_allows` **could not run at scale
  at all**: it discarded every draw whose amounts missed the cap, exhausted
  proptest's global-reject budget and aborted. The property had never failed —
  it had never been exercised more than a few hundred times, despite being the
  backbone of the split-bypass claim. Fixed by constructing the over-cap
  aggregate instead of rejecting under-cap draws; the whole suite is now green
  at 200k. That is the argument for soaking, made by the soak.
- **Differential testing samples instruction shapes; it should cover them.**
  Every encoding we emit should be diffed against the reference implementation,
  not a representative subset.
- **No independent review.** Nobody outside this project has read the code. We
  say this in the README's mainnet gate and repeat it here because it is the
  single largest unquantified risk in the system.
- **Verified builds do not exist.** We ship a signed `.wasm` and ask you to
  trust that it came from this source. Reproducing the artifact from the
  repository, byte for byte, would remove that trust edge entirely — and it is
  the natural completion of the capability check, which already reads the
  compiled import table rather than the source.

---

## 5. Adversarial work we have not done

Our 28 fixtures are **regression tests**. They encode attacks we already
understood. They cannot discover a class we have not imagined, and presenting
them as a red team would be dishonest.

What is missing:

- **Humans paid to break it**, with the transcripts published either way.
  Still outstanding, and the most valuable thing we do not have.
- **Chaos at each trust boundary, not just the prompt.** *Addressed.*
  `tests/chaos_boundaries.rs` now covers the RPC and the policy document: a
  simulation slot ahead of the chain, a stale one, eight shapes of malformed
  evidence, an unreachable endpoint, a mint the endpoint will not describe,
  and fifteen hostile policy documents including a duplicate key whose second
  value is permissive. One invariant throughout — degrade to refusal, never to
  permission. All passed unchanged; the behaviour was already right, and is
  now pinned.
- **A compromised model, not merely a fooled one.** *Addressed.*
  `tests/compromised_model.rs`. Every other injection test assumes a model that
  has been tricked; this one assumes it is cooperating with the attacker and
  therefore produces no contradiction to notice — a transfer, an intent that
  describes it exactly, a passing simulation, all consistent. What it cannot
  supply is the operator policy, which arrives from host config. Seven cases
  plus a control that must be ALLOW, so the suite cannot pass by refusing
  everything. If any of them fails, intent matching has been promoted from a
  second check into a substitute for the first.
- **Attacking the human.** The approval step is the weakest link in the whole
  design and the least tested. Nobody has tried to construct a proposal that
  a tired operator approves at 11pm. We would expect that to succeed.

---

## 6. What would actually validate this

One real merchant, real money, for a year.

Everything else is a proxy. Our honest expectation is that the interesting
failures would be operational rather than cryptographic: a lost phone, a staff
change, a disputed charge, an operator who edits the allowlist to make a
problem go away. A guard that is correct and unusable gets removed, and then
protects nobody.

---

## 7. What we would remove

The four-component split is an artifact of the plugin model — one tool per
component — not a design we would choose freely. Four components means four
trust boundaries, four manifests and four places for policy to drift.

Given time we would collapse to a single authorization kernel with the proof
attached to it, and make everything else a thin caller. Fewer boundaries beat
more layers; the current shape is defensible, not ideal.

---

## 8. The order we would do it in

1. Prove `decode()`, or shrink it until it can be proven. It is the weakest
   link and everything above it inherits its correctness.

   *Started.* `src/decode_proofs.rs` proves the property that matters most —
   **no input up to N bytes makes the decoder panic** — plus decoding-is-a-
   function, as theorems rather than fuzzing results. In a `wasm32-wasip2`
   component a panic is a trap, and a host reading a trap as anything but
   *refuse* has failed open. The bounds are small (8, 6 and 3 bytes) because
   Kani explores the entire input space, so each byte costs exponentially; they
   reach past the signature shortvec, the version byte and the message header,
   where a truncated buffer and a lying length prefix are both in play. This
   runs as a **non-blocking** CI job: symbolic execution through a parser can
   fail to terminate in a way the heap-free policy model cannot, and a
   speculative proof must not be able to turn the gate red.

   **Measured, and worse than hoped:** at `N = 8` it did not terminate inside
   90 minutes on CI. The bound is now 4 bytes. That number is the useful
   output of the attempt — the obstacle is the *shape of the code*, not the
   amount of solver time available. A decoder assembled from bounded,
   heap-free steps would be provable at a width worth having; this one reads
   length prefixes out of the same buffer that bounds it, and symbolic
   execution has to carry every resulting path. So the first move is to
   restructure `decode` until it can be proven, not to keep raising `N`.
2. Verified builds, so the artifact needs no trust separate from the source.
3. Continuous fuzzing with a persistent corpus.
4. Independent review.
5. Token-2022 hooks — the largest genuinely-used surface we refuse.
6. Intent semantics. The real problem, and the one we would still be working on
   in year two.

---

*If you are evaluating this project: sections 1, 2 and 5 are the ones we would
read first if it were someone else's.*
