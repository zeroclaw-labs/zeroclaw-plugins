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

**Not proven, only tested — and currently divergent.** `resolve()` is supposed
to produce the same verdict as `evaluate()`. It does not, on one path, and two
independent reviewers found it before we did.

`evaluate()` forgives an `unknown:` program when effects are required, present,
and the program is on the operator's admitted list (`policy.rs:435-441`).
`resolve()` implements no such carve-out (`policy/resolved.rs:307-310`) — it
sets `has_unknown_program` unconditionally, and `ResolvedFacts` has no field to
express admission. Run on the repository's own ALLOW fixture, the engine says
`Allow` and the model says `Deny`.

Two things follow, and both matter:

- **Every divergence found runs model-stricter-than-engine** (59 in a
  6552-combination sweep, none the other way). So there is no exploit here.
- **The proofs still do not transfer.** Reading "the model can never ALLOW X"
  as a statement about the engine requires *engine-ALLOW ⇒ model-ALLOW*, and
  that implication is false. On the admitted-program path — the one place the
  engine deliberately permits a program nobody decoded — the twelve proofs say
  nothing.

The agreement tests cannot see it: both build every input from a helper whose
instruction list is hard-coded, so **17 of 34 boolean fields are never
exercised**, and `has_unknown_program` is one of them. Raising
`SH_PROPTEST_CASES` does not help — the field is unreachable at any count.

The README previously said drift would be caught "immediately". It was not.
The fix is to implement admission in `resolve()` (or drop the carve-out from
`evaluate()`), and to make the agreement test vary the instruction list and
fail when a field stops being exercised.

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

## 2a. Two findings from adversarial review that are still open

An independent review found these. Neither is fixed, and neither should be
discovered by a reader rather than stated here.

**Effect analysis was blind to authority grants.** *Fixed.* `effects.rs` diffs
balances, so an SPL `Approve` CPI'd from an admitted program granted an
unlimited delegate while moving **zero lamports and zero tokens** — every
`Movement` zero, inside any cap, reachable ALLOW, and the account drained
afterwards outside this system. `FreezeAccount` and
`SetAuthority(CloseAccount)` were invisible the same way.

`parse_token_account` read mint, owner, amount and state and skipped precisely
the fields that mattered: delegate (72..108), `delegated_amount` (121..129) and
`close_authority` (129..165). `effects::authority_changes` now compares all
four across the transaction and reports the accounts where they moved, with a
positive control asserting an ordinary transfer is *not* reported.

The README claimed the worst case was the operator's per-transaction cap. It
was not — it was an unbounded standing delegate, and the amount at risk was the
whole account. **Still to do:** wire the reported change into a policy outcome
so it denies rather than merely being observable.

**The T1 builders never populate `facts.effects`.** So under any
`effects.required` policy, `spl-transfer-build` and `squads-proposal-build`
return `UNKNOWN` (`SH-UNKNOWN-EFFECT-072`) rather than a proposal. The
mitigation named above — route what the decoder cannot read to a human through
Squads — is therefore unavailable exactly when it is needed. That inverts the
intended safety story and is the more urgent of the two.

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
  and hostile policy documents including a duplicate key whose second value is
  permissive. One invariant throughout — degrade to refusal, never to
  permission.

  **The first version of this pinned nothing.** Every policy assertion sat
  behind `if let Ok(...)` and not one document parsed, so the bodies never ran;
  the zero-cap check inside was also reasoning backwards. Rewritten to assert
  rejection directly, with two positive controls so the file cannot pass by
  refusing everything.
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
   were *claimed* to reach past the signature shortvec and the message header.
   **They do not.** A legacy message needs ≥37 bytes to deserialize at all, so
   every input these harnesses explore returns `Err` — exhaustively confirmed
   for the whole ≤3-byte space. What is actually proven is that the early
   length guard does not panic. That is worth having and is not what was
   written. This
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
