# Evidence — the transparency log, anchored on devnet

Every number and transcript below is from a real run. The anchor is a real
Solana devnet transaction; the log it pins ships in this repository at
`conformance/log/arena.jsonl`, and anyone can check it against the chain
without an API key:

```sh
just log-verify                                    # offline
just log-audit                                     # public devnet RPC
```

---

## What is being claimed

A `decision_id` makes one decision checkable. It says nothing about the
decisions you were not shown.

An operator whose agent moved money can hand over four clean receipts and keep
the fifth. They can widen the policy, take the money, narrow it back, and hand
over receipts that are individually perfect — every one of them re-derives,
because each commits only to the policy that produced it.

The claim here is narrower and stronger than "we log things":

> Once a head is published on chain, no entry before it can be altered,
> reordered, or removed without contradicting a value the operator can no
> longer retract.

That is the property Certificate Transparency provides for TLS certificates.
Below it is demonstrated, then attacked four ways.

---

## The anchors

Three, on Solana devnet, all under the same authority
`BJqcN1wqvpakoMtu5xVepNHRTVbQohnDAfARtwe9HNcV`:

| Slot | Signature | Memo |
|---|---|---|
| 478989134 | [`dyiyH5fw…1xH1wGj`](https://explorer.solana.com/tx/dyiyH5fwBsYNuT6H9ZytdBV8YoCxDgMh8sa2WjBtMpKsFPnomUyr8dAH84GNMRGKf262Y2dCjBpVQTxx1xH1wGj?cluster=devnet) | `sh1 n=22 head=b9f032a7…add55` |
| 478991446 | [`2HczD1C7…1mu7FV`](https://explorer.solana.com/tx/2HczD1C7wzCtR1h3vzCrDUg8xoE4MySmjGZycUmg9UxJBkcGW3HybMKfiNHGmN69odQPEBohAy5Ft71rQP1mu7FV?cluster=devnet) | `sh1 n=22 head=b9f032a7…add55` |
| 478999926 | [`5c3C2v3L…hu3tr`](https://explorer.solana.com/tx/5c3C2v3LExKPQLc56j75PFgHXrx83uirunfJXSV76ERav9HYYuEVTkytwyEs2EzWuqwxuAYtZc25AqKacykhu3tr?cluster=devnet) | `sh1 n=27 head=40de23bd…10645` |

Each transaction is one SPL Memo instruction, ~76 bytes of payload. Safe Hands
built all three **unsigned** — it holds no key here any more than it does when
preparing a refund — and the operator signed them.

Anchoring repeatedly is the intended pattern, not duplication: each anchor
narrows the window of entries that are chained but not yet pinned, and every
past anchor keeps pinning the prefix it covered.

**The third anchor shows that directly.** It was published after the
effect-analysis fixtures were added, growing the log from 22 entries to 27. The
two earlier anchors did not go stale — they still pin entries 0–21 exactly as
before. A log grows; its history does not move.

### Signing without handing a library your key

`tools/sign-anchor.js` is the operator's half, and it has **no dependencies** —
Node's built-in crypto has done Ed25519 since v12, so a Solana CLI keypair can
be used directly. One fewer package with access to a private key.

```text
$ just log-anchor                          # Safe Hands prints unsigned bytes
$ node tools/sign-anchor.js key.json "<base64>"

memo       sh1 n=22 head=b9f032a72a192ebb505fc79b685d6cd5d00f86682ea4301ea858e6bf9c4add55
signer     BJqcN1wqvpakoMtu5xVepNHRTVbQohnDAfARtwe9HNcV
signature  2HczD1C7wzCtR1h3vzCrDUg8xoE4MySmjGZycUmg9UxJBkcGW3HybMKfiNHGmN69odQPEBohAy5Ft71rQP1mu7FV
```

It refuses to sign anything that is not an anchor. A script that signs whatever
base64 it is handed is a signing oracle, and putting one next to an agent would
undo the entire architecture:

```text
$ node tools/sign-anchor.js key.json "<a real USDC transfer>"

this transaction is not a Safe Hands anchor — it carries no `sh1` memo to the
SPL Memo program. This tool signs anchors and nothing else.
```

It also refuses an already-signed transaction, a fee payer that is not the
keypair it holds, and any message wanting more than one signature. The blockhash
is refreshed in place before signing — a human looking at an anchor takes longer
than a blockhash lives — by overwriting exactly 32 bytes at a computed offset,
leaving the memo being attested untouched.

---

## The log

`conformance/log/arena.jsonl` is the entire attack arena, logged in order:

| Verdict | Entries |
|---|---|
| DENY | 18 |
| ALLOW | 4 |
| REVIEW | 2 |
| UNKNOWN | 3 |

It is deliberately not a curated list of approvals. A transparency log made
only of successes proves nothing, and the refusals are the interesting part.

Fixture 20 is a `squads-proposal-build` case and produces a proposal rather than
an authorization decision, so 28 fixtures yield 27 logged decisions.

```text
PASS  every entry re-derives from its own inputs
      27 entries recomputed from bytes + policy + intent
PASS  the chain is unbroken from genesis
      genesis dd79c5eb… → head 40de23bd8ac186449b5addd92702be927f4f1483505b087284b8989acac10645
```

The file is append-only and grew as the suite did, which is why `just
log-rebuild` builds a *fresh* log rather than claiming to reproduce this one.
Rebuilding demonstrates the pipeline; this file is the artifact, and the anchors
above are what make it one.

---

## Audited against the chain

```text
$ just log-audit

Safe Hands — anchor audit
log:       conformance/log/arena.jsonl
authority: BJqcN1wqvpakoMtu5xVepNHRTVbQohnDAfARtwe9HNcV

  OK    slot 478989134 — 22 entries (unix 1785054065)
        dyiyH5fwBsYNuT6H9ZytdBV8YoCxDgMh8sa2WjBtMpKsFPnomUyr8dAH84GNMRGKf262Y2dCjBpVQTxx1xH1wGj
  OK    slot 478991446 — 22 entries (unix 1785054912)
        2HczD1C7wzCtR1h3vzCrDUg8xoE4MySmjGZycUmg9UxJBkcGW3HybMKfiNHGmN69odQPEBohAy5Ft71rQP1mu7FV
  OK    slot 478999926 — 27 entries (unix 1785058017)
        5c3C2v3LExKPQLc56j75PFgHXrx83uirunfJXSV76ERav9HYYuEVTkytwyEs2EzWuqwxuAYtZc25AqKacykhu3tr

  All 3 anchors agree. 27 of 27 entries are pinned on chain; the earliest at slot 478989134.
  Those entries can no longer be altered, reordered, or removed without
  contradicting a value published at slot 478999926 by a key we do not hold.
```

Run against `https://api.devnet.solana.com` — the public endpoint, no API key.

---

## Four attacks on the anchored log

Each one starts from the exact file above and applies an edit an operator might
actually want to make. All four fail, and each fails with the specific
accusation it deserves.

### 1. Truncate the tail

Drop the last two decisions. The remaining file is internally flawless — the
chain still verifies against itself.

```text
PASS  every entry re-derives from its own inputs
PASS  the chain is unbroken from genesis
FAIL  every on-chain anchor agrees with this log
      slot 478999926: TRUNCATED: an anchor covers 27 entries, the log holds 25.
      2 published entries are gone.
```

This is the attack the chain alone cannot see, and the reason anchoring exists.

### 2. Delete a decision from the middle and rebuild every head

Remove entry 11, renumber, recompute all 26 heads so nothing is inconsistent.

The *oldest* anchor catches it: an edit made today contradicts a value published
before the effect-analysis work existed. That is the argument for anchoring
early and often.

```text
PASS  every entry re-derives from its own inputs
PASS  the chain is unbroken from genesis
FAIL  every on-chain anchor agrees with this log
      slot 478989134: FORKED at 22 entries:
        chain published  b9f032a7…add55
        this log computes c91ae955…8c207
      slot 478999926: TRUNCATED: an anchor covers 27 entries, the log holds 26.
```

### 3. Rewrite a refusal into an approval

Entry 3 is `level-04 recipient swapped to attacker → DENY`. Change the verdict
to ALLOW and clear the reason codes.

```text
FAIL  every entry re-derives from its own inputs
      entry 3 does not re-derive — the log records a decision this engine does
      not produce for those inputs: re-derived verdict matches the receipt:
      claimed ALLOW, re-derived DENY; re-derived reason codes match the receipt:
      ["SH-DENY-RECIPIENT-003", "SH-INTENT-RECIPIENT-031"]
```

Caught without the chain and without the network, because the log stores the
receipt's *inputs* and re-runs the engine over them rather than trusting the
verdict written next to them.

### 4. Substitute one decision and rebuild the whole chain

The hardest version: keep all 27 entries, swap entry 11 for a different genuine
decision, recompute every head. The file is perfect by every internal measure —
every receipt re-derives, the chain is unbroken, and the newest anchor's entry
count matches exactly.

All three anchors refuse it.

```text
PASS  every entry re-derives from its own inputs
      27 entries recomputed from bytes + policy + intent
PASS  the chain is unbroken from genesis
PASS  the published head covers every entry
FAIL  every on-chain anchor agrees with this log
      slot 478989134: FORKED at 22 entries:
        chain published  b9f032a72a192ebb505fc79b685d6cd5d00f86682ea4301ea858e6bf9c4add55
        this log computes 87e235bf5f21c3a782241e72c6ee2adf06bc22b341e2fa1bdd84e87a8915ca3d
      slot 478999926: FORKED at 27 entries:
        chain published  40de23bd8ac186449b5addd92702be927f4f1483505b087284b8989acac10645
        this log computes f2512ab23544f16c3cc372d377de5d8a5f397e99e6f6d44cb37afa556d57c9cd
      Two histories exist under one authority.
```

---

## Two gaps this work exposed, and closed

Building the log found two places where the product was quietly less auditable
than it claimed. Both are fixed; both are worth stating plainly, because the
first one was the more serious.

### Fail-closed refusals carried no `decision_id`

Four refusals happen before the engine is reached: no policy configured, the
policy does not parse, the payload is not base64, the transaction does not
decode. All four returned a verdict with no `decision_id` at all — so they
could not be re-derived, and could not be entered in the log.

Those are exactly the decisions an operator would most like to make quietly.
*"The policy was broken that day"* is unfalsifiable if the resulting refusals
leave no checkable trace.

Every terminal verdict now commits to something. Payloads that never became
transactions, and policies that never parsed, get domain-separated stand-in
digests (`libs/safe-hands-core/src/commitment.rs`) that cannot collide with the
real thing. Four distinct failures produce four distinct ids, asserted in
`fail_closed_refusals_carry_a_decision_id`.

### A boolean could not describe the evidence

A receipt recorded `simulation_ok: true | false`. But "the node said this
transaction fails", "the node did not answer", "the answer was too old to
trust", and "a mint could not be evidenced" are four different outcomes with
four different reason codes. Collapsed into one bit, three whole classes of
UNKNOWN could not be re-derived.

The authorizer now names the evidence it decided under, and the verifier
re-derives each shape. UNKNOWN is the verdict most easily explained away, so it
is the one that most needed to stay checkable.

---

## Mutation testing

Tests that pass against broken code are worse than no tests. Every new module
here was run through `cargo mutants`, which deletes and inverts operators one at
a time and asks whether the suite notices.

| Module | Mutants | Caught | Unviable | Surviving |
|---|---|---|---|---|
| `safe-hands-core/src/log.rs` + `commitment.rs` | 51 | 40 | 11 | **0** |
| `conformance/src/log.rs` | 112 | 104 | 5 | **3** |

The first pass found two things worth having found.

`AnchorVerdict::is_consistent` could be replaced with `true` and every test still
passed — which would have made the auditor approve every tampered log it was
ever shown. The positive cases asserted `is_consistent()`; nothing asserted the
negative.

The whole of `Report::finish` could be replaced with `Ok(())`. That is the exit
code of `--log-verify`. A verifier that prints FAIL and exits 0 is worse than no
verifier, because it looks like it checked. The pass/fail accounting is now a
separate `outcome()` with its own test, and the command functions take their
transport as an argument so they can be driven from canned RPC answers instead
of only from a shell.

The three survivors are named rather than left unmentioned: `verify_log` and
`audit`, the two-line wrappers that construct an HTTP transport and delegate to
the tested functions, and `HttpTransport::call`, which cannot run without a
server. None contains a decision. An undisclosed gap in a tool whose job is
disclosure would be a poor joke.

---

## What this does not claim

- **It does not stop an operator from lying.** It makes one specific lie —
  *"that decision never happened"*, *"the log always said this"* — impossible to
  tell consistently once a later head is anchored.
- **Entries after the newest anchor are not yet pinned.** `--log-verify` says so
  explicitly rather than implying full coverage. Anchor more often to narrow the
  window; the anchor costs one memo transaction.
- **Simulation remains attested, not reproduced.** It is external RPC evidence
  and cannot be recreated offline. The receipt records which evidence was
  obtained, and a receipt that misstates it fails to re-derive.
- **A single anchor cannot prove an entry was logged promptly**, only that it
  existed by the anchored slot. Frequent anchoring is what tightens that.
- **One authority keeps one log.** The genesis binds to the anchoring key on
  purpose, so an operator cannot quietly start over under the same key without
  every past anchor calling it a fork. That is the property working rather than
  a limitation to route around — but it does mean starting a log is a
  commitment.
