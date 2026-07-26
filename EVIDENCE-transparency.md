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

Two, on Solana devnet, both under the same authority
`BJqcN1wqvpakoMtu5xVepNHRTVbQohnDAfARtwe9HNcV`:

| Slot | Signature | Memo |
|---|---|---|
| 478989134 | [`dyiyH5fw…1xH1wGj`](https://explorer.solana.com/tx/dyiyH5fwBsYNuT6H9ZytdBV8YoCxDgMh8sa2WjBtMpKsFPnomUyr8dAH84GNMRGKf262Y2dCjBpVQTxx1xH1wGj?cluster=devnet) | `sh1 n=22 head=b9f032a7…add55` |
| 478991446 | [`2HczD1C7…1mu7FV`](https://explorer.solana.com/tx/2HczD1C7wzCtR1h3vzCrDUg8xoE4MySmjGZycUmg9UxJBkcGW3HybMKfiNHGmN69odQPEBohAy5Ft71rQP1mu7FV?cluster=devnet) | `sh1 n=22 head=b9f032a7…add55` |

Each transaction is one SPL Memo instruction, ~76 bytes of payload. Safe Hands
built both **unsigned** — it holds no key here any more than it does when
preparing a refund — and the operator signed them.

Anchoring repeatedly is the intended pattern, not a duplicate: each anchor
narrows the window of entries that are chained but not yet pinned.

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
| DENY | 15 |
| ALLOW | 3 |
| REVIEW | 2 |
| UNKNOWN | 2 |

It is deliberately not a curated list of approvals. A transparency log made
only of successes proves nothing, and the refusals are the interesting part.

It is also reproducible from source — `just log-rebuild` reruns all 23 fixtures
through the real plugins, emits a receipt for each, appends them, and arrives
at the identical head:

```text
PASS  every entry re-derives from its own inputs
      22 entries recomputed from bytes + policy + intent
PASS  the chain is unbroken from genesis
      genesis dd79c5eb… → head b9f032a72a192ebb505fc79b685d6cd5d00f86682ea4301ea858e6bf9c4add55
```

Fixture 20 is a `squads-proposal-build` case and produces a proposal rather than
an authorization decision, so 23 fixtures yield 22 logged decisions.

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

  All 2 anchors agree. 22 of 22 entries are pinned on chain; the earliest at slot 478989134.
  Those entries can no longer be altered, reordered, or removed without
  contradicting a value published at slot 478991446 by a key we do not hold.
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
PASS  the chain is unbroken from genesis
FAIL  every on-chain anchor agrees with this log
      slot 478989134: TRUNCATED: an anchor covers 22 entries, the log holds 20.
      2 published entries are gone.
```

This is the attack the chain alone cannot see, and the reason anchoring exists.

### 2. Delete a decision from the middle and rebuild every head

Remove entry 11, renumber, recompute all 21 heads so nothing is inconsistent.

```text
PASS  every entry re-derives from its own inputs
PASS  the chain is unbroken from genesis
FAIL  every on-chain anchor agrees with this log
      slot 478989134: TRUNCATED: an anchor covers 22 entries, the log holds 21.
      1 published entry is gone.
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

The hardest version: keep 22 entries, swap entry 11 for a different genuine
decision, recompute every head. The file is perfect by every internal measure.

```text
PASS  every entry re-derives from its own inputs
      22 entries recomputed from bytes + policy + intent
PASS  the chain is unbroken from genesis
PASS  the published head covers every entry
FAIL  every on-chain anchor agrees with this log
      slot 478989134: FORKED at 22 entries:
        chain published  b9f032a72a192ebb505fc79b685d6cd5d00f86682ea4301ea858e6bf9c4add55
        this log computes 87e235bf5f21c3a782241e72c6ee2adf06bc22b341e2fa1bdd84e87a8915ca3d
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
